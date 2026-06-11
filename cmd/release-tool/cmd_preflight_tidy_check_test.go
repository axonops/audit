// Copyright 2026 AxonOps Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/sumdb"
)

// makeTempRepo initialises a bare-bones git repo under t.TempDir
// and seeds it with a `go.sum` file at HEAD. Tests then mutate
// `go.sum` in the workdir without committing — the runtime captures
// that diff exactly like the release-flow workflow will.
func makeTempRepo(t *testing.T, initialGoSum map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	gitInit := exec.Command("git", "-C", dir, "init", "--quiet", "--initial-branch=main")
	gitInit.Env = append(gitInit.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := gitInit.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, cmd := range [][]string{
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
	} {
		args := append([]string{"-C", dir}, cmd...)
		if err := exec.Command("git", args...).Run(); err != nil {
			t.Fatalf("git %v: %v", cmd, err)
		}
	}
	for path, content := range initialGoSum {
		full := filepath.Join(dir, path)
		if err := exec.Command("mkdir", "-p", filepath.Dir(full)).Run(); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := writeFile(full, content); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		if err := exec.Command("git", "-C", dir, "add", path).Run(); err != nil {
			t.Fatalf("git add %s: %v", path, err)
		}
	}
	commit := exec.Command("git", "-C", dir, "commit", "--quiet", "-m", "init")
	commit.Env = append(commit.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	return dir
}

func writeFile(path, content string) error {
	// #967 review N2: stdlib os.WriteFile is the right tool;
	// the earlier shell-out roundtrip added a /bin/sh dependency
	// for zero benefit.
	return os.WriteFile(path, []byte(content), 0o600)
}

// fakeSumdb returns an httptest server whose /lookup response is
// built from the supplied (module, version) → (zipHash, modHash) map.
func fakeSumdb(t *testing.T, ans map[string][2]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path: /lookup/<module>@<version>
		const prefix = "/lookup/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		modVer := strings.TrimPrefix(r.URL.Path, prefix)
		key := modVer
		hashes, ok := ans[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Two-line body: zip hash and go.mod hash.
		at := strings.LastIndex(modVer, "@")
		module := modVer[:at]
		version := modVer[at+1:]
		body := fmt.Sprintf("1\n%s %s %s\n%s %s/go.mod %s\n\n",
			module, version, hashes[0], module, version, hashes[1])
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runSubcmd(t *testing.T, workdir, version, mods, sumdbURL string, skipSumdb bool) (code int, stdout, stderr string) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	args := []string{
		"--workdir", workdir,
		"--last-released-version", version,
		"--published-modules", mods,
		"--sumdb-endpoint", sumdbURL,
	}
	if skipSumdb {
		args = append(args, "--skip-sumdb-cross-check")
	}
	code = runPreflightTidyCheck(context.Background(), args, outBuf, errBuf, &rootFlags{})
	stdout = outBuf.String()
	stderr = errBuf.String()
	return code, stdout, stderr
}

func TestPreflightTidyCheck_NoDriftExitsIdempotent(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	if code != exitIdempotentNoOp {
		t.Errorf("exit code: got %d want %d", code, exitIdempotentNoOp)
	}
	if !strings.Contains(stdout, msgNoDrift) {
		t.Errorf("stdout missing %q: %q", msgNoDrift, stdout)
	}
}

func TestPreflightTidyCheck_Gate1_GoModModifiedAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.mod": "module example\n", "go.sum": ""})
	// Mutate go.mod (gate 1 trigger).
	if err := writeFile(filepath.Join(repo, "go.mod"), "module example\n\nrequire foo v0.0.1\n"); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgGoModModified) {
		t.Errorf("stdout missing %q: %q", msgGoModModified, stdout)
	}
}

func TestPreflightTidyCheck_Gate2_DeletionsAbort(t *testing.T) {
	t.Parallel()
	initial := "github.com/axonops/audit v0.2.1 h1:OLD=\n"
	repo := makeTempRepo(t, map[string]string{"go.sum": initial})
	// Replace the file — deletion of the old line + addition of a new one.
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:NEW=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgGoSumDeletions) {
		t.Errorf("stdout missing %q: %q", msgGoSumDeletions, stdout)
	}
}

func TestPreflightTidyCheck_Gate3_UnrelatedModuleAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	// Add a line for an unrelated module — gate 3 rejects.
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/evil/audit v0.2.2 h1:AAA=\ngithub.com/evil/audit v0.2.2/go.mod h1:BBB=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgUnrelatedChecksums) {
		t.Errorf("stdout missing %q: %q", msgUnrelatedChecksums, stdout)
	}
}

func TestPreflightTidyCheck_Gate3_WrongVersionAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.3.0 h1:AAA=\ngithub.com/axonops/audit v0.3.0/go.mod h1:BBB=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgUnrelatedChecksums) {
		t.Errorf("stdout missing %q: %q", msgUnrelatedChecksums, stdout)
	}
}

func TestPreflightTidyCheck_Gate4_SumdbDisagreesAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:TIDYHASH=\ngithub.com/axonops/audit v0.2.2/go.mod h1:TIDYMOD=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := fakeSumdb(t, map[string][2]string{
		"github.com/axonops/audit@v0.2.2": {"h1:SUMDBHASH=", "h1:SUMDBMOD="},
	})
	// #967 review M1: a sumdb disagreement is a VALIDATION failure
	// (exit 3) — the diff fails a safety gate. Transient transport
	// failures are operational (exit 1, see the SumdbNotFound /
	// ServerError tests below).
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, false)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	// #967 review M2: gate-4 emits on BOTH stdout (workflow summary
	// pipe) AND stderr (human log).
	if !strings.Contains(stdout, msgSumdbDisagrees) {
		t.Errorf("stdout missing %q: %q", msgSumdbDisagrees, stdout)
	}
}

func TestPreflightTidyCheck_Gate4_SumdbNotFoundIsTransient(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:AAA=\ngithub.com/axonops/audit v0.2.2/go.mod h1:BBB=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	code, _, stderr := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, false)
	if code != exitOperational {
		t.Errorf("exit code: got %d want %d", code, exitOperational)
	}
	if !strings.Contains(stderr, msgSumdbTransient) {
		t.Errorf("stderr missing %q: %q", msgSumdbTransient, stderr)
	}
}

func TestPreflightTidyCheck_Gate4_SumdbServerErrorIsTransient(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:AAA=\ngithub.com/axonops/audit v0.2.2/go.mod h1:BBB=\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	code, _, stderr := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, false)
	if code != exitOperational {
		t.Errorf("exit code: got %d want %d", code, exitOperational)
	}
	if !strings.Contains(stderr, msgSumdbTransient) {
		t.Errorf("stderr missing %q: %q", msgSumdbTransient, stderr)
	}
}

func TestPreflightTidyCheck_HappyPath(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": "", "file/go.sum": ""})
	// Tidy adds entries at both the root and the file submodule.
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:HASH1=\ngithub.com/axonops/audit v0.2.2/go.mod h1:HASH2=\n"); err != nil {
		t.Fatalf("write root go.sum: %v", err)
	}
	if err := writeFile(filepath.Join(repo, "file", "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:HASH1=\ngithub.com/axonops/audit v0.2.2/go.mod h1:HASH2=\n"); err != nil {
		t.Fatalf("write file/go.sum: %v", err)
	}
	srv := fakeSumdb(t, map[string][2]string{
		"github.com/axonops/audit@v0.2.2": {"h1:HASH1=", "h1:HASH2="},
	})
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, false)
	if code != exitSuccess {
		t.Errorf("exit code: got %d want %d", code, exitSuccess)
	}
	// Summary should mention the validated (module, version) pair.
	if !strings.Contains(stdout, "github.com/axonops/audit v0.2.2") {
		t.Errorf("stdout missing validated pair: %q", stdout)
	}
}

// #967 review M3: cross-file hash divergence. If the root go.sum
// and a submodule go.sum both add a line for the same
// (module, version) but with DIFFERENT h1: values, gate 4 must
// reject — only the last-written hash would be checked against the
// sumdb otherwise, silently passing the other tampered hash.
func TestPreflightTidyCheck_Gate4_CrossFileHashDivergenceAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": "", "file/go.sum": ""})
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:HONEST=\ngithub.com/axonops/audit v0.2.2/go.mod h1:MOD=\n"); err != nil {
		t.Fatalf("write root go.sum: %v", err)
	}
	if err := writeFile(filepath.Join(repo, "file", "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:TAMPERED=\ngithub.com/axonops/audit v0.2.2/go.mod h1:MOD=\n"); err != nil {
		t.Fatalf("write file/go.sum: %v", err)
	}
	srv := fakeSumdb(t, map[string][2]string{
		"github.com/axonops/audit@v0.2.2": {"h1:HONEST=", "h1:MOD="},
	})
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, false)
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgSumdbDisagrees) {
		t.Errorf("stdout missing %q: %q", msgSumdbDisagrees, stdout)
	}
}

// test-analyst silent-bypass class: if `parseGoSumLine` silently
// drops a malformed added line (e.g. 4 fields instead of 3), and
// that's the ONLY added line, every gate trivially passes and the
// release proceeds against a diff containing the malformed line.
// The fix is to require at least one valid added line whenever the
// diff is non-empty AND go.sum-only AND addition-only.
func TestPreflightTidyCheck_MalformedAddedLineDoesNotSilentlyPass(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	// 4-field line — `parseGoSumLine` rejects, but the line is real.
	if err := writeFile(filepath.Join(repo, "go.sum"),
		"github.com/axonops/audit v0.2.2 h1:AAA= EXTRA\n"); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}
	srv := fakeSumdb(t, nil)
	code, stdout, _ := runSubcmd(t, repo, "v0.2.2", "github.com/axonops/audit", srv.URL, true)
	// Gates 1+2 pass (go.sum-only, no deletions), gate 3 receives
	// empty `added` because the malformed line was dropped → without
	// a guard, gate 3 returns true on an empty set and the run
	// reaches gate 4 (skipped) and exits 0. With the guard, gate 3
	// rejects because there's no valid line covering the actual diff.
	if code == exitSuccess {
		t.Errorf("malformed-only diff silently passed; got exitSuccess, want exitValidation")
	}
	if !strings.Contains(stdout, msgUnrelatedChecksums) {
		t.Errorf("stdout missing %q (expected gate-3 reject of empty added set): %q",
			msgUnrelatedChecksums, stdout)
	}
}

func TestPreflightTidyCheck_DiffSizeCapAborts(t *testing.T) {
	t.Parallel()
	repo := makeTempRepo(t, map[string]string{"go.sum": ""})
	// Force a tiny cap and write a go.sum just above it. This
	// tests the cap mechanism without depending on the
	// (production) default value.
	big := strings.Repeat("a", 200)
	if err := writeFile(filepath.Join(repo, "go.sum"), big); err != nil {
		t.Fatalf("write big go.sum: %v", err)
	}
	srv := fakeSumdb(t, nil)
	outBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	code := runPreflightTidyCheck(context.Background(), []string{
		"--workdir", repo,
		"--last-released-version", "v0.2.2",
		"--published-modules", "github.com/axonops/audit",
		"--sumdb-endpoint", srv.URL,
		"--skip-sumdb-cross-check",
		"--max-diff-bytes", "100", // tiny cap — must trip
	}, outBuf, errBuf, &rootFlags{})
	stdout := outBuf.String()
	if code != exitValidation {
		t.Errorf("exit code: got %d want %d", code, exitValidation)
	}
	if !strings.Contains(stdout, msgDiffSizeCapExceeded) {
		t.Errorf("stdout missing %q: %q", msgDiffSizeCapExceeded, stdout)
	}
}

func TestPreflightTidyCheck_RequiresFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
	}{
		{name: "no last-released-version", args: []string{"--published-modules", "x"}},
		{name: "no published-modules", args: []string{"--last-released-version", "v0.2.2"}},
		{name: "empty published-modules csv", args: []string{
			"--last-released-version", "v0.2.2", "--published-modules", " , , ,",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			code := runPreflightTidyCheck(context.Background(), tc.args, stdout, stderr, &rootFlags{})
			if code != exitUsage {
				t.Errorf("expected exitUsage, got %d", code)
			}
		})
	}
}

// Ensure the sumdb client is correctly wired through the default
// constructor path — exercised once so the constructor parameter
// surface is covered by the test suite.
func TestSumdbClientDefaultTimeout(t *testing.T) {
	t.Parallel()
	c := &sumdb.Client{Endpoint: "http://example.invalid"}
	_, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v0.2.2")
	if err == nil {
		t.Fatal("expected error against invalid host")
	}
}
