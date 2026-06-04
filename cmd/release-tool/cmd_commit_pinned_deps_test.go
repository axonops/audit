// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/gitstatus"
)

const (
	branchHeadSHA = "feedface0000000000000000000000000000feed"
	newCommitSHA  = "cafebabe0000000000000000000000000000cafe"
)

// TestRun_CommitPinnedDeps_NoStagedChanges_ExitsIdempotent covers the
// re-run scenario: when the upstream invocation already committed the
// pinned go.mods, a re-run finds nothing to stage and must exit 4
// (no-op), not 0 (false-success) and not 1 (false-failure).
func TestRun_CommitPinnedDeps_NoStagedChanges_ExitsIdempotent(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	srv := newCommitServer(t, commitFixture{})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitIdempotentNoOp {
		t.Errorf("want exit %d (no-op), got %d (stderr=%q)", exitIdempotentNoOp, code, stderr.String())
	}
}

// TestRun_CommitPinnedDeps_OffAllowlist_Rejected is the regression
// for #906: a staged path outside the go.mod / go.sum allowlist must
// be refused with an exit 3 (validation), not silently committed.
func TestRun_CommitPinnedDeps_OffAllowlist_Rejected(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, ".github/workflows/release.yml", []byte("# off-allowlist"))

	srv := newCommitServer(t, commitFixture{})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitValidation {
		t.Errorf("want exit %d (validation), got %d (stderr=%q)", exitValidation, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "rejected by allowlist") {
		t.Errorf("stderr must explain the allowlist rejection: %q", stderr.String())
	}
}

// TestRun_CommitPinnedDeps_Symlink_Rejected is the regression for
// #910: even an allowed path is refused when it points at a symlink.
// Without this gate, a malicious caller could `ln -s /etc/passwd
// go.mod` and commit anything via the App identity.
func TestRun_CommitPinnedDeps_Symlink_Rejected(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	target := filepath.Join(repo, "real-target.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-target.txt", filepath.Join(repo, "go.mod")); err != nil {
		t.Fatal(err)
	}
	runGitOrFatal(t, repo, "add", "go.mod")

	srv := newCommitServer(t, commitFixture{})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitValidation {
		t.Errorf("want exit %d (validation), got %d (stderr=%q)", exitValidation, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "symlink") {
		t.Errorf("stderr must explain the symlink rejection: %q", stderr.String())
	}
}

// TestRun_CommitPinnedDeps_StructuredVariables is the regression for
// #915 / #916: the bash version sent variables as a JSON-string-
// containing-an-object instead of a structured object, and the
// server rejected the mutation. The HTTP fixture captures the body
// and asserts it parses as a typed structure.
func TestRun_CommitPinnedDeps_StructuredVariables(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\ngo 1.26\n"))
	writeAndStage(t, repo, "webhook/go.mod", []byte("module example.com/webhook\ngo 1.26\n"))

	var captured atomic.Pointer[capturedMutation]
	srv := newCommitServer(t, commitFixture{
		branchHeadSHA: branchHeadSHA,
		commitOID:     newCommitSHA,
		captureBody:   &captured,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}

	got := captured.Load()
	if got == nil {
		t.Fatal("server never received the GraphQL mutation")
	}
	// The variables key MUST decode as a structured object — the
	// #916 regression is that the bash version was sending it as a
	// quoted JSON string.
	varsAsObject, ok := got.Variables.(map[string]any)
	if !ok {
		t.Fatalf("variables must be a structured object, got %T (#916)", got.Variables)
	}
	input, ok := varsAsObject["input"].(map[string]any)
	if !ok {
		t.Fatalf("variables.input must be a structured object, got %T", varsAsObject["input"])
	}
	if input["expectedHeadOid"] != branchHeadSHA {
		t.Errorf("expectedHeadOid: want %q, got %v", branchHeadSHA, input["expectedHeadOid"])
	}
	// And both files must show up in the additions list — proves
	// the #907 NUL-stream parse worked.
	fc, ok := input["fileChanges"].(map[string]any)
	if !ok {
		t.Fatalf("variables.input.fileChanges missing or wrong shape")
	}
	additions, ok := fc["additions"].([]any)
	if !ok || len(additions) != 2 {
		t.Errorf("fileChanges.additions must have 2 entries (#907), got %v", additions)
	}
	if strings.TrimSpace(stdout.String()) != newCommitSHA {
		t.Errorf("stdout must be the new commit OID: want %q, got %q", newCommitSHA, stdout.String())
	}
}

// TestRun_CommitPinnedDeps_NULDelimitedManyFiles is a targeted
// regression for #907: 35 staged files would have produced a single
// garbled record under the bash `$()` parser. The Go parser is fed
// the raw stream, so every file must round-trip.
func TestRun_CommitPinnedDeps_NULDelimitedManyFiles(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	for _, p := range []string{
		"go.mod", "go.sum",
		"webhook/go.mod", "webhook/go.sum",
		"syslog/go.mod", "syslog/go.sum",
		"loki/go.mod", "loki/go.sum",
		"file/go.mod", "file/go.sum",
		"splunk/go.mod", "splunk/go.sum",
		"secrets/go.mod", "secrets/go.sum",
		"secrets/openbao/go.mod", "secrets/openbao/go.sum",
		"secrets/vault/go.mod", "secrets/vault/go.sum",
	} {
		writeAndStage(t, repo, p, []byte("module x\n"))
	}

	var captured atomic.Pointer[capturedMutation]
	srv := newCommitServer(t, commitFixture{
		branchHeadSHA: branchHeadSHA,
		commitOID:     newCommitSHA,
		captureBody:   &captured,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	got := captured.Load()
	if got == nil {
		t.Fatal("mutation never received")
	}
	additions := additionPathsFrom(t, got)
	if len(additions) != 18 {
		t.Errorf("want 18 additions, got %d (#907 NUL-stream parse may have collapsed paths): %v",
			len(additions), additions)
	}
}

// TestRun_CommitPinnedDeps_GraphQLErrors_ExitsOperational covers
// test-analyst B3: the production handler must translate a 200-
// with-errors GraphQL response into exit operational with a
// useful diagnostic, not silent success or a misleading "create
// commit" wrapper. Without this end-to-end lock, a future change
// to ghclient could swap the error surfacing and the test suite
// would miss it.
func TestRun_CommitPinnedDeps_GraphQLErrors_ExitsOperational(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

	srv := newCommitGraphQLErrorServer(t, branchHeadSHA)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Variable $input") {
		t.Errorf("stderr must surface the GraphQL error message: %q", stderr.String())
	}
}

// TestRun_CommitPinnedDeps_NotAGitRepo_ExitsOperational covers
// analyst I1: pointing --workdir at a directory that is not a git
// checkout must exit operational with a diagnostic that names git's
// own stderr, not silently succeed or panic.
func TestRun_CommitPinnedDeps_NotAGitRepo_ExitsOperational(t *testing.T) {
	t.Parallel()
	nonGit := t.TempDir() // empty tempdir — no .git directory
	srv := newCommitServer(t, commitFixture{})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, nonGit, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "git status failed") {
		t.Errorf("stderr must name the git status failure: %q", stderr.String())
	}
}

// newCommitGraphQLErrorServer constructs an httptest server whose
// /graphql endpoint returns the bash-era response shape that broke
// v0.2.1 — 200 status with a top-level errors array carrying the
// invalid-variable message.
func newCommitGraphQLErrorServer(t *testing.T, head string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/release/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/release/v0.2.2","object":{"sha":"` + head + `","type":"commit"}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Variable $input of type CreateCommitOnBranchInput! was provided invalid value"}]}`))
	})
	return httptest.NewServer(mux)
}

// TestGitStatusParse_HandlesRenamesAndSpacedPaths is the real
// #907 NUL-stream regression. The bash $() parser would have
// collapsed:
//   - the two NUL records of a rename ("R  newpath\x00oldpath") into
//     a single garbled string, and
//   - a path containing a literal space (`my file/go.mod`) by
//     re-splitting on whitespace.
//
// This test feeds gitstatus.Parse a hand-built NUL-delimited stream
// that EXACTLY replicates what `git status -z` emits for these
// shapes, and asserts the parsed Entry slice. Unlike the end-to-end
// many-files test, this exercises the parser at the level the bash
// version actually broke at.
func TestGitStatusParse_HandlesRenamesAndSpacedPaths(t *testing.T) {
	t.Parallel()
	// Build the porcelain stream:
	//   M  go.mod\x00              regular modified file
	//   R  webhook/go.mod\x00web_old/go.mod\x00   rename (two NUL records)
	//   M  spaced dir/go.mod\x00   path with a literal space
	raw := []byte(
		"M  go.mod\x00" +
			"R  webhook/go.mod\x00web_old/go.mod\x00" +
			"M  spaced dir/go.mod\x00",
	)
	entries, err := gitstatus.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].Path != "go.mod" {
		t.Errorf("entries[0].Path: want %q, got %q", "go.mod", entries[0].Path)
	}
	if entries[1].Path != "webhook/go.mod" || entries[1].OldPath != "web_old/go.mod" {
		t.Errorf("entries[1]: want path=webhook/go.mod old=web_old/go.mod, got path=%q old=%q (#907 rename collapse)",
			entries[1].Path, entries[1].OldPath)
	}
	if entries[2].Path != "spaced dir/go.mod" {
		t.Errorf("entries[2].Path: want %q (with literal space — bash $() would have lost this), got %q",
			"spaced dir/go.mod", entries[2].Path)
	}
}

// --- helpers ---

// newGitRepo creates a tempdir and runs `git init` so the test can
// stage paths via `git add` and have them appear in `git status -z`.
func newGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitOrFatal(t, dir, "init", "--quiet")
	runGitOrFatal(t, dir, "config", "user.email", "test@example.com")
	runGitOrFatal(t, dir, "config", "user.name", "Test User")
	runGitOrFatal(t, dir, "commit", "--allow-empty", "-m", "init")
	return dir
}

func writeAndStage(t *testing.T, root, rel string, body []byte) {
	t.Helper()
	dir := filepath.Join(root, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rel), body, 0o600); err != nil {
		t.Fatal(err)
	}
	runGitOrFatal(t, root, "add", rel)
}

func runGitOrFatal(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// capturedMutation is what the test fixture records about the
// GraphQL request body it received.
type capturedMutation struct {
	Variables any    `json:"variables"`
	Query     string `json:"query"`
}

// commitFixture configures the commit server fixture.
type commitFixture struct {
	captureBody   *atomic.Pointer[capturedMutation]
	branchHeadSHA string
	commitOID     string
}

func newCommitServer(t *testing.T, f commitFixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/release/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		if f.branchHeadSHA == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/release/v0.2.2","object":{"sha":"` + f.branchHeadSHA + `","type":"commit"}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var body capturedMutation
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("server decoding mutation: %v", err)
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if f.captureBody != nil {
			f.captureBody.Store(&body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"createCommitOnBranch":{"commit":{"oid":"` + f.commitOID + `","url":""}}}}`))
	})
	return httptest.NewServer(mux)
}

// additionPathsFrom extracts the additions paths from a captured
// mutation. Used in #907 regression assertions.
func additionPathsFrom(t *testing.T, m *capturedMutation) []string {
	t.Helper()
	vars, ok := m.Variables.(map[string]any)
	if !ok {
		t.Fatalf("variables wrong shape: %T", m.Variables)
	}
	input, ok := vars["input"].(map[string]any)
	if !ok {
		t.Fatal("variables.input wrong shape")
	}
	fc, ok := input["fileChanges"].(map[string]any)
	if !ok {
		t.Fatal("fileChanges wrong shape")
	}
	additions, ok := fc["additions"].([]any)
	if !ok {
		t.Fatal("additions wrong shape")
	}
	out := make([]string, 0, len(additions))
	for _, a := range additions {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := am["path"].(string); ok {
			out = append(out, p)
		}
	}
	return out
}
