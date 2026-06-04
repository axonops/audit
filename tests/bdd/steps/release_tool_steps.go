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

package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/cucumber/godog"
)

// releaseToolState is private to the release-tool BDD scenarios.
// A fresh instance is created per scenario by registerReleaseToolSteps.
type releaseToolState struct {
	server      *httptest.Server // pointer (8) — set when scenarios start a fake GH API
	binaryPath  string           // path to bin/release-tool
	gitRepo     string           // temp dir with `git init` for commit-pinned-deps scenarios
	capturedOID string           // OID returned by the fake GraphQL server
	capturedTag string           // tag-object SHA returned by the fake REST server
	stdout      bytes.Buffer
	stderr      bytes.Buffer
	mutations   atomic.Int32 // mutation-endpoint hit counter
	createRefs  atomic.Int32 // POST /git/refs hit counter (for auto-create-branch)
	exitCode    int
}

// registerReleaseToolSteps registers the Gherkin steps that drive the
// release-tool binary via os/exec.
//
// release-tool is a CLI binary (not a Go-API library), so the steps
// here capture stdout / stderr / exit code from a subprocess rather
// than from in-process function calls. The scenarios assert the
// observable external contract: stdout is for machines, stderr is
// for humans, exit codes follow the 0 / 1 / 2 / 3 / 4 ladder.
//
// State is per-scenario: every scenario gets a fresh
// releaseToolState struct via the BeforeScenario hook. A single
// shared struct (the previous design) would race if godog ever ran
// scenarios with Concurrency > 1.
func registerReleaseToolSteps(ctx *godog.ScenarioContext, _ *AuditTestContext) {
	var s *releaseToolState
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		s = &releaseToolState{}
		return c, nil
	})
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if s.server != nil {
			s.server.Close()
		}
		return c, nil
	})

	registerCoreSteps(ctx, func() *releaseToolState { return s })
	registerFixtureSteps(ctx, func() *releaseToolState { return s })
	registerServerSteps(ctx, func() *releaseToolState { return s })
	registerInvocationSteps(ctx, func() *releaseToolState { return s })
	registerAssertionSteps(ctx, func() *releaseToolState { return s })
}

// registerCoreSteps wires the persistent-flag scenarios that don't
// need a fake server or git repo.
func registerCoreSteps(ctx *godog.ScenarioContext, get func() *releaseToolState) {
	ctx.Given(`^the release-tool binary has been built$`, func() error {
		s := get()
		repoRoot, err := findRepoRoot()
		if err != nil {
			return err
		}
		s.binaryPath = filepath.Join(repoRoot, "bin", "release-tool")
		if _, err := exec.LookPath(s.binaryPath); err != nil {
			return fmt.Errorf("release-tool binary not found at %s — run `make build-release-tool`: %w",
				s.binaryPath, err)
		}
		return nil
	})

	ctx.When(`^I run release-tool with arguments "([^"]*)"$`, func(argStr string) error {
		return get().run(argStr)
	})
	ctx.When(`^I run release-tool with these args:$`, func(doc *godog.DocString) error {
		return get().runWithRawArgs(doc.Content)
	})
	ctx.When(`^I run release-tool with no arguments$`, func() error {
		return get().run("")
	})

	ctx.Then(`^the exit code is (\d+)$`, func(want int) error {
		s := get()
		if s.exitCode != want {
			return fmt.Errorf("exit code: want %d, got %d (stderr=%q)",
				want, s.exitCode, s.stderr.String())
		}
		return nil
	})
	ctx.Then(`^the stderr contains "([^"]*)"$`, func(needle string) error {
		s := get()
		if !strings.Contains(s.stderr.String(), needle) {
			return fmt.Errorf("stderr missing %q\n--- stderr ---\n%s", needle, s.stderr.String())
		}
		return nil
	})
	ctx.Then(`^the stdout starts with "([^"]*)"$`, func(prefix string) error {
		s := get()
		if !strings.HasPrefix(s.stdout.String(), prefix) {
			return fmt.Errorf("stdout prefix: want %q, got %q", prefix, s.stdout.String())
		}
		return nil
	})
}

// registerFixtureSteps wires the Given-side filesystem fixtures
// (staged go.mod, off-allowlist path, symlink).
func registerFixtureSteps(ctx *godog.ScenarioContext, get func() *releaseToolState) {
	ctx.Given(`^a staged go.mod in a fresh git repo$`, func() error {
		return get().stageFile("go.mod", []byte("module example.com\n"))
	})
	ctx.Given(`^a staged ".github/workflows/release.yml" in a fresh git repo$`, func() error {
		return get().stageFile(".github/workflows/release.yml", []byte("# off-allowlist\n"))
	})
	ctx.Given(`^a symlinked go.mod in a fresh git repo$`, func() error {
		s := get()
		if err := s.ensureRepo(); err != nil {
			return err
		}
		target := filepath.Join(s.gitRepo, "real-target.txt")
		if err := os.WriteFile(target, []byte("secret\n"), 0o600); err != nil {
			return fmt.Errorf("write target: %w", err)
		}
		if err := os.Symlink("real-target.txt", filepath.Join(s.gitRepo, "go.mod")); err != nil {
			return fmt.Errorf("symlink: %w", err)
		}
		return s.gitAdd("go.mod")
	})
}

// registerServerSteps wires the Given-side httptest fake-server
// configurations.
func registerServerSteps(ctx *godog.ScenarioContext, get func() *releaseToolState) {
	ctx.Given(`^the GH_API_URL points at a server that accepts the GraphQL mutation$`, func() error {
		get().startCommitServer(serverProfileCommitAccept)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server that fails on any request$`, func() error {
		get().startCommitServer(serverProfileFailAny)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server that succeeds on idempotency lookups but fails on any mutation$`, func() error {
		get().startCommitServer(serverProfileDryRun)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server where the release branch does not exist$`, func() error {
		get().startCommitServer(serverProfileAutoCreate)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server where the tag does not exist$`, func() error {
		get().startCreateTagServer(serverProfileTagFresh)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server where the tag does not exist and any mutation fails the test$`, func() error {
		get().startCreateTagServer(serverProfileTagDryRun)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server where the tag exists at the same SHA$`, func() error {
		get().startCreateTagServer(serverProfileTagSameSHA)
		return nil
	})
	ctx.Given(`^the GH_API_URL points at a server where the tag exists at a different SHA$`, func() error {
		get().startCreateTagServer(serverProfileTagDifferentSHA)
		return nil
	})
}

// registerInvocationSteps wires the When-side subcommand
// invocations that drive the binary against the configured server.
func registerInvocationSteps(ctx *godog.ScenarioContext, get func() *releaseToolState) {
	ctx.When(`^I run release-tool commit-pinned-deps against that server$`, func() error {
		return get().runCommitPinnedDeps(false)
	})
	ctx.When(`^I run release-tool commit-pinned-deps with --dry-run against that server$`, func() error {
		return get().runCommitPinnedDeps(true)
	})
	ctx.When(`^I run release-tool commit-pinned-deps with --auto-create-branch against that server$`, func() error {
		return get().runCommitPinnedDepsAutoCreate()
	})
	ctx.When(`^I run release-tool create-tag against that server$`, func() error {
		return get().runCreateTag(false)
	})
	ctx.When(`^I run release-tool create-tag with --dry-run against that server$`, func() error {
		return get().runCreateTag(true)
	})
}

// registerAssertionSteps wires the Then-side assertions on stdout,
// stderr, and server-side mutation counters.
func registerAssertionSteps(ctx *godog.ScenarioContext, get func() *releaseToolState) {
	ctx.Then(`^the stdout is exactly the captured commit OID$`, func() error {
		s := get()
		want := s.capturedOID + "\n"
		if s.stdout.String() != want {
			return fmt.Errorf("stdout: want %q, got %q", want, s.stdout.String())
		}
		return nil
	})
	ctx.Then(`^the stdout is exactly the captured tag-object SHA$`, func() error {
		s := get()
		want := s.capturedTag + "\n"
		if s.stdout.String() != want {
			return fmt.Errorf("stdout: want %q, got %q", want, s.stdout.String())
		}
		return nil
	})
	ctx.Then(`^the stdout decodes as JSON containing "([^"]*)"$`, func(needle string) error {
		s := get()
		var v any
		if err := json.Unmarshal(s.stdout.Bytes(), &v); err != nil {
			return fmt.Errorf("stdout must be valid JSON: %w (stdout=%s)", err, s.stdout.String())
		}
		if !strings.Contains(s.stdout.String(), needle) {
			return fmt.Errorf("stdout JSON missing %q\n%s", needle, s.stdout.String())
		}
		return nil
	})
	ctx.Then(`^the server received zero mutation requests$`, func() error {
		s := get()
		if got := s.mutations.Load(); got != 0 {
			return fmt.Errorf("dry-run must perform zero mutating calls, got %d", got)
		}
		return nil
	})
	ctx.Then(`^the server received a CreateRef call for the release branch$`, func() error {
		s := get()
		if got := s.createRefs.Load(); got == 0 {
			return errors.New("auto-create-branch must call POST /git/refs at least once")
		}
		return nil
	})
}

// runWithRawArgs treats the input as one argument per non-empty
// line, no shell parsing at all. This is what scenarios should use
// for anything containing JSON or other shell-special characters,
// because it preserves bytes verbatim. The splitShellLike helper is
// reserved for simple whitespace-separated argument lists.
func (s *releaseToolState) runWithRawArgs(raw string) error {
	s.stdout.Reset()
	s.stderr.Reset()
	s.exitCode = 0

	lines := strings.Split(raw, "\n")
	args := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		args = append(args, line)
	}
	return s.exec(args)
}

// run executes the binary with shell-style argument splitting so the
// Gherkin can quote SHAs containing special chars.
func (s *releaseToolState) run(argStr string) error {
	s.stdout.Reset()
	s.stderr.Reset()
	s.exitCode = 0

	var args []string
	if strings.TrimSpace(argStr) != "" {
		var err error
		args, err = splitShellLike(argStr)
		if err != nil {
			return fmt.Errorf("split %q: %w", argStr, err)
		}
	}
	return s.exec(args)
}

// exec is the shared subprocess execution path used by both `run`
// (whitespace-split args) and `runWithRawArgs` (one-arg-per-line).
func (s *releaseToolState) exec(args []string) error {
	return s.execEnv(args, nil)
}

// execEnv is like exec but appends extra env vars. Used by the
// orchestration scenarios to inject GH_API_URL.
func (s *releaseToolState) execEnv(args, extraEnv []string) error {
	// G204 is satisfied: s.binaryPath is `<repo>/bin/release-tool`,
	// constructed by findRepoRoot (which walks the local filesystem
	// looking for the audit go.mod) — not influenced by external
	// input. args come from a Gherkin feature file checked into the
	// repository, also not user-supplied.
	cmd := exec.Command(s.binaryPath, args...) //nolint:gosec // see comment above
	cmd.Stdout = &s.stdout
	cmd.Stderr = &s.stderr
	// Set GH_TOKEN to a stub so buildClient gets past the env
	// check; tests assert exit codes BEFORE any HTTP call is made.
	cmd.Env = append(cmd.Environ(), "GH_TOKEN=stub-token-for-bdd")
	cmd.Env = append(cmd.Env, extraEnv...)

	err := cmd.Run()
	if exitErr, ok := asExitError(err); ok {
		s.exitCode = exitErr.ExitCode()
		return nil
	}
	if err != nil {
		return fmt.Errorf("exec release-tool: %w", err)
	}
	s.exitCode = 0
	return nil
}

// --- Orchestration helpers ---

// fakeBranchHead / fakeCommitOID / fakeTagSHA are the canonical
// "happy-path" SHAs the fake servers return.
const (
	fakeBranchHead = "feedface0000000000000000000000000000feed"
	fakeCommitOID  = "cafebabe0000000000000000000000000000cafe"
	fakeTagSHA     = "9999999999999999999999999999999999999999"
	fakeTagCommit  = "abcdef0123456789abcdef0123456789abcdef01"
	fakeOtherSHA   = "0123456789abcdef0123456789abcdef01234567"
)

type serverProfile int

const (
	serverProfileCommitAccept serverProfile = iota
	serverProfileFailAny
	serverProfileDryRun
	serverProfileAutoCreate
	serverProfileTagFresh
	serverProfileTagSameSHA
	serverProfileTagDifferentSHA
	serverProfileTagDryRun
)

// ensureRepo lazily initialises s.gitRepo with `git init` so the
// scenario can stage files via gitAdd.
func (s *releaseToolState) ensureRepo() error {
	if s.gitRepo != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "release-tool-bdd-*")
	if err != nil {
		return fmt.Errorf("mkdtemp: %w", err)
	}
	s.gitRepo = dir
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test User"},
		{"commit", "--allow-empty", "-m", "init"},
	} {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // tempdir
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w (output=%s)", args, err, out)
		}
	}
	return nil
}

// stageFile writes a file (relative to s.gitRepo) and `git add`s it.
func (s *releaseToolState) stageFile(rel string, content []byte) error {
	if err := s.ensureRepo(); err != nil {
		return err
	}
	full := filepath.Join(s.gitRepo, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return s.gitAdd(rel)
}

// gitAdd stages rel inside s.gitRepo.
func (s *releaseToolState) gitAdd(rel string) error {
	c := exec.Command("git", "-C", s.gitRepo, "add", rel) //nolint:gosec // tempdir + checked-in fixture
	c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("git add %s: %w (output=%s)", rel, err, out)
	}
	return nil
}

// startCommitServer wires up the fake GH server for commit-pinned-deps.
func (s *releaseToolState) startCommitServer(p serverProfile) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/release/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		switch p { //nolint:exhaustive // tag-profile cases never hit this commit endpoint
		case serverProfileFailAny:
			w.WriteHeader(http.StatusInternalServerError)
		case serverProfileAutoCreate:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/release/v0.2.2","object":{"sha":"` + fakeBranchHead + `","type":"commit"}}`))
		}
	})
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/main","object":{"sha":"` + fakeBranchHead + `","type":"commit"}}`))
	})
	mux.HandleFunc("/repos/axonops/audit/git/refs", func(w http.ResponseWriter, r *http.Request) {
		s.createRefs.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/release/v0.2.2","object":{"sha":"` + fakeBranchHead + `","type":"commit"}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		s.mutations.Add(1)
		if p == serverProfileFailAny || p == serverProfileDryRun {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.capturedOID = fakeCommitOID
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"createCommitOnBranch":{"commit":{"oid":"` + fakeCommitOID + `","url":""}}}}`))
	})
	s.server = httptest.NewServer(mux)
}

// startCreateTagServer wires up the fake GH server for create-tag.
func (s *releaseToolState) startCreateTagServer(p serverProfile) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/tags/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		switch p { //nolint:exhaustive // commit-profile cases never hit this tag endpoint
		case serverProfileTagSameSHA:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ref":"refs/tags/v0.2.2","object":{"sha":"` + fakeTagCommit + `","type":"commit"}}`))
		case serverProfileTagDifferentSHA:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ref":"refs/tags/v0.2.2","object":{"sha":"` + fakeOtherSHA + `","type":"commit"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	mux.HandleFunc("/repos/axonops/audit/git/tags", func(w http.ResponseWriter, r *http.Request) {
		s.mutations.Add(1)
		if p == serverProfileTagDryRun {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.capturedTag = fakeTagSHA
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sha":"` + fakeTagSHA + `","tag":"v0.2.2"}`))
	})
	mux.HandleFunc("/repos/axonops/audit/git/refs", func(w http.ResponseWriter, r *http.Request) {
		s.mutations.Add(1)
		if p == serverProfileTagDryRun {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ref":"refs/tags/v0.2.2","object":{"sha":"` + fakeTagSHA + `","type":"tag"}}`))
	})
	s.server = httptest.NewServer(mux)
}

// runCommitPinnedDeps invokes the subcommand against s.server with
// s.gitRepo as the workdir.
func (s *releaseToolState) runCommitPinnedDeps(dryRun bool) error {
	args := []string{}
	if dryRun {
		args = append(args, "--dry-run")
	}
	args = append(args,
		"commit-pinned-deps",
		"--owner", "axonops", "--repo", "audit",
		"--branch", "release/v0.2.2",
		"--message", "chore: pin deps for BDD",
		"--workdir", s.gitRepo,
	)
	return s.execEnv(args, []string{"GH_API_URL=" + s.server.URL})
}

// runCommitPinnedDepsAutoCreate runs with --auto-create-branch.
func (s *releaseToolState) runCommitPinnedDepsAutoCreate() error {
	args := []string{
		"commit-pinned-deps",
		"--owner", "axonops", "--repo", "audit",
		"--branch", "release/v0.2.2",
		"--message", "chore: pin deps for BDD",
		"--workdir", s.gitRepo,
		"--auto-create-branch",
	}
	return s.execEnv(args, []string{"GH_API_URL=" + s.server.URL})
}

// runCreateTag invokes the subcommand against s.server.
func (s *releaseToolState) runCreateTag(dryRun bool) error {
	args := []string{}
	if dryRun {
		args = append(args, "--dry-run")
	}
	args = append(args,
		"create-tag",
		"--owner", "axonops", "--repo", "audit",
		"--tag", "v0.2.2",
		"--sha", fakeTagCommit,
		"--message", "Release v0.2.2",
	)
	return s.execEnv(args, []string{"GH_API_URL=" + s.server.URL})
}

// splitShellLike splits a string on whitespace, respecting single and
// double-quoted regions. No backslash escaping, no command
// substitution. Sufficient for the release-tool BDD scenarios that
// quote a single value (e.g. an invalid SHA JSON string) inside the
// argument list.
func splitShellLike(s string) ([]string, error) {
	st := splitState{}
	for _, r := range s {
		st.consume(r)
	}
	if st.quote != 0 {
		return nil, fmt.Errorf("unterminated %c-quoted string", st.quote)
	}
	st.flush()
	return st.out, nil
}

// splitState carries the running state of splitShellLike.
type splitState struct {
	current strings.Builder
	out     []string
	quote   rune
	inField bool
}

// consume processes one rune of input.
func (st *splitState) consume(r rune) {
	switch {
	case st.quote != 0:
		st.consumeQuoted(r)
	case r == '\'' || r == '"':
		st.quote = r
		st.inField = true
	case r == ' ' || r == '\t':
		st.flush()
	default:
		st.current.WriteRune(r)
		st.inField = true
	}
}

// consumeQuoted handles a rune inside a quoted region.
func (st *splitState) consumeQuoted(r rune) {
	if r == st.quote {
		st.quote = 0
		return
	}
	st.current.WriteRune(r)
	st.inField = true
}

// flush moves the current field (if any) into the output slice.
func (st *splitState) flush() {
	if !st.inField {
		return
	}
	st.out = append(st.out, st.current.String())
	st.current.Reset()
	st.inField = false
}

// asExitError narrows err to *exec.ExitError when applicable.
func asExitError(err error) (*exec.ExitError, bool) {
	if err == nil {
		return nil, false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr, true
	}
	return nil, false
}

// findRepoRoot walks upward looking for a go.mod that declares the
// audit module. release-tool's BDD steps need the absolute path so
// they can locate the built binary regardless of CWD at test time.
//
// Match is line-based (not substring) so a sub-module go.mod's
// `require github.com/axonops/audit` line cannot false-positive,
// and line-ending agnostic so Windows / CRLF checkouts behave
// correctly. The walk is bounded by maxRepoRootDepth to avoid
// pathological climbs through `/`.
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("release-tool BDD: getwd: %w", err)
	}
	dir := wd
	for i := 0; i < maxRepoRootDepth; i++ {
		// G304 is satisfied: dir starts at os.Getwd() and walks
		// upward by repeated filepath.Dir, so the path is always
		// derived from the local filesystem layout — never from
		// user input.
		data, err := os.ReadFile(filepath.Join(dir, "go.mod")) //nolint:gosec // see comment above
		if err == nil && isAuditRootGoMod(data) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("release-tool BDD: could not locate audit repo root within %d levels above %s",
		maxRepoRootDepth, wd)
}

// maxRepoRootDepth caps the findRepoRoot upward walk. 20 is more
// than enough for any realistic checkout depth and prevents a
// malformed go.mod from making the walk run all the way to `/`.
const maxRepoRootDepth = 20

// isAuditRootGoMod reports whether data is the root audit go.mod by
// scanning lines (not substring), so CRLF line endings work and a
// sub-module's `require github.com/axonops/audit ...` line cannot
// false-positive.
func isAuditRootGoMod(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "module github.com/axonops/audit" {
			return true
		}
	}
	return false
}
