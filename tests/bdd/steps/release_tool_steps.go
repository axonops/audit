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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// releaseToolState is private to the release-tool BDD scenarios.
// A fresh instance is created per scenario by registerReleaseToolSteps.
type releaseToolState struct {
	binaryPath string
	stdout     bytes.Buffer
	stderr     bytes.Buffer
	exitCode   int
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

	ctx.Given(`^the release-tool binary has been built$`, func() error {
		// We expect the binary at <repo>/bin/release-tool, built by
		// `make build-release-tool`. The BDD harness can not perform
		// the build itself (no go.mod boundary to lean on); the
		// surrounding make target handles it.
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
		return s.run(argStr)
	})

	ctx.When(`^I run release-tool with these args:$`, func(doc *godog.DocString) error {
		return s.runWithRawArgs(doc.Content)
	})

	ctx.When(`^I run release-tool with no arguments$`, func() error {
		return s.run("")
	})

	ctx.Then(`^the exit code is (\d+)$`, func(want int) error {
		if s.exitCode != want {
			return fmt.Errorf("exit code: want %d, got %d (stderr=%q)",
				want, s.exitCode, s.stderr.String())
		}
		return nil
	})

	ctx.Then(`^the stderr contains "([^"]*)"$`, func(needle string) error {
		if !strings.Contains(s.stderr.String(), needle) {
			return fmt.Errorf("stderr missing %q\n--- stderr ---\n%s", needle, s.stderr.String())
		}
		return nil
	})

	ctx.Then(`^the stdout starts with "([^"]*)"$`, func(prefix string) error {
		if !strings.HasPrefix(s.stdout.String(), prefix) {
			return fmt.Errorf("stdout prefix: want %q, got %q", prefix, s.stdout.String())
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
