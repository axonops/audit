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

// Command release-tool is the audit project's typed replacement for
// scripts/release/gh-graphql-commit.sh and gh-graphql-tag.sh.
//
// PR-2 (this revision) lays the foundation: the subcommand dispatch,
// persistent flags, and the four internal helper packages. PR-3 will
// add the `commit-pinned-deps` and `create-tag` subcommands that
// orchestrate the helpers into the actual release flow.
//
// # I/O contract
//
// Stderr is for humans. Every log line, error, and diagnostic
// message goes there.
//
// Stdout is for machines. When a subcommand produces a result the
// release workflow needs to capture (e.g. the SHA of a created
// commit), it writes the value to stdout with no decoration.
//
// # Exit codes
//
//	0 — success
//	1 — operational failure (API error, network, I/O)
//	2 — usage error (flag parse, unknown subcommand)
//	3 — validation error (allowlist rejected, invalid SHA)
//	4 — idempotent no-op (target already in desired state)
//
// # Environment
//
// GH_TOKEN — required. The App's Installation Token. Never logged.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// Exit codes. All are referenced in the help text; PR-3 subcommands
// will start returning the validation / idempotent codes once they
// land.
const (
	exitSuccess        = 0
	exitOperational    = 1
	exitUsage          = 2
	exitValidation     = 3
	exitIdempotentNoOp = 4
)

// reservedExitCodes silences the linter for the PR-3 placeholders.
// PR-3 will start returning these and the variable becomes
// unnecessary at that point.
var _ = []int{exitOperational, exitValidation, exitIdempotentNoOp}

// rootFlags holds the persistent flags every subcommand inherits.
type rootFlags struct {
	help    bool
	version bool
	dryRun  bool
	timeout time.Duration
}

func main() {
	os.Exit(run(context.Background(), os.Args, os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns the exit code rather
// than calling os.Exit directly so unit tests can assert on it.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("release-tool", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { writeRootHelp(fs.Output()) }

	rf := rootFlags{}
	fs.BoolVar(&rf.help, "help", false, "Show this help and exit.")
	fs.BoolVar(&rf.version, "version", false, "Print the release-tool version and exit.")
	fs.BoolVar(&rf.dryRun, "dry-run", false,
		"Print every state-mutating API payload to stdout and exit 0 without performing the mutation.")
	fs.DurationVar(&rf.timeout, "timeout", 30*time.Second,
		"Per-request timeout for GitHub API calls.")

	// Split args at the first non-flag — that's the subcommand.
	subArgs, sub := splitSubcommand(args[1:])
	if perr := fs.Parse(subArgs); perr != nil {
		// fs already wrote a diagnostic.
		return exitUsage
	}

	if rf.help {
		writeRootHelp(stderr)
		return exitSuccess
	}
	if rf.version {
		_, _ = fmt.Fprintln(stdout, versionString())
		return exitSuccess
	}

	if sub == "" {
		_, _ = fmt.Fprintln(stderr, "release-tool: no subcommand specified; run --help for usage")
		return exitUsage
	}

	// PR-3 will register subcommand handlers here. For now any
	// subcommand is unknown.
	_ = ctx
	_, _ = fmt.Fprintf(stderr, "release-tool: unknown subcommand %q; run --help for usage\n", sub)
	return exitUsage
}

// splitSubcommand walks argv looking for the first non-flag token.
// Returns (flagArgs, subcommandName). When no subcommand is present,
// returns the full slice and "".
func splitSubcommand(argv []string) (flagArgs []string, subcommand string) {
	for i, a := range argv {
		if a == "--" {
			// Everything after `--` is positional / subcommand-owned.
			if i+1 < len(argv) {
				return argv[:i], argv[i+1]
			}
			return argv[:i], ""
		}
		if a == "" || a[0] == '-' {
			continue
		}
		return argv[:i], a
	}
	return argv, ""
}

// versionString returns the human-readable version. When the binary
// is built via `go build` (no ldflags), it appends the VCS revision
// from the Go runtime debug info so operators can identify the exact
// commit a CI run executed.
func versionString() string {
	if version != "dev" {
		return "release-tool " + version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev string
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				rev = s.Value[:7]
			}
		}
		if rev != "" {
			return "release-tool dev (commit " + rev + ")"
		}
	}
	return "release-tool dev"
}

func writeRootHelp(w io.Writer) {
	const helpText = `release-tool — typed automation for the audit release flow

USAGE
    release-tool [persistent flags] <subcommand> [subcommand flags]

PERSISTENT FLAGS
    --dry-run             Print every state-mutating API payload to stdout
                          and exit 0 without performing the mutation.
    --timeout DURATION    Per-request timeout for GitHub API calls.
                          Default: 30s.
    --help                Show this help and exit.
    --version             Print the release-tool version and exit.

SUBCOMMANDS (PR-3, not yet implemented)
    commit-pinned-deps    Open an App-signed commit pinning every go.mod
                          to a release version.
    create-tag            Create an annotated tag on a commit SHA.

EXIT CODES
    0 — success
    1 — operational failure (API error, network, I/O)
    2 — usage error (flag parse, unknown subcommand)
    3 — validation error (allowlist rejected, invalid SHA)
    4 — idempotent no-op (target already in desired state)

ENVIRONMENT
    GH_TOKEN              GitHub App Installation Token. Required for
                          all subcommands that hit the GitHub API.

I/O CONTRACT
    Stderr is for humans. Logs, errors, diagnostics go there.
    Stdout is for machines. Subcommand results (new commit SHA, etc.)
    go there with no decoration so they can be captured into a shell
    variable.
`
	_, _ = fmt.Fprint(w, helpText)
}
