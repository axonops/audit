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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/axonops/audit/cmd/release-tool/internal/sumdb"
)

// preflightTidyArgs are the parsed flags for the
// preflight-tidy-check subcommand.
type preflightTidyArgs struct {
	workdir             string
	lastReleasedVersion string
	publishedModulesCSV string
	sumdbEndpoint       string
	sumdbTimeout        time.Duration
	maxDiffBytes        int64
	skipSumdbCrossCheck bool
	dryRun              bool
}

// AC #4 exact error strings — operator-facing contract. Each is
// emitted to stderr (for human consumption) AND stdout (for the
// workflow $GITHUB_STEP_SUMMARY pipe). Do NOT alter punctuation,
// capitalisation, or the em-dash without updating the AC and the
// bats grep assertions in tests/release-scripts/release-yml-grep.bats.
const (
	msgNoDrift             = "preflight-tidy: no drift to absorb"
	msgGoModModified       = "preflight-tidy: go.mod modified — aborting"
	msgGoSumDeletions      = "preflight-tidy: go.sum lines deleted — aborting"
	msgUnrelatedChecksums  = "preflight-tidy: unrelated checksum lines — aborting"
	msgSumdbDisagrees      = "preflight-tidy: sum.golang.org disagrees — aborting"
	msgSumdbTransient      = "preflight-tidy: sum.golang.org timeout or 5xx — aborting"
	msgDiffSizeCapExceeded = "preflight-tidy: diff exceeds size cap — aborting"
)

// runPreflightTidyCheck implements the `preflight-tidy-check`
// subcommand. It inspects the working tree's uncommitted diff
// (presumed to be the output of a fresh `make tidy`) and aborts
// with one of the operator-facing AC #4 error strings if any
// safety gate fails. On a successful check, stdout receives a
// machine-readable summary of the validated module/version pairs.
//
// Exit codes:
//
//	0 — all gates pass, diff is safe to commit
//	1 — operational failure (sumdb network, etc.)
//	2 — usage error
//	3 — validation failure (one of the safety gates)
//	4 — no diff (idempotent no-op)
func runPreflightTidyCheck(ctx context.Context, args []string, stdout, stderr io.Writer, persistent *rootFlags) int {
	fs := flag.NewFlagSet("preflight-tidy-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { writePreflightTidyCheckHelp(fs.Output()) }

	in := preflightTidyArgs{}
	fs.StringVar(&in.workdir, "workdir", ".",
		"Path to the git working directory (must be a trusted release-flow checkout)")
	fs.StringVar(&in.lastReleasedVersion, "last-released-version", "",
		"Last released version, e.g. v0.2.2 — gates 3+4 root their checks here (required)")
	fs.StringVar(&in.publishedModulesCSV, "published-modules", "",
		"Comma-separated list of github.com/axonops/audit/<sub> module paths to expect in the diff (required)")
	// #971: default bumped 8 KiB → 64 KiB. The original 8 KiB was a
	// per-module estimate from the #967 security review; the actual
	// v0.2.2→v0.2.3 drift is ~10–12 KiB across 15 sub-module go.sum
	// files. 64 KiB bounds a runaway-diff attack but accommodates
	// expected drift for ~80 modules of headroom.
	fs.Int64Var(&in.maxDiffBytes, "max-diff-bytes", 65536,
		"Hard cap on total diff size in bytes; larger diffs abort with msgDiffSizeCapExceeded")
	fs.StringVar(&in.sumdbEndpoint, "sumdb-endpoint", sumdb.DefaultEndpoint,
		"Sigstore checksum database endpoint")
	fs.DurationVar(&in.sumdbTimeout, "sumdb-timeout", 30*time.Second,
		"Per-module sumdb lookup timeout")
	fs.BoolVar(&in.skipSumdbCrossCheck, "skip-sumdb-cross-check", false,
		"DANGER: skip gate 4 (sum.golang.org cross-check). Test-only.")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	in.dryRun = persistent.dryRun

	if in.lastReleasedVersion == "" {
		_, _ = fmt.Fprintln(stderr, "preflight-tidy-check: --last-released-version is required")
		return exitUsage
	}
	if in.publishedModulesCSV == "" {
		_, _ = fmt.Fprintln(stderr, "preflight-tidy-check: --published-modules is required")
		return exitUsage
	}

	publishedModules := splitPublishedModules(in.publishedModulesCSV)
	if len(publishedModules) == 0 {
		_, _ = fmt.Fprintln(stderr, "preflight-tidy-check: --published-modules parsed to empty list")
		return exitUsage
	}

	return doPreflightTidyCheck(ctx, &in, publishedModules, stdout, stderr)
}

// doPreflightTidyCheck runs the six safety gates against the
// working-tree diff produced by `make tidy`. Split out from the
// flag-parsing path so tests can inject a faked sumdb endpoint and
// workdir.
func doPreflightTidyCheck(ctx context.Context, in *preflightTidyArgs, publishedModules []string, stdout, stderr io.Writer) int {
	// Step 1 — capture the uncommitted diff.
	diffBytes, code := captureDiff(in.workdir, stderr)
	if code != exitSuccess {
		return code
	}
	if len(diffBytes) == 0 {
		emit(stdout, stderr, msgNoDrift)
		return exitIdempotentNoOp
	}

	// Diff-size cap — defence-in-depth against runaway diffs.
	if int64(len(diffBytes)) > in.maxDiffBytes {
		emit(stdout, stderr, msgDiffSizeCapExceeded)
		return exitValidation
	}

	// Step 2 — parse the diff into per-file additions/deletions.
	files, err := parseUnifiedDiff(diffBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "preflight-tidy-check: parse diff: %v\n", err)
		return exitOperational
	}

	// Gate 1 — go.sum only (no go.mod changes).
	if hasGoModChange(files) {
		emit(stdout, stderr, msgGoModModified)
		return exitValidation
	}

	// Gate 2 — additions only (no deletions).
	if hasGoSumDeletions(files) {
		emit(stdout, stderr, msgGoSumDeletions)
		return exitValidation
	}

	// Collect all added go.sum lines, scoped to go.sum paths only.
	added := collectAddedGoSumLines(files)

	// Gate 3 — every added line must reference the just-released
	// version at one of the published module paths. Anything else
	// aborts with msgUnrelatedChecksums.
	if !linesAreInExpectedSet(added, publishedModules, in.lastReleasedVersion) {
		emit(stdout, stderr, msgUnrelatedChecksums)
		return exitValidation
	}

	// Gate 4 — cross-check each unique (module, version) pair
	// against sum.golang.org's transparency log.
	if !in.skipSumdbCrossCheck {
		code := crossCheckAgainstSumdb(ctx, added, in, stdout, stderr)
		if code != exitSuccess {
			// crossCheckAgainstSumdb has already emitted the
			// appropriate operator-facing string.
			return code
		}
	}

	// All gates passed. Stdout receives a machine-readable summary
	// of the unique (module, version) pairs validated, one per
	// line, so the workflow can echo them into the summary table.
	emitValidatedSummary(stdout, added)
	return exitSuccess
}

// emit writes msg to BOTH stdout and stderr so it lands in both the
// machine-consumable channel (workflow $GITHUB_STEP_SUMMARY pipe)
// and the human-readable run log.
func emit(stdout, stderr io.Writer, msg string) {
	_, _ = fmt.Fprintln(stdout, msg)
	_, _ = fmt.Fprintln(stderr, msg)
}

// captureDiff runs `git -C workdir diff --no-color --no-ext-diff
// HEAD` and returns the resulting unified diff. An empty result
// means the working tree is clean (the "no drift" path).
func captureDiff(workdir string, stderr io.Writer) (diff []byte, exit int) {
	cmd := exec.Command("git", "-C", workdir, "diff", "--no-color", "--no-ext-diff", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "preflight-tidy-check: git diff failed: %v\n", err)
		return nil, exitOperational
	}
	return out, exitSuccess
}

// fileDiff captures the additions and deletions for a single file
// in a parsed unified diff.
type fileDiff struct {
	path      string
	additions []string
	deletions []string
}

// parseUnifiedDiff is a minimal parser for `git diff --no-color`
// output covering just what the safety gates need: per-file
// addition / deletion lines (with the leading +/- stripped). It
// deliberately rejects unfamiliar diff structures rather than
// silently tolerating them — a parse anomaly during a release flow
// is exactly the kind of thing we want to bubble. The structure
// mirrors the unified-diff spec; flatter as one switch.
//
//nolint:gocognit,gocyclo,cyclop // see godoc above
func parseUnifiedDiff(diff []byte) ([]fileDiff, error) {
	if len(diff) == 0 {
		return nil, nil
	}
	var files []fileDiff
	var cur *fileDiff
	lines := strings.Split(string(diff), "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if cur != nil {
				files = append(files, *cur)
			}
			cur = &fileDiff{}
		case strings.HasPrefix(line, "+++ b/"):
			if cur == nil {
				return nil, errors.New("malformed diff: +++ outside file block")
			}
			cur.path = strings.TrimPrefix(line, "+++ b/")
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "index "),
			strings.HasPrefix(line, "@@"), strings.HasPrefix(line, "new file mode"),
			strings.HasPrefix(line, "deleted file mode"), strings.HasPrefix(line, "similarity"),
			strings.HasPrefix(line, "rename "), strings.HasPrefix(line, "Binary files"):
			// Header / hunk-marker / mode / rename / binary — skip.
		case strings.HasPrefix(line, "+"):
			if cur == nil {
				return nil, errors.New("malformed diff: + line outside file block")
			}
			cur.additions = append(cur.additions, strings.TrimPrefix(line, "+"))
		case strings.HasPrefix(line, "-"):
			if cur == nil {
				return nil, errors.New("malformed diff: - line outside file block")
			}
			cur.deletions = append(cur.deletions, strings.TrimPrefix(line, "-"))
		case line == "":
			// Blank between hunks — skip.
		default:
			// Context line (no +/- prefix) — skip.
		}
	}
	if cur != nil {
		files = append(files, *cur)
	}
	return files, nil
}

// hasGoModChange reports true if any file in the diff is a go.mod.
func hasGoModChange(files []fileDiff) bool {
	for _, f := range files {
		if isGoModPath(f.path) {
			return true
		}
	}
	return false
}

// hasGoSumDeletions reports true if any go.sum file has at least
// one deletion line. tidy can prune orphaned checksums — but doing
// so on a release dispatch could quietly drop a checksum a
// maintainer added on purpose. Force human review.
func hasGoSumDeletions(files []fileDiff) bool {
	for _, f := range files {
		if !isGoSumPath(f.path) {
			continue
		}
		if len(f.deletions) > 0 {
			return true
		}
	}
	return false
}

// collectAddedGoSumLines returns the parsed addition lines from
// every go.sum in the diff. Non-go.sum files (which gate 1 should
// have rejected, but are skipped here defensively) are ignored.
func collectAddedGoSumLines(files []fileDiff) []parsedGoSumLine {
	var out []parsedGoSumLine
	for _, f := range files {
		if !isGoSumPath(f.path) {
			continue
		}
		for _, l := range f.additions {
			if line, ok := parseGoSumLine(l); ok {
				out = append(out, line)
			}
		}
	}
	return out
}

// parsedGoSumLine is a structured representation of a single
// go.sum entry. The raw line has the shape:
//
//	<module> <version>[/go.mod] h1:<base64>
type parsedGoSumLine struct {
	module       string
	version      string // semver; never the "/go.mod" suffix variant
	hash         string // h1:... full hash literal
	raw          string
	isModSection bool // true if the line was the `<v>/go.mod` form
}

func parseGoSumLine(line string) (parsedGoSumLine, bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "h1:") {
		return parsedGoSumLine{}, false
	}
	out := parsedGoSumLine{
		module: fields[0],
		hash:   fields[2],
		raw:    line,
	}
	switch {
	case strings.HasSuffix(fields[1], "/go.mod"):
		out.version = strings.TrimSuffix(fields[1], "/go.mod")
		out.isModSection = true
	default:
		out.version = fields[1]
	}
	return out, true
}

// linesAreInExpectedSet enforces gate 3: every added go.sum line
// must reference one of the publishedModules at the lastReleasedVersion.
// Anything else — an unrelated module, an unexpected version, OR an
// empty added set (signalling a silently-dropped malformed line; see
// test-analyst review) — aborts the release.
//
// This is a STRICTER interpretation than the "go mod graph
// transitive set" originally proposed in the issue: in the v0.2.2 →
// v0.2.3 case the drift is exclusively axonops/audit submodules at
// the previously-published version. If a future release legitimately
// needs transitive-dep checksums added, this gate will catch and
// abort, forcing human review.
func linesAreInExpectedSet(added []parsedGoSumLine, publishedModules []string, version string) bool {
	// Silent-bypass guard: a non-empty diff that parses to zero
	// recognised go.sum lines means every line was malformed and
	// silently dropped by parseGoSumLine. The caller's gate
	// orchestration relies on this returning false so the run
	// aborts with msgUnrelatedChecksums rather than passing every
	// safety gate trivially.
	if len(added) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(publishedModules))
	for _, m := range publishedModules {
		allowed[m] = struct{}{}
	}
	for _, line := range added {
		if line.version != version {
			return false
		}
		if _, ok := allowed[line.module]; !ok {
			return false
		}
	}
	return true
}

// crossCheckAgainstSumdb enforces gate 4: every unique
// (module, version) pair in the added lines is independently
// fetched from sum.golang.org's transparency log and the h1: hashes
// are byte-compared. A mismatch aborts with msgSumdbDisagrees; a
// network/HTTP failure aborts with msgSumdbTransient. There are no
// retries — the operator re-dispatches when the network is healthy.
//
// Exit codes (per godoc + docs/releasing.md): a disagreement is a
// validation failure (exit 3); a transient transport failure is
// operational (exit 1). The original implementation conflated them
// on exit 1 — fixed in #967 review M1.
//
// Cross-file hash divergence (review M3): if two added go.sum lines
// for the same (module, version) carry DIFFERENT h1: values
// (legitimately impossible from `make tidy`, but a clear tampering
// signal), reject immediately. Without this, only the last-written
// hash would be checked against sumdb and the other would pass.
//
//nolint:gocognit,gocyclo,cyclop // see godoc above
func crossCheckAgainstSumdb(ctx context.Context, added []parsedGoSumLine, in *preflightTidyArgs, stdout, stderr io.Writer) int {
	// Deduplicate (module, version) — both the module-zip and
	// go.mod hash lines for the same release share the same lookup.
	// Detect intra-diff hash divergence: two added lines for the
	// same (module, version, section) MUST carry the same hash.
	type modVer struct{ module, version string }
	expected := make(map[modVer]map[string]string) // modVer → {"zip": h1:..., "mod": h1:...}
	for _, l := range added {
		key := modVer{module: l.module, version: l.version}
		if expected[key] == nil {
			expected[key] = map[string]string{}
		}
		section := "zip"
		if l.isModSection {
			section = "mod"
		}
		if existing, ok := expected[key][section]; ok && existing != l.hash {
			_, _ = fmt.Fprintf(stderr,
				"preflight-tidy-check: cross-file %s hash divergence for %s@%s: %s vs %s\n",
				section, key.module, key.version, existing, l.hash)
			emit(stdout, stderr, msgSumdbDisagrees)
			return exitValidation
		}
		expected[key][section] = l.hash
	}

	client := &sumdb.Client{
		Endpoint: in.sumdbEndpoint,
		Timeout:  in.sumdbTimeout,
	}
	for key, ourHashes := range expected {
		lookup, err := client.Lookup(ctx, key.module, key.version)
		if err != nil {
			// Differentiate transparency-log "not found" (likely
			// a transient proxy/log skew or genuinely-not-published
			// version) from other transport failures.
			switch {
			case errors.Is(err, sumdb.ErrNotFound):
				_, _ = fmt.Fprintf(stderr,
					"preflight-tidy-check: sumdb has no record for %s@%s: %v\n",
					key.module, key.version, err)
			default:
				_, _ = fmt.Fprintf(stderr, "preflight-tidy-check: sumdb lookup %s@%s failed: %v\n",
					key.module, key.version, err)
			}
			emit(stdout, stderr, msgSumdbTransient)
			return exitOperational
		}
		if hash, ok := ourHashes["zip"]; ok && hash != lookup.Hash {
			_, _ = fmt.Fprintf(stderr,
				"preflight-tidy-check: zip hash for %s@%s differs from sumdb: tidy=%s sumdb=%s\n",
				key.module, key.version, hash, lookup.Hash)
			emit(stdout, stderr, msgSumdbDisagrees)
			return exitValidation
		}
		if hash, ok := ourHashes["mod"]; ok && hash != lookup.ModHash {
			_, _ = fmt.Fprintf(stderr,
				"preflight-tidy-check: go.mod hash for %s@%s differs from sumdb: tidy=%s sumdb=%s\n",
				key.module, key.version, hash, lookup.ModHash)
			emit(stdout, stderr, msgSumdbDisagrees)
			return exitValidation
		}
	}
	return exitSuccess
}

// emitValidatedSummary writes one line per unique (module, version)
// pair that passed every gate, in deterministic sorted order, so
// the release workflow can render them in $GITHUB_STEP_SUMMARY.
func emitValidatedSummary(stdout io.Writer, added []parsedGoSumLine) {
	uniq := make(map[string]struct{})
	for _, l := range added {
		uniq[l.module+" "+l.version] = struct{}{}
	}
	keys := make([]string, 0, len(uniq))
	for k := range uniq {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintln(stdout, k)
	}
}

// splitPublishedModules parses --published-modules and returns a
// trimmed list of module paths. Empty or whitespace-only entries
// are dropped.
func splitPublishedModules(csv string) []string {
	parts := strings.Split(csv, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// isGoModPath reports whether path is a go.mod file (root or any
// sub-module). The strict basename check is intentional — a path
// like `cmd/audit-gen/go.mod.backup` should NOT trip gate 1.
func isGoModPath(path string) bool {
	return path == "go.mod" || strings.HasSuffix(path, "/go.mod")
}

// isGoSumPath reports whether path is a go.sum file.
func isGoSumPath(path string) bool {
	return path == "go.sum" || strings.HasSuffix(path, "/go.sum")
}

// writePreflightTidyCheckHelp emits the subcommand help text.
func writePreflightTidyCheckHelp(w io.Writer) {
	const helpText = `release-tool preflight-tidy-check — validate post-tidy go.sum diff

USAGE
    release-tool [persistent flags] preflight-tidy-check \
        --last-released-version vX.Y.Z \
        --published-modules github.com/axonops/audit,github.com/axonops/audit/file,... \
        [--workdir PATH] [--max-diff-bytes N] [--sumdb-endpoint URL]
        [--sumdb-timeout DURATION] [--skip-sumdb-cross-check]

DESCRIPTION
    Inspects the working tree's uncommitted diff (presumed to be
    the output of a fresh ` + "`make tidy`" + `) and applies six safety
    gates before the orchestrating release workflow auto-commits it
    via the commit-pinned-deps subcommand. The gates are
    NON-NEGOTIABLE; each failure aborts with one of the exact
    operator-facing error strings declared in #967 AC #4.

GATES
    Gate 1 — go.sum only (no go.mod changes)
    Gate 2 — additions only (no deletions)
    Gate 3 — every added line references one of the published
             modules at the last-released version
    Gate 4 — every (module, version) is independently fetched from
             sum.golang.org and the h1: hashes byte-match
    Defence — diff size capped at 8 KiB; larger aborts.

EXIT CODES
    0 — every gate passed; stdout lists validated (module, version)
    1 — operational failure (sumdb network, etc.)
    2 — usage error
    3 — validation failure (a safety gate aborted)
    4 — clean working tree (idempotent no-op)
`
	_, _ = fmt.Fprint(w, helpText)
}
