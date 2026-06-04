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
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/axonops/audit/cmd/release-tool/internal/allowlist"
	"github.com/axonops/audit/cmd/release-tool/internal/ghclient"
	"github.com/axonops/audit/cmd/release-tool/internal/gitstatus"
)

// commitPinnedDepsArgs are the parsed flags for the
// commit-pinned-deps subcommand. Shared between runCommitPinnedDeps
// and the test hook.
type commitPinnedDepsArgs struct {
	owner            string
	repo             string
	branch           string
	message          string
	workdir          string
	autoCreateBranch bool
	dryRun           bool
}

// runCommitPinnedDeps implements the `commit-pinned-deps` subcommand.
//
// It runs `git status -z` against the workdir, parses the result with
// internal/gitstatus (regression for #907 — bash $() NUL-stripping),
// filters paths through internal/allowlist (regression for #906/#910
// — symlink + non-manifest path exfiltration), reads every staged
// go.mod / go.sum file's bytes from disk, then submits them as a
// single GraphQL createCommitOnBranch mutation (regression for
// #915/#916 — variables must be a structured object).
func runCommitPinnedDeps(ctx context.Context, args []string, stdout, stderr io.Writer, persistent *rootFlags) int {
	fs := flag.NewFlagSet("commit-pinned-deps", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { writeCommitPinnedDepsHelp(fs.Output()) }

	in := commitPinnedDepsArgs{}
	fs.StringVar(&in.owner, "owner", "", "GitHub repository owner (required)")
	fs.StringVar(&in.repo, "repo", "", "GitHub repository name (required)")
	fs.StringVar(&in.branch, "branch", "", "Target branch for the commit, e.g. release/v0.2.2 (required)")
	fs.StringVar(&in.message, "message", "", "Commit message headline (required)")
	fs.BoolVar(&in.autoCreateBranch, "auto-create-branch", false,
		"Create the branch from main if it does not already exist")
	// --workdir is a TRUSTED path — the release workflow is
	// expected to hardcode this to the CI-managed checkout
	// directory. release-tool does not validate that the path is
	// inside the repo; an operator pointing it at an attacker-
	// controlled tree gets exactly the go.mod/go.sum from that
	// tree. The git -C workdir invocation will refuse non-git
	// directories, blunting accidental misuse, but the contract is
	// the caller's responsibility (security review W3).
	fs.StringVar(&in.workdir, "workdir", ".", "Path to the git working directory (must be a trusted release-flow checkout)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	in.dryRun = persistent.dryRun

	if err := requireCommitFlags(in.owner, in.repo, in.branch, in.message); err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %v\n", err)
		return exitUsage
	}
	if code := validateCommitPinnedDepsArgs(&in, stderr); code != exitSuccess {
		return code
	}

	client, code := buildClient(persistent, stderr)
	if code != exitSuccess {
		return code
	}
	return doCommitPinnedDeps(ctx, client, &in, stdout, stderr)
}

// doCommitPinnedDeps performs the staged-file collection and the
// GraphQL mutation. Split out so tests can inject a client pointed
// at httptest.
func doCommitPinnedDeps(ctx context.Context, client *ghclient.Client, in *commitPinnedDepsArgs, stdout, stderr io.Writer) int {
	additions, code := collectAllowedAdditions(in.workdir, stderr)
	if code != exitSuccess {
		return code
	}
	if len(additions) == 0 {
		_, _ = fmt.Fprintln(stderr, "commit-pinned-deps: no staged changes — idempotent no-op")
		return exitIdempotentNoOp
	}

	branchHead, code := resolveOrCreateBranch(ctx, client, in.owner, in.repo, in.branch, in.autoCreateBranch, stderr)
	if code != exitSuccess {
		return code
	}

	if in.dryRun {
		return writeDryRunCommit(stdout, in.owner, in.repo, in.branch, in.message, branchHead, additions)
	}

	commit, err := client.CreateCommitOnBranch(ctx, &ghclient.CreateCommitOnBranchInput{
		RepositoryNameWithOwner: in.owner + "/" + in.repo,
		BranchName:              in.branch,
		ExpectedHeadOID:         branchHead,
		Message:                 in.message,
		Additions:               additions,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: create commit: %v\n", err)
		return exitOperational
	}

	_, _ = fmt.Fprintln(stdout, commit.OID)
	return exitSuccess
}

// collectAllowedAdditions runs `git status -z` in workdir, parses it,
// filters through the allowlist, rejects symlinks, and reads each
// surviving path's content into a CommitFileAddition.
//
// Returns an exit code on failure; (additions, exitSuccess) on success.
func collectAllowedAdditions(workdir string, stderr io.Writer) (out []ghclient.CommitFileAddition, exit int) {
	entries, code := runGitStatusZ(workdir, stderr)
	if code != exitSuccess {
		return nil, code
	}

	additions := make([]ghclient.CommitFileAddition, 0, len(entries))
	for _, e := range entries {
		path := e.Path

		if !allowlist.IsAllowed(path) {
			_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: path %q rejected by allowlist\n", path)
			return nil, exitValidation
		}

		body, err := readAllowedFile(workdir, path)
		if err != nil {
			code := exitOperational
			if errors.Is(err, errSymlinkRefused) {
				code = exitValidation
			}
			_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %s: %v\n", path, err)
			return nil, code
		}
		additions = append(additions, ghclient.CommitFileAddition{
			Path:     path,
			Contents: body,
		})
	}

	// Deterministic order: GraphQL signs whatever we send, but
	// deterministic ordering simplifies reproducing release commits
	// by hand for incident response.
	sort.Slice(additions, func(i, j int) bool {
		return additions[i].Path < additions[j].Path
	})
	return additions, exitSuccess
}

// validateCommitPinnedDepsArgs enforces the identifier and message
// invariants. Shared between runCommitPinnedDeps and the test hook
// so both paths refuse the same set of values.
func validateCommitPinnedDepsArgs(in *commitPinnedDepsArgs, stderr io.Writer) int {
	if err := validateIdent("--owner", in.owner); err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %v\n", err)
		return exitValidation
	}
	if err := validateIdent("--repo", in.repo); err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %v\n", err)
		return exitValidation
	}
	if err := validateIdent("--branch", in.branch); err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %v\n", err)
		return exitValidation
	}
	if err := validateMessage("--message", in.message); err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: %v\n", err)
		return exitValidation
	}
	return exitSuccess
}

// errSymlinkRefused is the sentinel returned by readAllowedFile
// when the open(2) call refuses a symlink via O_NOFOLLOW. Callers
// translate this into exitValidation (#910).
var errSymlinkRefused = errors.New("path is a symlink — refusing")

// readAllowedFile opens an already-allowlisted path with O_NOFOLLOW
// and reads its full contents. This collapses the lstat + open dance
// into a single syscall, closing the TOCTOU window where an
// attacker could swap the regular file for a symlink between the
// lstat and the read (#910 threat-model B2).
//
// The error returns errSymlinkRefused when the operating system
// refuses to traverse the final path component because it is a
// symlink. Linux and Darwin both surface this as syscall.ELOOP;
// the predicate isSymlinkOpenError checks for it explicitly.
// Defence in depth: even if a future BSD kernel returned a
// different errno, the path drops through to "open: %w" and the
// caller exits operational — no commit is sent.
func readAllowedFile(workdir, path string) ([]byte, error) {
	full := filepath.Join(workdir, path)
	// O_NOFOLLOW on the final component is the kernel-level
	// guarantee. O_RDONLY because we never mutate; mode 0 because
	// we never create.
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // path is allowlist-screened above
	if err != nil {
		if isSymlinkOpenError(err) {
			return nil, errSymlinkRefused
		}
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Defence in depth: stat the open fd and refuse anything that
	// is not a regular file (sockets, FIFOs, devices). O_NOFOLLOW
	// already refuses symlinks; this catches everything else the
	// allowlist might inadvertently let through if the path
	// happens to be a special file.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file (mode=%v)", info.Mode())
	}

	body, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return body, nil
}

// isSymlinkOpenError reports whether err looks like an
// O_NOFOLLOW-rejected symlink (ELOOP on Linux/macOS).
func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

// runGitStatusZ shells out to `git status -z --porcelain
// --untracked-files=no` in workdir and parses the result.
func runGitStatusZ(workdir string, stderr io.Writer) (entries []gitstatus.Entry, exit int) {
	cmd := exec.Command("git", "-C", workdir, "status", "-z",
		"--porcelain", "--untracked-files=no")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		gitMsg := strings.TrimRight(errBuf.String(), "\n")
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: git status failed: %v\n%s\n",
			err, gitMsg)
		return nil, exitOperational
	}
	var err error
	entries, err = gitstatus.Parse(&out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: parse git status: %v\n", err)
		return nil, exitOperational
	}
	return entries, exitSuccess
}

// resolveOrCreateBranch returns the OID of the branch HEAD. If the
// branch does not exist and autoCreate is true, it is created from
// the OID of `main`. Otherwise the missing branch is an operational
// failure.
func resolveOrCreateBranch(ctx context.Context, c *ghclient.Client, owner, repo, branch string, autoCreate bool, stderr io.Writer) (head string, exit int) {
	ref, err := c.GetRef(ctx, owner, repo, "heads/"+branch)
	switch {
	case err == nil:
		return ref.Object.SHA, exitSuccess
	case !isNotFound(err):
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: lookup branch %q: %v\n", branch, err)
		return "", exitOperational
	}

	if !autoCreate {
		_, _ = fmt.Fprintf(stderr,
			"commit-pinned-deps: branch %q does not exist (pass --auto-create-branch to create from main)\n",
			branch)
		return "", exitOperational
	}

	mainRef, err := c.GetRef(ctx, owner, repo, "heads/main")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: resolve main: %v\n", err)
		return "", exitOperational
	}
	created, err := c.CreateRef(ctx, owner, repo, &ghclient.CreateRefInput{
		Ref: "refs/heads/" + branch,
		SHA: mainRef.Object.SHA,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "commit-pinned-deps: create branch %q: %v\n", branch, err)
		return "", exitOperational
	}
	return created.Object.SHA, exitSuccess
}

// writeDryRunCommit prints the proposed GraphQL payload (without the
// raw file contents — those would be enormous) to stdout.
func writeDryRunCommit(stdout io.Writer, owner, repo, branch, message, head string, additions []ghclient.CommitFileAddition) int {
	type fileSummary struct {
		Path string `json:"path"`
		Size int    `json:"contents_bytes"`
	}
	files := make([]fileSummary, 0, len(additions))
	for _, a := range additions {
		files = append(files, fileSummary{Path: a.Path, Size: len(a.Contents)})
	}
	payload := map[string]any{
		"mutation": "createCommitOnBranch",
		"variables": map[string]any{
			"input": map[string]any{
				"branch": map[string]string{
					"repositoryNameWithOwner": owner + "/" + repo,
					"branchName":              branch,
				},
				"expectedHeadOid": head,
				"message":         map[string]string{"headline": message},
				"fileChanges": map[string]any{
					"additions_summary": files,
				},
			},
		},
	}
	if err := json.NewEncoder(stdout).Encode(payload); err != nil {
		return exitOperational
	}
	return exitSuccess
}

// requireCommitFlags returns a usage error listing missing flags.
func requireCommitFlags(owner, repo, branch, message string) error {
	missing := []string{}
	if owner == "" {
		missing = append(missing, "--owner")
	}
	if repo == "" {
		missing = append(missing, "--repo")
	}
	if branch == "" {
		missing = append(missing, "--branch")
	}
	if message == "" {
		missing = append(missing, "--message")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func writeCommitPinnedDepsHelp(w io.Writer) {
	_, _ = fmt.Fprint(w, `release-tool commit-pinned-deps — open an App-signed commit
on a branch using the GitHub GraphQL createCommitOnBranch mutation.

USAGE
    release-tool commit-pinned-deps \
        --owner OWNER --repo REPO --branch BRANCH \
        --message TEXT [--auto-create-branch] [--workdir DIR]

FLAGS
    --owner                OWNER       GitHub repository owner (required)
    --repo                 REPO        GitHub repository name (required)
    --branch               BRANCH      Target branch (required)
    --message              TEXT        Commit message headline (required)
    --auto-create-branch               Create the branch from main if missing
    --workdir              DIR         Path to the git working directory
                                       (default: ".")

PERSISTENT FLAGS (inherited)
    --dry-run        Print proposed payload (path + size only) to stdout
                     and exit 0 without performing any state mutation
    --timeout        Per-request timeout for GitHub API calls

EXIT CODES
    0 — success (commit SHA written to stdout)
    1 — operational failure (git status failed, API error, network)
    3 — validation error (path failed allowlist, or path is a symlink)
    4 — idempotent no-op (no staged changes)

REGRESSIONS LOCKED
    #906 / #910  symlinked or off-allowlist paths refused
    #907         NUL-delimited git-status parsed via io.Reader, never $()
    #911         only 40-hex commit SHAs reach the API (gh-CLI 404 JSON
                 was previously accepted as a SHA)
    #915 / #916  GraphQL variables sent as a structured object, never a
                 JSON-string-of-an-object
`)
}
