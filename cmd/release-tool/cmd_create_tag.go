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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"unicode/utf8"

	"github.com/axonops/audit/cmd/release-tool/internal/ghclient"
	"github.com/axonops/audit/cmd/release-tool/internal/sha"
)

// createTagArgs are the parsed flags for the create-tag subcommand.
// Sharing this type between the production handler and the test hook
// keeps the contract a single source of truth.
type createTagArgs struct {
	owner   string
	repo    string
	tag     string
	commit  string
	message string
	dryRun  bool
}

// runCreateTag implements the `create-tag` subcommand.
//
// Idempotent semantics (regression for #911 / gh-graphql-tag.sh
// BLOCKER-3):
//   - tag absent → create, exit 0
//   - tag exists at same SHA → exit 4 (idempotent no-op)
//   - tag exists at different SHA → exit 1 (history contamination)
func runCreateTag(ctx context.Context, args []string, stdout, stderr io.Writer, persistent *rootFlags) int {
	fs := flag.NewFlagSet("create-tag", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { writeCreateTagHelp(fs.Output()) }

	in := createTagArgs{}
	fs.StringVar(&in.owner, "owner", "", "GitHub repository owner (required)")
	fs.StringVar(&in.repo, "repo", "", "GitHub repository name (required)")
	fs.StringVar(&in.tag, "tag", "", "Tag name, e.g. v0.2.2 (required)")
	fs.StringVar(&in.commit, "sha", "", "Commit SHA to point the tag at; must be 40 hex chars (required)")
	fs.StringVar(&in.message, "message", "", "Tag annotation message (required)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	in.dryRun = persistent.dryRun

	if code := validateCreateTagArgs(&in, stderr); code != exitSuccess {
		return code
	}

	client, code := buildClient(persistent, stderr)
	if code != exitSuccess {
		return code
	}
	return doCreateTag(ctx, client, &in, stdout, stderr)
}

// validateCreateTagArgs enforces the required-flag and SHA-shape
// invariants. Exposed so the test hook can share the same gate.
func validateCreateTagArgs(in *createTagArgs, stderr io.Writer) int {
	if err := requireFlags(in.owner, in.repo, in.tag, in.commit, in.message); err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: %v\n", err)
		return exitUsage
	}
	if err := validateIdent("--owner", in.owner); err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: %v\n", err)
		return exitValidation
	}
	if err := validateIdent("--repo", in.repo); err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: %v\n", err)
		return exitValidation
	}
	if err := validateIdent("--tag", in.tag); err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: %v\n", err)
		return exitValidation
	}
	if err := validateMessage("--message", in.message); err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: %v\n", err)
		return exitValidation
	}
	if !sha.IsValid(in.commit) {
		_, _ = fmt.Fprintf(stderr, "create-tag: --sha must be 40 lowercase hex chars, got %q\n",
			truncateForDiag(in.commit, 80))
		return exitValidation
	}
	return exitSuccess
}

// truncateForDiag clips an operator-pasted value to at most n bytes
// for inclusion in a diagnostic message. Multi-kilobyte 404 JSON
// pasted into --sha is the realistic case (#911 again, in reverse).
//
// Truncation is rune-safe: if the n-th byte falls in the middle of
// a multi-byte UTF-8 sequence, the returned string trims back to
// the nearest preceding rune boundary so stderr never emits invalid
// UTF-8 (test-analyst N2).
func truncateForDiag(s string, n int) string {
	if len(s) <= n {
		return s
	}
	end := n
	// Walk back to the start of the rune that the byte index n
	// fell inside, if any. utf8.RuneStart reports whether byte b
	// is a leading byte; we trim continuation bytes from the cut
	// point.
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "…"
}

// doCreateTag executes the create-tag dance against the supplied
// client. Split out from runCreateTag so the test hook can inject a
// client pointed at httptest.
func doCreateTag(ctx context.Context, client *ghclient.Client, in *createTagArgs, stdout, stderr io.Writer) int {
	// Idempotency check: does the tag already exist?
	existingRef, err := client.GetRef(ctx, in.owner, in.repo, "tags/"+in.tag)
	switch {
	case err == nil:
		return handleExistingTag(ctx, client, existingRef, in, stderr)
	case isNotFound(err):
		// Fall through to create.
	default:
		_, _ = fmt.Fprintf(stderr, "create-tag: lookup existing tag: %v\n", err)
		return exitOperational
	}

	// Dry-run short-circuit — only after we've established the tag
	// doesn't already exist, so a re-run on a contaminated tag still
	// exits with the contamination diagnostic in dry-run mode.
	if in.dryRun {
		return writeDryRunCreateTag(stdout, in.owner, in.repo, in.tag, in.commit, in.message)
	}

	tagObj, err := client.CreateTag(ctx, in.owner, in.repo, &ghclient.CreateTagInput{
		Tag:     in.tag,
		Message: in.message,
		Object:  in.commit,
		Type:    "commit",
		Tagger: ghclient.TagAuthor{
			Name:  "axonops-audit-release-bot[bot]",
			Email: "axonops-audit-release-bot[bot]@users.noreply.github.com",
			Date:  time.Now().UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: create tag object: %v\n", err)
		return exitOperational
	}

	if _, err := client.CreateRef(ctx, in.owner, in.repo, &ghclient.CreateRefInput{
		Ref: "refs/tags/" + in.tag,
		SHA: tagObj.SHA,
	}); err != nil {
		// Partial-success recovery (test-analyst I2): the tag
		// OBJECT was committed but the REF could not be created.
		// Surface the orphan object SHA explicitly so the
		// operator can finish the release manually.
		_, _ = fmt.Fprintf(stderr,
			"create-tag: tag object %s created but ref refs/tags/%s could not be published: %v\n",
			tagObj.SHA, in.tag, err)
		_, _ = fmt.Fprintf(stderr,
			"create-tag: recover manually with: gh api -X POST /repos/%s/%s/git/refs --field ref=refs/tags/%s --field sha=%s\n",
			in.owner, in.repo, in.tag, tagObj.SHA)
		return exitOperational
	}

	_, _ = fmt.Fprintln(stdout, tagObj.SHA)
	return exitSuccess
}

// handleExistingTag handles the case where the tag already exists.
// Returns exit 4 if the tag points at the same commit (idempotent
// no-op), exit 1 with a contamination diagnostic otherwise.
//
// For lightweight tags, existing.Object.Type == "commit" and
// existing.Object.SHA is the commit SHA — compare directly.
//
// For annotated tags, existing.Object.Type == "tag" and
// existing.Object.SHA is the tag-object SHA, not the commit SHA.
// Comparing the flag's commit SHA against the tag-object SHA would
// be a false-contamination diagnostic on every re-run. We MUST
// dereference via GET /git/tags/<tag_object_sha> first.
func handleExistingTag(ctx context.Context, client *ghclient.Client, existing *ghclient.Ref, in *createTagArgs, stderr io.Writer) int {
	existingCommit, err := resolveExistingCommit(ctx, client, in.owner, in.repo, existing)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "create-tag: dereference tag object: %v\n", err)
		return exitOperational
	}
	if existingCommit == in.commit {
		_, _ = fmt.Fprintf(stderr, "create-tag: %s already exists at %s — no-op\n", in.tag, in.commit)
		return exitIdempotentNoOp
	}
	_, _ = fmt.Fprintf(stderr,
		"create-tag: %s exists at %s but wanted %s — refusing to overwrite\n",
		in.tag, existingCommit, in.commit)
	return exitOperational
}

// resolveExistingCommit returns the commit SHA the existing tag
// points at, dereferencing through the tag object when the ref is an
// annotated tag.
func resolveExistingCommit(ctx context.Context, client *ghclient.Client, owner, repo string, existing *ghclient.Ref) (string, error) {
	switch existing.Object.Type {
	case "commit":
		return existing.Object.SHA, nil
	case "tag":
		tag, err := client.GetTag(ctx, owner, repo, existing.Object.SHA)
		if err != nil {
			return "", fmt.Errorf("dereference tag object %s: %w", existing.Object.SHA, err)
		}
		return tag.Object.SHA, nil
	default:
		return "", fmt.Errorf("unknown ref object type %q", existing.Object.Type)
	}
}

// writeDryRunCreateTag prints what create-tag WOULD send to the
// GitHub API.
func writeDryRunCreateTag(stdout io.Writer, owner, repo, tag, commit, message string) int {
	payload := map[string]any{
		"tag_object": map[string]any{
			"endpoint": fmt.Sprintf("POST /repos/%s/%s/git/tags", owner, repo),
			"body": map[string]any{
				"tag":     tag,
				"message": message,
				"object":  commit,
				"type":    "commit",
				"tagger": map[string]any{
					"name":  "axonops-audit-release-bot[bot]",
					"email": "axonops-audit-release-bot[bot]@users.noreply.github.com",
					"date":  "<NOW>",
				},
			},
		},
		"ref": map[string]any{
			"endpoint": fmt.Sprintf("POST /repos/%s/%s/git/refs", owner, repo),
			"body": map[string]any{
				"ref": "refs/tags/" + tag,
				"sha": "<tag_object.sha>",
			},
		},
	}
	if err := json.NewEncoder(stdout).Encode(payload); err != nil {
		return exitOperational
	}
	return exitSuccess
}

// buildClient constructs a ghclient.Client using the persistent
// flags. Returns the appropriate exit code on failure.
//
// Environment:
//   - GH_TOKEN (required): App Installation Token. Never logged.
//   - GH_API_URL (optional): override the GitHub API base URL.
//     Used by BDD scenarios that drive the binary against an
//     httptest server. NOT for production use — pointing this at
//     anything other than api.github.com routes App-signed
//     mutations through an untrusted endpoint.
func buildClient(persistent *rootFlags, stderr io.Writer) (client *ghclient.Client, exit int) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		_, _ = fmt.Fprintln(stderr, "release-tool: GH_TOKEN environment variable is required")
		return nil, exitOperational
	}
	opts := []ghclient.Option{
		ghclient.WithHTTPClient(&http.Client{Timeout: persistent.timeout}),
	}
	if base := os.Getenv("GH_API_URL"); base != "" {
		opts = append(opts, ghclient.WithBaseURL(base))
	}
	c, err := ghclient.New(token, opts...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "release-tool: ghclient init: %v\n", err)
		return nil, exitOperational
	}
	return c, exitSuccess
}

// requireFlags reports a usage error if any required flag is empty.
func requireFlags(owner, repo, tag, commit, message string) error {
	missing := []string{}
	if owner == "" {
		missing = append(missing, "--owner")
	}
	if repo == "" {
		missing = append(missing, "--repo")
	}
	if tag == "" {
		missing = append(missing, "--tag")
	}
	if commit == "" {
		missing = append(missing, "--sha")
	}
	if message == "" {
		missing = append(missing, "--message")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %v", missing)
	}
	return nil
}

// isNotFound reports whether err is a 404 HTTPError.
func isNotFound(err error) bool {
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		return false
	}
	return herr.StatusCode == http.StatusNotFound
}

func writeCreateTagHelp(w io.Writer) {
	_, _ = fmt.Fprint(w, `release-tool create-tag — create an annotated tag at a commit SHA

USAGE
    release-tool create-tag --owner OWNER --repo REPO --tag TAG \
                            --sha SHA --message TEXT

FLAGS
    --owner    OWNER    GitHub repository owner (required)
    --repo     REPO     GitHub repository name (required)
    --tag      TAG      Tag name, e.g. v0.2.2 (required)
    --sha      SHA      Commit SHA to point the tag at; 40 hex chars
    --message  TEXT     Tag annotation message (required)

PERSISTENT FLAGS (inherited)
    --dry-run        Print proposed payloads to stdout and exit 0
                     without performing any state mutation
    --timeout        Per-request timeout for GitHub API calls

EXIT CODES
    0 — success
    1 — API error / tag exists at a different SHA (contamination)
    3 — validation error (invalid SHA)
    4 — idempotent no-op (tag already exists at the same SHA)

EXAMPLES
    release-tool create-tag --owner axonops --repo audit \
        --tag v0.2.2 --sha abc...def --message "Release v0.2.2"
`)
}
