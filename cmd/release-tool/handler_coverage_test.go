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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newAutoCreateBranchServer drives the create-branch flow: GET ref/
// heads/release/v0.2.2 returns 404, GET ref/heads/main returns
// mainSHA, POST git/refs creates the new branch, GraphQL returns
// commitOID.
func newAutoCreateBranchServer(t *testing.T, mainSHA, commitOID string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/release/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/axonops/audit/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/main","object":{"sha":"` + mainSHA + `","type":"commit"}}`))
	})
	mux.HandleFunc("/repos/axonops/audit/git/refs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ref":"refs/heads/release/v0.2.2","object":{"sha":"` + mainSHA + `","type":"commit"}}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"createCommitOnBranch":{"commit":{"oid":"` + commitOID + `","url":""}}}}`))
	})
	return httptest.NewServer(mux)
}

// TestRun_CreateTag_NoToken_ExitsOperational covers the production
// runCreateTag path: when GH_TOKEN is missing, buildClient must
// surface a useful error before any HTTP call is attempted.
func TestRun_CreateTag_NoToken_ExitsOperational(t *testing.T) {
	t.Setenv("GH_TOKEN", "")

	rf := rootFlags{timeout: time.Second}
	var stdout, stderr bytes.Buffer
	code := runCreateTag(context.Background(),
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA, "--message", "Release"},
		&stdout, &stderr, &rf)
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "GH_TOKEN") {
		t.Errorf("stderr must explain the missing token: %q", stderr.String())
	}
}

// TestRun_CommitPinnedDeps_NoToken_ExitsOperational mirrors the
// create-tag GH_TOKEN-missing check.
func TestRun_CommitPinnedDeps_NoToken_ExitsOperational(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\ngo 1.26\n"))

	rf := rootFlags{timeout: time.Second}
	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDeps(context.Background(),
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin",
			"--workdir", repo},
		&stdout, &stderr, &rf)
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
}

// TestRun_CommitPinnedDeps_HelpFlag covers the help output and
// confirms flag.ContinueOnError funnels --help through to a usage exit.
func TestRun_CommitPinnedDeps_HelpFlag(t *testing.T) {
	t.Parallel()
	rf := rootFlags{timeout: time.Second}
	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDeps(context.Background(),
		[]string{"--help"}, &stdout, &stderr, &rf)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d", exitUsage, code)
	}
}

// TestRun_CreateTag_HelpFlag mirrors the commit-pinned-deps help check.
func TestRun_CreateTag_HelpFlag(t *testing.T) {
	t.Parallel()
	rf := rootFlags{timeout: time.Second}
	var stdout, stderr bytes.Buffer
	code := runCreateTag(context.Background(),
		[]string{"--help"}, &stdout, &stderr, &rf)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d", exitUsage, code)
	}
}

// TestRun_CommitPinnedDeps_MissingFlags_ExitsUsage covers the
// usage-error path for the production handler.
func TestRun_CommitPinnedDeps_MissingFlags_ExitsUsage(t *testing.T) {
	t.Parallel()
	rf := rootFlags{timeout: time.Second}
	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDeps(context.Background(),
		[]string{"--owner", "axonops"}, &stdout, &stderr, &rf)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d (stderr=%q)", exitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing required flag") {
		t.Errorf("stderr must list the missing flags: %q", stderr.String())
	}
}

// TestRun_CommitPinnedDeps_DryRun_PrintsPayload covers the dry-run
// branch end-to-end: real staged files, fake server, --dry-run, no
// mutation should be sent to the GraphQL endpoint.
func TestRun_CommitPinnedDeps_DryRun_PrintsPayload(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

	var captured atomic.Pointer[capturedMutation]
	srv := newCommitServer(t, commitFixture{
		branchHeadSHA: branchHeadSHA,
		commitOID:     "should-not-be-returned",
		captureBody:   &captured,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, true, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin deps"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if captured.Load() != nil {
		t.Error("dry-run must NOT send the createCommitOnBranch mutation")
	}
	assertCommitPinnedDepsDryRunPayload(t, stdout.Bytes())
}

// assertCommitPinnedDepsDryRunPayload drills into the nested
// dry-run payload (test-analyst I7). Extracted so the parent test
// stays under the cyclomatic-complexity gate.
func assertCommitPinnedDepsDryRunPayload(t *testing.T, raw []byte) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("dry-run stdout must be valid JSON: %v\n%s", err, string(raw))
	}
	if payload["mutation"] != "createCommitOnBranch" {
		t.Errorf("dry-run payload must name the mutation: %v", payload["mutation"])
	}
	input := dryRunMutationInput(t, payload)
	if input["expectedHeadOid"] != branchHeadSHA {
		t.Errorf("dry-run expectedHeadOid: want %q, got %v", branchHeadSHA, input["expectedHeadOid"])
	}
	assertDryRunBranch(t, input)
	assertDryRunAdditions(t, input)
}

// dryRunMutationInput drills through variables.input and returns
// the inner object.
func dryRunMutationInput(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	vars, ok := payload["variables"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload missing variables: %T", payload["variables"])
	}
	input, ok := vars["input"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload missing variables.input: %T", vars["input"])
	}
	return input
}

func assertDryRunBranch(t *testing.T, input map[string]any) {
	t.Helper()
	branch, ok := input["branch"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload missing variables.input.branch")
	}
	for k, want := range map[string]any{
		"repositoryNameWithOwner": "axonops/audit",
		"branchName":              "release/v0.2.2",
	} {
		if branch[k] != want {
			t.Errorf("dry-run branch.%s: want %q, got %v", k, want, branch[k])
		}
	}
}

func assertDryRunAdditions(t *testing.T, input map[string]any) {
	t.Helper()
	fc, ok := input["fileChanges"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload missing variables.input.fileChanges")
	}
	additions, ok := fc["additions_summary"].([]any)
	if !ok {
		t.Fatalf("dry-run payload missing additions_summary list, got %T", fc["additions_summary"])
	}
	if len(additions) != 1 {
		t.Errorf("dry-run additions_summary: want 1 entry, got %d", len(additions))
	}
}

// TestRun_CommitPinnedDeps_BranchAutoCreate covers the branch-
// missing-with-auto-create path: GetRef returns 404, the tool falls
// back to main's SHA, and CreateRef establishes the branch.
func TestRun_CommitPinnedDeps_BranchAutoCreate(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

	srv := newAutoCreateBranchServer(t, branchHeadSHA, newCommitSHA)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin",
			"--auto-create-branch"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != newCommitSHA {
		t.Errorf("stdout must carry new commit OID: %q", stdout.String())
	}
}

// TestRun_CommitPinnedDeps_MissingBranch_NoAutoCreate covers the
// safety default: a missing branch with --auto-create-branch=false
// is an operational error, not a silent success.
func TestRun_CommitPinnedDeps_MissingBranch_NoAutoCreate(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

	srv := newCommitServer(t, commitFixture{
		// branchHeadSHA empty → GetRef returns 404.
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--auto-create-branch") {
		t.Errorf("stderr must point operators at --auto-create-branch: %q", stderr.String())
	}
}
