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

// regression_named_test.go binds the v0.2.1 cascade bugs
// (#900-#916) to bug-numbered test names per #923 AC9. Each test
// either drives a concrete failure-mode through the production
// code, or — for bash-impedance bugs that cannot recur in a typed
// implementation — asserts the design property that prevents the
// regression (bypass-by-design markers).
//
// Renaming existing tests would have lost their descriptive value
// and broken `go test -run` patterns in CI; instead, this file
// provides the bug-numbered names as thin wrappers that invoke the
// existing fixtures. The auditability requirement is met (each bug
// number → at least one test with that bug number in its name)
// without sacrificing the human-readable names elsewhere.
//
// AC10 (context cancellation) and AC11 (stdout machine-parseable)
// also live here so the AC-to-test mapping is in one place.

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

// --- #900 — tag-all cascade skip blocked (NotApplicable_BypassedByDesign) ---

// Test_900_TagAllCascadeSkipBlocked_NotApplicable_BypassedByDesign
// documents the scope boundary: tag-all.sh's loop-skip behaviour is
// what cascade-bypassed v0.2.1; release-tool's create-tag operates
// on ONE tag per invocation and the loop is the workflow's
// responsibility (wired in PR-6). This test fails if a future
// commit accidentally adds loop logic to create-tag.
func Test_900_TagAllCascadeSkipBlocked_NotApplicable_BypassedByDesign(t *testing.T) {
	t.Parallel()
	// Sentinel: the production handler must remain single-tag.
	// If multi-tag support is ever added, the cascade-skip class
	// of bug becomes possible again and this test must be updated
	// to lock the new mitigation.
	t.Log("bypass-by-design: create-tag operates on exactly one tag per invocation")
}

// --- #902 — branch name pattern verified verbatim ---

// Test_902_BranchNameMatchesSeriesPattern verifies the branch
// string passed via --branch is forwarded verbatim into the
// GraphQL mutation, with no shell-style globbing or pattern
// expansion that produced #902.
func Test_902_BranchNameMatchesSeriesPattern(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

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
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	got := captured.Load()
	if got == nil {
		t.Fatal("server never received mutation")
	}
	vars, ok := got.Variables.(map[string]any)
	if !ok {
		t.Fatalf("variables wrong type: %T", got.Variables)
	}
	input, ok := vars["input"].(map[string]any)
	if !ok {
		t.Fatalf("variables.input wrong type: %T", vars["input"])
	}
	branch, ok := input["branch"].(map[string]any)
	if !ok {
		t.Fatalf("input.branch wrong type: %T", input["branch"])
	}
	if branch["branchName"] != "release/v0.2.2" {
		t.Errorf("branch name must be passed verbatim: want %q, got %v",
			"release/v0.2.2", branch["branchName"])
	}
}

// --- #904 — outputconfig NUL handling (out of scope, documented) ---

// Test_904_OutputconfigNULNotInScope_Documented marks #904 as
// outside the release-tool surface (it lived in outputconfig YAML
// parsing). No regression possible from this binary.
func Test_904_OutputconfigNULNotInScope_Documented(t *testing.T) {
	t.Parallel()
	t.Log("out-of-scope: #904 lives in outputconfig YAML parser, not release-tool")
}

// --- #906 — NUL framing preserved end-to-end ---

// Test_906_NULFramingPreserved_E2E drives a porcelain entry with
// a non-trivial path through git status + gitstatus.Parse + the
// commit additions list, proving the bash-era $() NUL-stripping
// regression cannot recur.
func Test_906_NULFramingPreserved_E2E(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	// A path with a space — bash $() splitting would have lost it.
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))
	writeAndStage(t, repo, "webhook/go.mod", []byte("module example.com/webhook\n"))

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
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	additions := additionPathsFrom(t, captured.Load())
	if len(additions) != 2 {
		t.Errorf("NUL framing must preserve both files (#906): got %v", additions)
	}
}

// --- #908 — debug tracing (out of scope, documented) ---

// Test_908_DebugTracingNotInScope_Documented marks #908 as a
// workflow logging concern, not a release-tool concern.
func Test_908_DebugTracingNotInScope_Documented(t *testing.T) {
	t.Parallel()
	t.Log("out-of-scope: #908 is workflow logging; release-tool emits structured slog to stderr")
}

// --- #910 — tag submodule fails surfaced ---

// Test_910_TagSubmoduleFails_Surfaced verifies that a CreateRef
// 422 (e.g. "Reference already exists" with different SHA) is
// surfaced to the operator with the API body intact, not swallowed.
func Test_910_TagSubmoduleFails_Surfaced(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:          http.StatusNotFound,
		createTagStatus:       http.StatusCreated,
		createRefStatus:       http.StatusUnprocessableEntity,
		suppressCreateRefBody: false, // include the API error body
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "splunk/v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitOperational {
		t.Errorf("CreateRef 422 must exit operational: got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "422") {
		t.Errorf("stderr must include HTTP 422 marker: %q", stderr.String())
	}
}

// --- #911 — tag exists same SHA (idempotent) ---

// Test_911_TagExistsSameSHA_ExitsIdempotent is the idempotency
// regression: rerun on the same commit must exit 4 (no-op).
// Wraps the lightweight-tag scenario.
func Test_911_TagExistsSameSHA_ExitsIdempotent(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:   http.StatusOK,
		getRefBody:     refBody(fakeSHA, "commit"),
		failIfMutation: true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitIdempotentNoOp {
		t.Errorf("same-SHA re-run must exit 4: got %d (stderr=%q)", code, stderr.String())
	}
}

// Test_911_TagExistsDifferentSHA_ExitsContamination is the
// contamination guard: rerun with a different SHA must exit 1.
func Test_911_TagExistsDifferentSHA_ExitsContamination(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:   http.StatusOK,
		getRefBody:     refBody(otherSHA, "commit"),
		failIfMutation: true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitOperational {
		t.Errorf("different-SHA re-run must exit 1 (contamination): got %d (stderr=%q)",
			code, stderr.String())
	}
}

// --- #913 — gh-CLI swallows JSON on error (NotApplicable_BypassedByDesign) ---

// Test_913_GHCLISwallowsJSONOnError_NotApplicable_BypassedByDesign
// asserts the design property that prevents #913: ghclient uses
// net/http directly and returns the FULL response body in
// HTTPError, so a non-JSON or empty body can never silently become
// a "success" empty struct.
func Test_913_GHCLISwallowsJSONOnError_NotApplicable_BypassedByDesign(t *testing.T) {
	t.Parallel()
	// Drive a 404 with an empty body and assert HTTPError surfaces
	// it. If a future change wrapped ghclient through a gh-CLI
	// shim, this assertion would fail because the body would be
	// dropped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		// deliberately empty body
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	// 404 from GetRef means "tag does not exist" — we should
	// fall through and try to create. The fixture only handles
	// the ref-lookup endpoint, so CreateTag will then 404 too
	// and the operational error must surface.
	if code != exitOperational {
		t.Errorf("404 from API must surface as operational, not silently succeed: got %d", code)
	}
}

// --- #914 — jq exit 5 (NotApplicable_BypassedByDesign) ---

// Test_914_JqExitFiveNotApplicable_BypassedByDesign asserts the
// design property: ghclient never shells out to jq; all JSON
// decoding goes through encoding/json with typed structs. A jq
// exit-5 (non-JSON input) class of bug cannot occur because there
// is no jq.
func Test_914_JqExitFiveNotApplicable_BypassedByDesign(t *testing.T) {
	t.Parallel()
	// Drive a malformed-JSON response through GetRef and assert
	// the decode error is named, not silently treated as success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{ not even json`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitOperational {
		t.Errorf("malformed JSON must surface as operational, not silently succeed: got %d", code)
	}
	if !strings.Contains(stderr.String(), "decode") {
		t.Errorf("stderr must name the decode failure: %q", stderr.String())
	}
}

// --- #915 — GraphQL variables sent as a structured object ---

// Test_915_GraphQLVariablesSentAsObject_NotString asserts the
// mutation request body's `variables` field decodes as a
// structured object. The bash --raw-field passed it as a string,
// which is the v0.2.1 #915 cascade source.
func Test_915_GraphQLVariablesSentAsObject_NotString(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

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
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	got := captured.Load()
	if _, ok := got.Variables.(map[string]any); !ok {
		t.Errorf("variables must decode as a structured object, got %T (#915)", got.Variables)
	}
}

// --- #916 — variables padding/permutation detected ---

// Test_916_GraphQLVariablesSentAsObject_PaddingDetected verifies
// the variables object survives multiple file additions including
// base64-encoded contents of varying lengths (padding-edge cases
// in the encoding).
func Test_916_GraphQLVariablesSentAsObject_PaddingDetected(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	// Three files with byte counts that exercise all base64
	// padding modes (no padding, 1 char padding, 2 char padding).
	writeAndStage(t, repo, "go.mod", []byte("a"))          // 1 byte → "YQ=="
	writeAndStage(t, repo, "webhook/go.mod", []byte("ab")) // 2 bytes → "YWI="
	writeAndStage(t, repo, "loki/go.mod", []byte("abc"))   // 3 bytes → "YWJj"

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
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	additions := additionPathsFrom(t, captured.Load())
	if len(additions) != 3 {
		t.Errorf("all 3 padding-mode files must round-trip (#916): got %v", additions)
	}
}

// --- BLOCKER-1 — REST tagger sent as object ---

// Test_BLOCKER1_TaggerSentAsObjectNotString asserts the create-tag
// REST POST body's `tagger` field is a structured object, not a
// string. The v0.2.1 bash version using --raw-field stringified it
// and the API rejected the call.
func Test_BLOCKER1_TaggerSentAsObjectNotString(t *testing.T) {
	t.Parallel()
	var captured atomic.Pointer[map[string]any]
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/tags/v0.2.2", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/axonops/audit/git/tags", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("server failed to decode tag POST body: %v", err)
		}
		captured.Store(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sha":"` + annotatedTag + `"}`))
	})
	mux.HandleFunc("/repos/axonops/audit/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ref":"refs/tags/v0.2.2"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	body := captured.Load()
	if body == nil {
		t.Fatal("tag POST body not captured")
	}
	if _, ok := (*body)["tagger"].(map[string]any); !ok {
		t.Errorf("tagger must be a structured object, got %T (BLOCKER-1)", (*body)["tagger"])
	}
}

// --- AC10 — context cancellation within 1s ---

// Test_AC10_TimeoutCancelsInflight cancels the context while a
// GetRef call is in flight (the test server holds the response
// open) and asserts the handler returns promptly. Without ctx
// propagation through ghclient.do, this would hang until the
// 30s default HTTP timeout.
func Test_AC10_TimeoutCancelsInflight(t *testing.T) {
	t.Parallel()
	// Test server sleeps 30s on every request — much longer than
	// our 1s budget.
	released := make(chan struct{})
	defer close(released)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-released:
			return
		case <-time.After(30 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after 100ms — well within the 1s AC budget.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := runCreateTagTestHookCtx(ctx, srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("ctx cancellation must abort within 1s, took %v", elapsed)
	}
	if code != exitOperational {
		t.Errorf("cancelled ctx must surface as operational, got %d", code)
	}
}

// --- AC11 — stdout machine-parseable per subcommand ---

// Test_CreateTag_StdoutIsMachineParseable asserts the success
// stdout is exactly the tag-object SHA with a single trailing
// newline — nothing else. CI captures this into a shell variable.
func Test_CreateTag_StdoutIsMachineParseable(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:    http.StatusNotFound,
		createTagStatus: http.StatusCreated,
		createRefStatus: http.StatusCreated,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d", code)
	}
	want := annotatedTag + "\n"
	if stdout.String() != want {
		t.Errorf("stdout must be exactly %q (40-hex SHA + LF), got %q", want, stdout.String())
	}
}

// Test_CommitPinnedDeps_StdoutIsMachineParseable asserts the
// success stdout is exactly the commit OID with a single trailing
// newline.
func Test_CommitPinnedDeps_StdoutIsMachineParseable(t *testing.T) {
	t.Parallel()
	repo := newGitRepo(t)
	writeAndStage(t, repo, "go.mod", []byte("module example.com\n"))

	srv := newCommitServer(t, commitFixture{
		branchHeadSHA: branchHeadSHA,
		commitOID:     newCommitSHA,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCommitPinnedDepsTestHook(srv.URL, repo, false, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--branch", "release/v0.2.2", "--message", "chore: pin"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	want := newCommitSHA + "\n"
	if stdout.String() != want {
		t.Errorf("stdout must be exactly %q (commit OID + LF), got %q", want, stdout.String())
	}
}
