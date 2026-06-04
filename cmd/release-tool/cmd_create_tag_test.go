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
	"strings"
	"sync/atomic"
	"testing"
)

const (
	fakeSHA      = "abcdef0123456789abcdef0123456789abcdef01"
	otherSHA     = "0123456789abcdef0123456789abcdef01234567"
	createdSHA   = "1111111111111111111111111111111111111111"
	annotatedTag = "9999999999999999999999999999999999999999"
)

// TestRun_CreateTag_MissingFlags_ExitsUsage covers the new-operator
// usability case: forgetting --tag should produce a fast usage error.
//
// Uses the test hook so we don't depend on GH_TOKEN — validation
// runs before the env lookup anyway.
func TestRun_CreateTag_MissingFlags_ExitsUsage(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook("http://unused.invalid", &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--sha", fakeSHA, "--message", "Release"})
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d (stderr=%q)", exitUsage, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--tag") {
		t.Errorf("error must name the missing flag: %q", stderr.String())
	}
}

// TestRun_CreateTag_BadSHA_ExitsValidation regression for #911:
// gh-CLI bash version was accepting 404 error JSON as a SHA. The
// validator must reject anything that isn't exactly 40 lowercase
// hex chars before any HTTP call goes out.
func TestRun_CreateTag_BadSHA_ExitsValidation(t *testing.T) {
	t.Parallel()
	// Simulated #911 payload: the error response that the bash
	// version mistook for a SHA.
	const bashEra911Bug = `{"message":"Not Found","documentation_url":"..."}`

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook("http://unused.invalid", &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", bashEra911Bug,
			"--message", "Release"})
	if code != exitValidation {
		t.Errorf("want exit %d (validation), got %d (stderr=%q)", exitValidation, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "40 lowercase hex") {
		t.Errorf("error must explain the SHA contract: %q", stderr.String())
	}
}

// TestRun_CreateTag_TagAbsent_CreatesAndReturnsSHA covers the happy
// path: tag does not exist, both API calls succeed, the OBJECT SHA is
// written to stdout (machines), the human diagnostic goes to stderr.
func TestRun_CreateTag_TagAbsent_CreatesAndReturnsSHA(t *testing.T) {
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
			"--message", "Release v0.2.2"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got != annotatedTag {
		t.Errorf("stdout must carry the tag OBJECT SHA: want %q, got %q", annotatedTag, got)
	}
}

// TestRun_CreateTag_TagExists_SameSHA_ExitsIdempotent covers the
// idempotent re-run case: rerunning the release with the same SHA
// must NOT be an error. Lightweight-tag case (ref Object.Type ==
// "commit").
func TestRun_CreateTag_TagExists_SameSHA_ExitsIdempotent(t *testing.T) {
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
			"--message", "Release v0.2.2"})
	if code != exitIdempotentNoOp {
		t.Errorf("want exit %d (idempotent), got %d (stderr=%q)", exitIdempotentNoOp, code, stderr.String())
	}
}

// TestRun_CreateTag_AnnotatedTagSameCommit_ExitsIdempotent covers
// the regression flagged in code review B1: the ref for an
// annotated tag carries the tag-object SHA, not the commit SHA. A
// re-run of the release on the SAME commit must dereference the
// tag object via GET /git/tags/{tag_object_sha} and compare
// .object.sha — NOT compare ref.object.sha against the flag.
// Without dereference, every annotated-tag re-run exits 1
// "refusing to overwrite", defeating the idempotency contract.
func TestRun_CreateTag_AnnotatedTagSameCommit_ExitsIdempotent(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		// Existing ref is an ANNOTATED tag — Object.Type=="tag",
		// Object.SHA is the tag-object SHA (annotatedTag), NOT the
		// commit SHA.
		getRefStatus: http.StatusOK,
		getRefBody:   refBody(annotatedTag, "tag"),
		// GET /git/tags/{annotatedTag} returns the tag object,
		// whose .object.sha is the commit (fakeSHA) we want.
		getTagStatus:        http.StatusOK,
		getTagDereferences:  annotatedTag,
		getTagBodyCommitSHA: fakeSHA,
		failIfMutation:      true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitIdempotentNoOp {
		t.Errorf("annotated-tag same-commit must be a no-op: want exit %d, got %d (stderr=%q)",
			exitIdempotentNoOp, code, stderr.String())
	}
}

// TestRun_CreateTag_AnnotatedTagDifferentCommit_ExitsOperational
// covers the contamination guard for annotated tags. The ref
// points at a tag-object SHA that derefences to a DIFFERENT commit
// than the flag — must exit 1 (refuses to overwrite).
func TestRun_CreateTag_AnnotatedTagDifferentCommit_ExitsOperational(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:        http.StatusOK,
		getRefBody:          refBody(annotatedTag, "tag"),
		getTagStatus:        http.StatusOK,
		getTagDereferences:  annotatedTag,
		getTagBodyCommitSHA: otherSHA, // different commit
		failIfMutation:      true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitOperational {
		t.Errorf("annotated-tag different-commit must refuse: want exit %d, got %d (stderr=%q)",
			exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), otherSHA) {
		t.Errorf("stderr must name the contaminating commit %s: %q", otherSHA, stderr.String())
	}
}

// TestRun_CreateTag_TagExists_DifferentSHA_ExitsOperational covers
// the history-contamination guard: re-running with a DIFFERENT SHA
// must refuse to overwrite.
func TestRun_CreateTag_TagExists_DifferentSHA_ExitsOperational(t *testing.T) {
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
			"--message", "Release v0.2.2"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing to overwrite") {
		t.Errorf("stderr must explain the contamination refusal: %q", stderr.String())
	}
}

// TestRun_CreateTag_UnknownRefObjectType_ExitsOperational locks the
// resolveExistingCommit default branch: a ref whose Object.Type is
// neither "commit" nor "tag" (e.g. a fabricated "blob") must exit
// operational with a diagnostic that names the unknown type, not
// fall through silently. Test-analyst B1.
func TestRun_CreateTag_UnknownRefObjectType_ExitsOperational(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:   http.StatusOK,
		getRefBody:     refBody(fakeSHA, "blob"),
		failIfMutation: true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `"blob"`) {
		t.Errorf("stderr must name the unknown object type: %q", stderr.String())
	}
}

// TestRun_CreateTag_GetRef5xx_ExitsOperational covers the non-404
// GetRef failure mode (analyst I4). The bash version conflated 5xx
// with "tag doesn't exist" and happily POSTed a duplicate. Now the
// 5xx must exit 1 with a useful diagnostic.
func TestRun_CreateTag_GetRef5xx_ExitsOperational(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:   http.StatusServiceUnavailable,
		failIfMutation: true,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "503") {
		t.Errorf("stderr must surface the HTTP status: %q", stderr.String())
	}
}

// TestRun_CreateTag_CreateRefFails_SurfacesTagSHA covers partial-
// success recovery (analyst I2). CreateTag succeeds (the tag-object
// is now committed to the repo's object database) but CreateRef
// fails. The operator must be able to see the tag-object SHA in
// stderr so they can finish the release manually — otherwise this
// is an undocumented information-loss event.
//
// To prove the SHA is surfaced by release-tool itself (not echoed
// back by the API mock), the createRef fixture replies with a 502
// body that does NOT include the SHA. The assertion fails if the
// production code stops printing the SHA explicitly.
func TestRun_CreateTag_CreateRefFails_SurfacesTagSHA(t *testing.T) {
	t.Parallel()
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:          http.StatusNotFound,
		createTagStatus:       http.StatusCreated,
		createRefStatus:       http.StatusBadGateway,
		suppressCreateRefBody: true, // 502 body has no SHA — prove release-tool surfaces it
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitOperational {
		t.Errorf("want exit %d (operational), got %d (stderr=%q)", exitOperational, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), annotatedTag) {
		t.Errorf("stderr must surface the orphan tag-object SHA %s so the operator can recover: %q",
			annotatedTag, stderr.String())
	}
	if !strings.Contains(stderr.String(), "recover manually") {
		t.Errorf("stderr must include the recovery recipe: %q", stderr.String())
	}
}

// TestRun_CreateTag_DryRun_NoMutations covers the safety contract:
// --dry-run prints the proposed payload to stdout and performs no
// state mutation, even when the tag does not exist. The fixture
// installs a mutation handler that always fails the test so any
// stray POST is caught directly.
func TestRun_CreateTag_DryRun_NoMutations(t *testing.T) {
	t.Parallel()
	var mutationHits atomic.Int32
	srv := newCreateTagServer(t, &createTagFixture{
		getRefStatus:    http.StatusNotFound,
		failIfMutation:  true,
		mutationCounter: &mutationHits,
	})
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runCreateTagTestHook(srv.URL, &stdout, &stderr,
		[]string{"--dry-run",
			"--owner", "axonops", "--repo", "audit",
			"--tag", "v0.2.2", "--sha", fakeSHA,
			"--message", "Release v0.2.2"})
	if code != exitSuccess {
		t.Fatalf("want exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if got := mutationHits.Load(); got != 0 {
		t.Errorf("dry-run must perform zero mutating API calls, got %d", got)
	}
	assertCreateTagDryRunPayload(t, stdout.Bytes())
}

// assertCreateTagDryRunPayload drills into the nested dry-run
// payload (test-analyst I6). Extracted so the parent test stays
// under the cyclomatic-complexity gate.
func assertCreateTagDryRunPayload(t *testing.T, raw []byte) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("dry-run stdout must be valid JSON: %v\n%s", err, string(raw))
	}
	tagObject, ok := payload["tag_object"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload must include nested `tag_object` object, got %T", payload["tag_object"])
	}
	body, ok := tagObject["body"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload must include nested `tag_object.body` object")
	}
	for k, want := range map[string]any{
		"tag":     "v0.2.2",
		"object":  fakeSHA,
		"message": "Release v0.2.2",
	} {
		if body[k] != want {
			t.Errorf("dry-run tag_object.body.%s: want %q, got %v", k, want, body[k])
		}
	}
	ref, ok := payload["ref"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload must include nested `ref` object")
	}
	refBody, ok := ref["body"].(map[string]any)
	if !ok {
		t.Fatalf("dry-run payload must include nested `ref.body` object")
	}
	if refBody["ref"] != "refs/tags/v0.2.2" {
		t.Errorf("dry-run ref.body.ref: want %q, got %v", "refs/tags/v0.2.2", refBody["ref"])
	}
}

// createTagFixture configures the test server behaviour.
//
// For lightweight-tag scenarios, leave getTagDereferences empty —
// the GET /git/tags handler will not be expected. For annotated-tag
// scenarios, set both getTagDereferences (the tag-object SHA the
// fixture is mock-dereferencing) and getTagBodyCommitSHA (the
// commit SHA the fixture should return).
//
// mutationCounter, if non-nil, is incremented every time a
// mutating endpoint (POST git/tags, POST git/refs) is hit. The
// caller asserts it is zero when verifying --dry-run safety.
type createTagFixture struct {
	mutationCounter     *atomic.Int32
	getRefBody          string
	getTagDereferences  string
	getTagBodyCommitSHA string
	getRefStatus        int
	getTagStatus        int
	createTagStatus     int
	createRefStatus     int
	failIfMutation      bool
	// suppressCreateRefBody, when true, makes the createRef handler
	// emit an empty 502 response body. Used to prove release-tool
	// surfaces the orphan tag-object SHA in stderr ITSELF rather
	// than passively relaying it from the API response body.
	suppressCreateRefBody bool
}

// newCreateTagServer constructs an httptest server that drives the
// four create-tag calls in order: GET ref/tags/X (idempotency),
// optional GET tags/{tag_object_sha} (annotated-tag dereference),
// POST git/tags (create the object), POST git/refs (publish the
// ref). The dry-run mutation counter is incremented every time a
// mutation endpoint is hit — the caller asserts on it via the
// returned *atomic.Int32 (use mutationCounter to check zero).
func newCreateTagServer(t *testing.T, f *createTagFixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/axonops/audit/git/ref/tags/v0.2.2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(f.getRefStatus)
		if f.getRefBody != "" {
			_, _ = w.Write([]byte(f.getRefBody))
		}
	})
	if f.getTagDereferences != "" {
		path := "/repos/axonops/audit/git/tags/" + f.getTagDereferences
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(f.getTagStatus)
			_, _ = w.Write([]byte(`{"sha":"` + f.getTagDereferences +
				`","tag":"v0.2.2","object":{"sha":"` + f.getTagBodyCommitSHA + `","type":"commit"}}`))
		})
	}
	mux.HandleFunc("/repos/axonops/audit/git/tags", func(w http.ResponseWriter, r *http.Request) {
		if f.mutationCounter != nil {
			f.mutationCounter.Add(1)
		}
		if f.failIfMutation {
			t.Errorf("mutation endpoint hit but fixture forbids it: %s %s", r.Method, r.URL.Path)
			http.Error(w, "forbidden by fixture", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(f.createTagStatus)
		_, _ = w.Write([]byte(`{"sha":"` + annotatedTag + `","tag":"v0.2.2"}`))
	})
	mux.HandleFunc("/repos/axonops/audit/git/refs", func(w http.ResponseWriter, r *http.Request) {
		if f.mutationCounter != nil {
			f.mutationCounter.Add(1)
		}
		if f.failIfMutation {
			t.Errorf("mutation endpoint hit but fixture forbids it: %s %s", r.Method, r.URL.Path)
			http.Error(w, "forbidden by fixture", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(f.createRefStatus)
		if f.suppressCreateRefBody {
			return
		}
		_, _ = w.Write([]byte(`{"ref":"refs/tags/v0.2.2","object":{"sha":"` + annotatedTag + `","type":"tag"}}`))
	})
	return httptest.NewServer(mux)
}

func refBody(sha, typ string) string {
	return `{"ref":"refs/tags/v0.2.2","object":{"sha":"` + sha + `","type":"` + typ + `","url":""}}`
}
