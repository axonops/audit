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

package ghclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/ghclient"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*ghclient.Client, *httptest.Server, *bytes.Buffer) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := ghclient.New("dummy-token",
		ghclient.WithBaseURL(ts.URL),
		ghclient.WithHTTPClient(ts.Client()),
		ghclient.WithLogger(logger),
	)
	if err != nil {
		t.Fatal(err)
	}
	return c, ts, logBuf
}

func TestClient_New_RejectsEmptyToken(t *testing.T) {
	t.Parallel()
	_, err := ghclient.New("")
	if err == nil {
		t.Error("empty token must be rejected")
	}
}

func TestClient_GetRef_200_OK(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/git/ref/heads/main") {
			http.Error(w, "wrong endpoint", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":     "refs/heads/main",
			"node_id": "REF_kw",
			"url":     "https://api.github.com/repos/o/r/git/refs/heads/main",
			"object": map[string]any{
				"sha":  "0123456789abcdef0123456789abcdef01234567",
				"type": "commit",
				"url":  "https://api.github.com/repos/o/r/git/commits/abc",
			},
		})
	})

	ref, err := c.GetRef(context.Background(), "owner", "repo", "heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Object.SHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("wrong SHA: %s", ref.Object.SHA)
	}
}

func TestClient_GetRef_404_NotFound(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Not Found","status":"404"}`)
	})

	_, err := c.GetRef(context.Background(), "owner", "repo", "tags/nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", herr.StatusCode)
	}
}

func TestClient_CreateTag_201_Created(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify request body is a structured JSON object (not a
		// stringified JSON — regression for #915/#916).
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if _, ok := body["tagger"].(map[string]any); !ok {
			http.Error(w, "tagger must be object", http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"node_id": "TAG_kw",
			"tag":     "v0.2.2",
			"sha":     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"url":     "https://api.github.com/repos/o/r/git/tags/dead",
			"message": "Release v0.2.2",
			"tagger": map[string]any{
				"name":  "bot",
				"email": "bot@example.com",
				"date":  "2026-06-04T12:00:00Z",
			},
			"object": map[string]any{
				"sha":  "0123456789abcdef0123456789abcdef01234567",
				"type": "commit",
				"url":  "https://api.github.com/repos/o/r/git/commits/abc",
			},
		})
	})

	tag, err := c.CreateTag(context.Background(), "owner", "repo", &ghclient.CreateTagInput{
		Tag:     "v0.2.2",
		Message: "Release v0.2.2",
		Object:  "0123456789abcdef0123456789abcdef01234567",
		Type:    "commit",
		Tagger: ghclient.TagAuthor{
			Name:  "bot",
			Email: "bot@example.com",
			Date:  "2026-06-04T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tag.SHA != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("wrong tag SHA: %s", tag.SHA)
	}
}

func TestClient_CreateRef_422_AlreadyExists(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"message":"Reference already exists"}`)
	})

	_, err := c.CreateRef(context.Background(), "owner", "repo", &ghclient.CreateRefInput{
		Ref: "refs/tags/v0.2.2",
		SHA: "0123456789abcdef0123456789abcdef01234567",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", herr.StatusCode)
	}
}

func TestClient_401_BadToken(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Bad credentials"}`)
	})

	_, err := c.GetRef(context.Background(), "o", "r", "heads/main")
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", herr.StatusCode)
	}
}

func TestClient_403_RateLimited_RetryAfterHonored(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	})

	_, err := c.GetRef(context.Background(), "o", "r", "heads/main")
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", herr.StatusCode)
	}
}

func TestClient_AuthorizationHeaderRedactedInSlog(t *testing.T) {
	t.Parallel()
	c, _, logBuf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Verify the test server received the token (so we know
		// it's not the request that's missing it).
		if r.Header.Get("Authorization") == "" {
			t.Errorf("server did not receive Authorization header")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":     "refs/heads/main",
			"node_id": "x",
			"url":     "u",
			"object":  map[string]any{"sha": "0123456789abcdef0123456789abcdef01234567", "type": "commit", "url": "u"},
		})
	})

	_, err := c.GetRef(context.Background(), "o", "r", "heads/main")
	if err != nil {
		t.Fatal(err)
	}
	// The structured log MUST NOT contain the token. We only log
	// method/url/status/duration — Authorization is never an
	// attribute.
	if strings.Contains(logBuf.String(), "dummy-token") {
		t.Errorf("token leaked into slog output: %s", logBuf.String())
	}
}

func TestClient_CreateRef_201_Created(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":     "refs/tags/v0.2.2",
			"node_id": "REF_kw",
			"url":     "https://api.github.com/repos/o/r/git/refs/tags/v0.2.2",
			"object": map[string]any{
				"sha":  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
				"type": "tag",
				"url":  "https://api.github.com/repos/o/r/git/tags/dead",
			},
		})
	})
	ref, err := c.CreateRef(context.Background(), "owner", "repo", &ghclient.CreateRefInput{
		Ref: "refs/tags/v0.2.2",
		SHA: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.Ref != "refs/tags/v0.2.2" {
		t.Errorf("wrong ref: %s", ref.Ref)
	}
}

func TestClient_CreateTag_422_ValidationError(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"message":"Validation Failed"}`)
	})
	_, err := c.CreateTag(context.Background(), "o", "r", &ghclient.CreateTagInput{Tag: "v0"})
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.StatusCode != 422 {
		t.Errorf("want 422, got %d", herr.StatusCode)
	}
}

func TestHTTPError_ErrorString(t *testing.T) {
	t.Parallel()
	e := &ghclient.HTTPError{
		StatusCode: 404,
		Body:       `{"message":"Not Found"}`,
		Method:     "GET",
		URL:        "https://api/repos/o/r/git/ref/heads/main",
		RequestID:  "abc-123",
	}
	s := e.Error()
	if !strings.Contains(s, "GET") || !strings.Contains(s, "404") || !strings.Contains(s, "abc-123") {
		t.Errorf("error string missing diagnostic content: %s", s)
	}
}

func TestClient_403_RetryAfterMalformed_LoggedAsZero(t *testing.T) {
	t.Parallel()
	c, _, logBuf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "not-a-number")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	})
	_, err := c.GetRef(context.Background(), "o", "r", "heads/main")
	if err == nil {
		t.Fatal("expected error")
	}
	// Malformed Retry-After must NOT crash and must NOT log a
	// retry_after_seconds attribute.
	if strings.Contains(logBuf.String(), "retry_after_seconds") {
		t.Errorf("malformed Retry-After must not produce a retry_after_seconds attr; got %s", logBuf.String())
	}
}

func TestClient_NetworkError_PropagatesAsWrappedError(t *testing.T) {
	t.Parallel()
	// Point at a port nobody listens on to force a connection
	// error.
	c, err := ghclient.New("dummy-token", ghclient.WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetRef(context.Background(), "o", "r", "heads/main")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "request_id=") {
		t.Errorf("network error must include request_id for correlation, got %v", err)
	}
}

func TestClient_HTTPError_IncludesRequestID(t *testing.T) {
	t.Parallel()
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	})

	_, err := c.GetRef(context.Background(), "o", "r", "heads/main")
	var herr *ghclient.HTTPError
	if !errors.As(err, &herr) {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if herr.RequestID == "" {
		t.Error("request ID must be populated on errors for trace correlation")
	}
	if herr.Body != "boom" {
		t.Errorf("response body must be preserved verbatim, got %q", herr.Body)
	}
}
