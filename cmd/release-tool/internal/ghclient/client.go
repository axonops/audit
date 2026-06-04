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

// Package ghclient is a typed HTTP wrapper for the three GitHub API
// endpoints release-tool needs:
//
//   - GetRef     (REST GET   /repos/{owner}/{repo}/git/ref/{ref})
//   - CreateTag  (REST POST  /repos/{owner}/{repo}/git/tags)
//   - CreateRef  (REST POST  /repos/{owner}/{repo}/git/refs)
//
// The bash scripts this replaces (#900-#916) repeatedly tripped on
// the gh-CLI quirks of swallowing JSON parse errors, dropping NUL
// framing, and sending JSON objects as strings. This implementation
// constructs typed structs, marshals to JSON via encoding/json, and
// surfaces every API failure with the full response body in the
// returned error.
//
// The client runs synchronously and starts no goroutines.
package ghclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Client is the audit-release-tool's typed wrapper around the
// GitHub REST API. Construct with [New]. The zero value is not
// usable.
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	baseURL    string
	token      string
}

// Option configures a [Client] at construction time.
type Option func(*Client)

// WithBaseURL overrides the GitHub API base URL. Used by tests
// against httptest.Server. Production callers leave the default.
func WithBaseURL(u string) Option {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(u, "/")
	}
}

// WithHTTPClient overrides the underlying HTTP client. The default
// is a [http.Client] with a 30-second timeout. Tests inject a
// httptest.Server's client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.httpClient = h }
}

// WithLogger sets the structured logger used to record API calls.
// Defaults to [slog.Default]. The logger MUST write to stderr to
// preserve the stdout/stderr contract; the package does not
// configure that itself.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// New constructs a [Client]. The token is the App's installation
// token (typically from the GH_TOKEN environment variable). The
// token MUST NOT be empty.
func New(token string, opts ...Option) (*Client, error) {
	if token == "" {
		return nil, errors.New("ghclient: token must not be empty")
	}
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.github.com",
		token:      token,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// RefObject is the object referenced by a Git ref (a commit or a
// tag).
type RefObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Ref is the response shape of a GitHub Git ref lookup.
type Ref struct {
	Ref    string    `json:"ref"`
	NodeID string    `json:"node_id"`
	URL    string    `json:"url"`
	Object RefObject `json:"object"`
}

// Tag is the response shape of a GitHub annotated tag object.
type Tag struct {
	NodeID  string    `json:"node_id"`
	Tag     string    `json:"tag"`
	SHA     string    `json:"sha"`
	URL     string    `json:"url"`
	Message string    `json:"message"`
	Tagger  TagAuthor `json:"tagger"`
	Object  RefObject `json:"object"`
}

// TagAuthor identifies the author of an annotated tag object.
type TagAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

// CreateTagInput is the request body for creating an annotated tag.
type CreateTagInput struct {
	Tag     string    `json:"tag"`
	Message string    `json:"message"`
	Object  string    `json:"object"`
	Type    string    `json:"type"`
	Tagger  TagAuthor `json:"tagger"`
}

// CreateRefInput is the request body for creating a git ref.
type CreateRefInput struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

// HTTPError carries the full response body and status code when an
// API call fails. PR-3's subcommands inspect the StatusCode to
// distinguish operational failure (1) from already-exists idempotent
// no-op (4).
type HTTPError struct {
	Body       string
	Method     string
	URL        string
	RequestID  string
	StatusCode int
}

// Error implements the error interface.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("ghclient: %s %s: HTTP %d (request_id=%s): %s",
		e.Method, e.URL, e.StatusCode, e.RequestID, e.Body)
}

// GetRef fetches the ref at refs/<refSuffix> in owner/repo. Pass
// refSuffix like "heads/main" or "tags/v0.2.2"; the leading
// "refs/" is supplied automatically.
//
// Returns nil and a [HTTPError] with StatusCode=404 when the ref
// does not exist. Callers MUST inspect the error type, NOT just
// check for nil — a missing ref is a structured condition, not an
// unexpected failure.
func (c *Client) GetRef(ctx context.Context, owner, repo, refSuffix string) (*Ref, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/ref/%s", c.baseURL, owner, repo, refSuffix)
	status, body, reqID, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &HTTPError{StatusCode: status, Body: string(body), Method: http.MethodGet, URL: url, RequestID: reqID}
	}
	var r Ref
	if uerr := json.Unmarshal(body, &r); uerr != nil {
		return nil, fmt.Errorf("ghclient: GetRef decode: %w", uerr)
	}
	return &r, nil
}

// CreateTag creates an annotated tag object in owner/repo. The
// returned [Tag.SHA] is the SHA of the tag OBJECT (not the
// referenced commit) — pass it to [Client.CreateRef] to make the
// tag visible.
func (c *Client) CreateTag(ctx context.Context, owner, repo string, in *CreateTagInput) (*Tag, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/tags", c.baseURL, owner, repo)
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("ghclient: CreateTag marshal: %w", err)
	}
	status, respBody, reqID, err := c.do(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, &HTTPError{StatusCode: status, Body: string(respBody), Method: http.MethodPost, URL: url, RequestID: reqID}
	}
	var t Tag
	if uerr := json.Unmarshal(respBody, &t); uerr != nil {
		return nil, fmt.Errorf("ghclient: CreateTag decode: %w", uerr)
	}
	return &t, nil
}

// CreateRef creates a git ref pointing at the given SHA. The Ref
// field of the input MUST start with "refs/" (e.g.,
// "refs/tags/v0.2.2" or "refs/heads/release/v0.2.x").
//
// A 422 ("Reference already exists") is surfaced as a [HTTPError]
// with StatusCode=422 — callers compare and decide whether the
// existing ref points at the same SHA (idempotent no-op) or
// different SHA (contamination warning).
func (c *Client) CreateRef(ctx context.Context, owner, repo string, in *CreateRefInput) (*Ref, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/refs", c.baseURL, owner, repo)
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("ghclient: CreateRef marshal: %w", err)
	}
	status, respBody, reqID, err := c.do(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, &HTTPError{StatusCode: status, Body: string(respBody), Method: http.MethodPost, URL: url, RequestID: reqID}
	}
	var r Ref
	if uerr := json.Unmarshal(respBody, &r); uerr != nil {
		return nil, fmt.Errorf("ghclient: CreateRef decode: %w", uerr)
	}
	return &r, nil
}

// do executes a single HTTP request, handles structured logging
// (including Authorization-header redaction — the token is never
// passed to slog as an attribute), and returns the status, body,
// and per-request UUID. The response body is closed before return,
// so callers never see an open *http.Response.
func (c *Client) do(ctx context.Context, method, url string, body []byte) (status int, respBody []byte, reqID string, err error) {
	reqID = uuid.New().String()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return 0, nil, reqID, fmt.Errorf("ghclient: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("X-Request-ID", reqID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	dur := time.Since(start)
	if err != nil {
		c.logger.LogAttrs(ctx, slog.LevelError, "github_api_call",
			slog.String("method", method),
			slog.String("url", url),
			slog.String("request_id", reqID),
			slog.String("error", err.Error()),
			slog.Int64("duration_ms", dur.Milliseconds()),
		)
		return 0, nil, reqID, fmt.Errorf("ghclient: %s %s (request_id=%s): %w", method, url, reqID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, reqID, fmt.Errorf("ghclient: read body: %w", err)
	}
	level := slog.LevelInfo
	if resp.StatusCode >= 400 {
		level = slog.LevelWarn
	}
	retryAfter := retryAfterSeconds(resp)
	attrs := []slog.Attr{
		slog.String("method", method),
		slog.String("url", url),
		slog.String("request_id", reqID),
		slog.Int("status", resp.StatusCode),
		slog.Int64("duration_ms", dur.Milliseconds()),
	}
	if retryAfter > 0 {
		attrs = append(attrs, slog.Int("retry_after_seconds", retryAfter))
	}
	c.logger.LogAttrs(ctx, level, "github_api_call", attrs...)
	return resp.StatusCode, respBody, reqID, nil
}

// retryAfterSeconds returns the seconds value of a 403 response's
// Retry-After header, or 0 when not present / not parseable / status
// is not 403. Best-effort context for the caller.
func retryAfterSeconds(resp *http.Response) int {
	if resp.StatusCode != http.StatusForbidden {
		return 0
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		return 0
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		return 0
	}
	return secs
}
