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

package audit_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers for webhook
// ---------------------------------------------------------------------------

// webhookTestServer wraps httptest.Server with request capture and
// a waitForRequests polling helper (no time.Sleep).
type webhookTestServer struct {
	server    *httptest.Server
	requests  []*webhookCapturedRequest
	requestCh chan struct{}
	mu        sync.Mutex
}

type webhookCapturedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

func newWebhookTestServer(t *testing.T, handler http.HandlerFunc) *webhookTestServer {
	t.Helper()
	s := &webhookTestServer{
		requestCh: make(chan struct{}, 1000),
	}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		s.mu.Lock()
		s.requests = append(s.requests, &webhookCapturedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
			Body:    body,
		})
		s.mu.Unlock()
		select {
		case s.requestCh <- struct{}{}:
		default:
		}
		handler(w, r)
	}))
	t.Cleanup(func() { s.server.Close() })
	return s
}

func (s *webhookTestServer) url() string { return s.server.URL }

func (s *webhookTestServer) waitForRequests(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		count := len(s.requests)
		s.mu.Unlock()
		if count >= n {
			return true
		}
		select {
		case <-s.requestCh:
		case <-deadline:
			return false
		}
	}
}

func (s *webhookTestServer) getRequests() []*webhookCapturedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*webhookCapturedRequest, len(s.requests))
	copy(cp, s.requests)
	return cp
}

func (s *webhookTestServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// newTestWebhookOutput creates a webhook output for testing with
// AllowInsecureHTTP and AllowPrivateRanges (httptest uses http://127.0.0.1).
func newTestWebhookOutput(t *testing.T, url string, opts ...func(*audit.WebhookConfig)) *audit.WebhookOutput {
	t.Helper()
	cfg := &audit.WebhookConfig{
		URL:                url,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	out, err := audit.NewWebhookOutput(cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// ---------------------------------------------------------------------------
// Commit 3 tests: Constructor, interface, Name
// ---------------------------------------------------------------------------

func TestNewWebhookOutput_Valid(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewWebhookOutput_InvalidConfig(t *testing.T) {
	_, err := audit.NewWebhookOutput(&audit.WebhookConfig{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestWebhookOutput_ImplementsOutput(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	var _ audit.Output = out
}

func TestWebhookOutput_Name(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	name := out.Name()
	assert.True(t, strings.HasPrefix(name, "webhook:"), "Name should start with webhook:")
	assert.Contains(t, name, "127.0.0.1")
}

// ---------------------------------------------------------------------------
// Commit 4 tests: Write/Close lifecycle
// ---------------------------------------------------------------------------

func TestWebhookOutput_WriteAfterClose(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte(`{"event":"after_close"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestWebhookOutput_CloseIdempotent(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestWebhookOutput_BufferOverflow_NonBlocking(t *testing.T) {
	// Slow server keeps the batch goroutine busy.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1, // flush immediately
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3, // tiny buffer
	}, metrics)
	require.NoError(t, err)

	// First event triggers flush (blocks on slow server).
	// Subsequent writes fill buffer and overflow.
	start := time.Now()
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}`))
	}
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond,
		"Write should not block on full buffer")

	require.NoError(t, out.Close())

	assert.Greater(t, metrics.getWebhookDrops(), 0,
		"RecordWebhookDrop should be called for overflow")
}

func TestWebhookOutput_ConcurrentWrites(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
		cfg.BufferSize = 1000
	})

	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = out.Write([]byte(`{"event":"concurrent"}`))
		}()
	}
	wg.Wait()
	// Close is handled by t.Cleanup in newTestWebhookOutput.
}
