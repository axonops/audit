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

package webhook_test

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/tests/testhelper"
	"github.com/axonops/go-audit/webhook"
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
	requestCh chan struct{}
	requests  []*webhookCapturedRequest
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
func newTestWebhookOutput(t *testing.T, url string, opts ...func(*webhook.WebhookConfig)) *webhook.WebhookOutput {
	t.Helper()
	cfg := &webhook.WebhookConfig{
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
	out, err := webhook.NewWebhookOutput(cfg, nil, nil)
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
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewWebhookOutput_InvalidConfig(t *testing.T) {
	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{}, nil, nil)
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
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte(`{"event":"after_close"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestWebhookOutput_CloseIdempotent(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil, nil)
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
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1, // flush immediately
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3, // tiny buffer
	}, metrics, metrics)
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

	assert.Greater(t, metrics.GetWebhookDrops(), 0,
		"RecordWebhookDrop should be called for overflow")
}

// ---------------------------------------------------------------------------
// Commit 5 tests: HTTP POST, NDJSON, retry
// ---------------------------------------------------------------------------

func TestWebhookOutput_Delivery(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 3
	})

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"delivery_test"}`+"\n")))
	}
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)

	// Verify NDJSON: 3 lines, each valid JSON.
	lines := strings.Split(strings.TrimSpace(string(reqs[0].Body)), "\n")
	assert.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, json.Valid([]byte(line)), "each line should be valid JSON: %s", line)
	}
}

func TestWebhookOutput_ContentType_NDJSON(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"ct"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	assert.Equal(t, "application/x-ndjson", reqs[0].Headers.Get("Content-Type"))
}

func TestWebhookOutput_FlushInterval(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1000 // large, so only timer triggers
		cfg.FlushInterval = 50 * time.Millisecond
	})

	require.NoError(t, out.Write([]byte(`{"event":"timer"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)
	assert.Contains(t, string(reqs[0].Body), "timer")
}

func TestWebhookOutput_CloseFlushesRemaining(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1000,             // won't trigger on size
		FlushInterval:      10 * time.Second, // won't trigger on timer
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"close_flush"}`+"\n")))
	}

	// Close triggers final flush.
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	require.GreaterOrEqual(t, len(reqs), 1)
	assert.Contains(t, string(reqs[len(reqs)-1].Body), "close_flush")
}

func TestWebhookOutput_EmptyBatch_NoRequest(t *testing.T) {
	var requestCount int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(200)
	})
	_ = newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.FlushInterval = 20 * time.Millisecond
	})

	// Wait for 2+ flush intervals with no events.
	time.Sleep(60 * time.Millisecond) // intentional: testing absence of action

	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
		"empty batch should not trigger HTTP request")
}

func TestWebhookOutput_TimerResets_AfterBatchFlush(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 2
		cfg.FlushInterval = 200 * time.Millisecond
	})

	// 2 events -> batch-size flush.
	require.NoError(t, out.Write([]byte(`{"n":1}`+"\n")))
	require.NoError(t, out.Write([]byte(`{"n":2}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))

	// 1 more event immediately after flush.
	require.NoError(t, out.Write([]byte(`{"n":3}`+"\n")))

	// Timer should reset — partial batch flushes at ~200ms from now.
	require.True(t, srv.waitForRequests(2, 1*time.Second),
		"partial batch should flush after reset FlushInterval")
	require.NoError(t, out.Close())
}

func TestWebhookOutput_CustomHeaders(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1
		cfg.Headers = map[string]string{
			"Authorization": "Bearer test-token-123",
			"X-Custom":      "custom-value",
		}
	})

	require.NoError(t, out.Write([]byte(`{"event":"headers"}`+"\n")))
	require.True(t, srv.waitForRequests(1, 2*time.Second))
	require.NoError(t, out.Close())

	reqs := srv.getRequests()
	assert.Equal(t, "Bearer test-token-123", reqs[0].Headers.Get("Authorization"))
	assert.Equal(t, "custom-value", reqs[0].Headers.Get("X-Custom"))
}

func TestWebhookOutput_Retry_503ThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1
		cfg.MaxRetries = 5
	})

	require.NoError(t, out.Write([]byte(`{"event":"retry"}`+"\n")))
	require.True(t, srv.waitForRequests(3, 10*time.Second))
	require.NoError(t, out.Close())

	assert.Equal(t, int32(3), attempts.Load())
}

func TestWebhookOutput_NoRetry_4xx(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var attempts atomic.Int32
			srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				attempts.Add(1)
				w.WriteHeader(code)
			})
			out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
				cfg.BatchSize = 1
				cfg.MaxRetries = 3
			})

			require.NoError(t, out.Write([]byte(`{"event":"no_retry"}`+"\n")))
			require.True(t, srv.waitForRequests(1, 2*time.Second))
			require.NoError(t, out.Close())

			assert.Equal(t, int32(1), attempts.Load(), "%d should not trigger retry", code)
		})
	}
}

func TestWebhookOutput_Retry_429(t *testing.T) {
	var attempts atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"429"}`+"\n")))
	require.True(t, srv.waitForRequests(2, 10*time.Second))
	require.NoError(t, out.Close())

	assert.Equal(t, int32(2), attempts.Load())
}

func TestWebhookOutput_Redirect_Rejected(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/other")
		w.WriteHeader(301)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BatchSize = 1
	})

	require.NoError(t, out.Write([]byte(`{"event":"redirect"}`+"\n")))
	require.NoError(t, out.Close())

	// Redirect is non-retryable — at most 1 request.
	assert.LessOrEqual(t, srv.requestCount(), 1)
}

func TestWebhookOutput_RetryExhausted_Metrics(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		MaxRetries:         2,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"exhaust"}`+"\n")))
	// Close blocks until batch goroutine exits (retries complete or cancelled).
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.GetWebhookDrops(), 0,
		"RecordWebhookDrop should be called on retry exhaustion")
}

// ---------------------------------------------------------------------------
// Concurrent writes (Commit 4, moved here for organization)
// ---------------------------------------------------------------------------

func TestWebhookOutput_ConcurrentWrites(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *webhook.WebhookConfig) {
		cfg.BufferSize = 1000
	})

	var wg sync.WaitGroup
	const goroutines = 50
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = out.Write([]byte(`{"event":"concurrent"}` + "\n"))
		}()
	}
	wg.Wait()
	// Close is handled by t.Cleanup in newTestWebhookOutput.
}

// ---------------------------------------------------------------------------
// Commit 7 tests: Edge cases, SSRF enforcement, backoff, NDJSON
// ---------------------------------------------------------------------------

func TestWebhookOutput_WriteNil(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	assert.NoError(t, out.Write(nil), "Write(nil) should not panic or error")
}

func TestWebhookOutput_WriteEmpty(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url())
	assert.NoError(t, out.Write([]byte{}), "Write([]byte{}) should not panic or error")
}

func TestWebhookOutput_SSRFBlocked(t *testing.T) {
	// httptest server at 127.0.0.1. With AllowPrivateRanges=false,
	// SSRF check blocks loopback. Events should be dropped.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: false, // SSRF blocks 127.0.0.1
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, metrics, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"ssrf"}`+"\n")))
	// Close blocks until batch goroutine exits (SSRF failure completes).
	require.NoError(t, out.Close())

	// No requests should reach the server — SSRF blocked the dial.
	assert.Equal(t, 0, srv.requestCount(), "SSRF should block connection to loopback")
}

func TestWebhookOutput_RequestTimeout(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second) // slow server
		w.WriteHeader(200)
	})
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond, // very short
		MaxRetries:         1,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"timeout"}`+"\n")))
	// Close blocks until batch goroutine exits (timeout + retries complete).
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.GetWebhookDrops(), 0,
		"timed out request should result in dropped batch")
}

func TestWebhookBackoff(t *testing.T) {
	d0 := webhook.WebhookBackoff(0)
	assert.GreaterOrEqual(t, d0, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d0, 100*time.Millisecond)          // 100ms * 1.0

	d1 := webhook.WebhookBackoff(1)
	assert.GreaterOrEqual(t, d1, 100*time.Millisecond)
	assert.Less(t, d1, 200*time.Millisecond)

	// Should be capped at 5s.
	d20 := webhook.WebhookBackoff(20)
	assert.LessOrEqual(t, d20, 5*time.Second)
}

func TestBuildNDJSON(t *testing.T) {
	events := [][]byte{
		[]byte(`{"a":1}` + "\n"),
		[]byte(`{"b":2}`), // missing newline — should be added
		[]byte(`{"c":3}` + "\n"),
	}
	result := webhook.BuildNDJSON(events)
	lines := strings.Split(strings.TrimSpace(string(result)), "\n")
	assert.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, json.Valid([]byte(line)), "each line should be valid JSON: %s", line)
	}
}

func TestBuildNDJSON_Empty(t *testing.T) {
	result := webhook.BuildNDJSON(nil)
	assert.Empty(t, result)
}

func TestNewWebhookOutput_EmbeddedCredentials_Rejected(t *testing.T) {
	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL: "https://user:pass@example.com/webhook",
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not contain credentials")
}

func TestNewWebhookOutput_HeaderValueCRLF_Rejected(t *testing.T) {
	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:     "https://example.com/webhook",
		Headers: map[string]string{"X-Custom": "val\r\nEvil: injected"},
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestNewWebhookOutput_TLSCA_NonexistentFile(t *testing.T) {
	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:   "https://example.com/webhook",
		TLSCA: "/nonexistent/ca.pem",
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca certificate")
}

func TestNewWebhookOutput_TLSCA_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := dir + "/bad-ca.pem"
	require.NoError(t, os.WriteFile(badCA, []byte("not a pem"), 0o600))

	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:   "https://example.com/webhook",
		TLSCA: badCA,
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse ca certificate")
}

func TestNewWebhookOutput_TLSCert_NonexistentFile(t *testing.T) {
	_, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:     "https://example.com/webhook",
		TLSCert: "/nonexistent/cert.pem",
		TLSKey:  "/nonexistent/key.pem",
	}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client certificate")
}

func TestWebhookOutput_ConcurrentWriteAndClose(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	// Start writers and close concurrently — exercise the race detector.
	var wg sync.WaitGroup
	wg.Add(21) // 20 writers + 1 closer
	for range 20 {
		go func() {
			defer wg.Done()
			_ = out.Write([]byte(`{"event":"race"}` + "\n"))
		}()
	}
	go func() {
		defer wg.Done()
		_ = out.Close()
	}()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TLSPolicy integration
// ---------------------------------------------------------------------------

func TestWebhookOutput_TLSPolicy_NilPreservesBehaviour(t *testing.T) {
	// Nil TLSPolicy should behave identically to the previous hardcoded
	// TLS 1.3 default.
	certs := testhelper.GenerateTestCerts(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		TLSPolicy:          nil, // explicitly nil
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"nil_policy"}`+"\n")))
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLSPolicy_AllowTLS12(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)
	// Server accepts TLS 1.2.
	certs.TLSCfg.MinVersion = tls.VersionTLS12

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:   srv.URL,
		TLSCA: certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12: true,
		},
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls12_policy"}`+"\n")))
	require.NoError(t, out.Close())
}

func TestWebhookOutput_NoInsecureSkipVerify(t *testing.T) {
	data, err := os.ReadFile("webhook.go")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "InsecureSkipVerify: true",
		"InsecureSkipVerify must never be set to true")
}

// ---------------------------------------------------------------------------
// TLS tests (reuses generateTestCerts from testhelper)
// ---------------------------------------------------------------------------

func TestWebhookOutput_TLS_WithCustomCA(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)

	// Start an HTTPS server with the test CA's cert.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls_test"}`+"\n")))
	// Close flushes the final batch.
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLS_MTLS(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)
	// Require client cert.
	certs.TLSCfg.ClientAuth = tls.RequireAndVerifyClientCert

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.URL,
		TLSCA:              certs.CAPath,
		TLSCert:            certs.ClientCert,
		TLSKey:             certs.ClientKey,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test"}`+"\n")))
	require.NoError(t, out.Close())
}

func TestWebhookOutput_TLS_WrongCA_Rejected(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = certs.TLSCfg
	srv.StartTLS()
	t.Cleanup(func() { srv.Close() })

	// Generate a DIFFERENT CA — the server cert won't be trusted.
	wrongCerts := testhelper.GenerateTestCerts(t)

	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.URL,
		TLSCA:              wrongCerts.CAPath, // wrong CA
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            2 * time.Second,
		MaxRetries:         1,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"wrong_ca"}`+"\n")))

	// Poll for the TLS failure to be recorded as a webhook drop.
	// This replaces time.Sleep synchronisation with an observable
	// condition, per CLAUDE.md requirements.
	require.Eventually(t, func() bool {
		return metrics.GetWebhookDrops() > 0
	}, 5*time.Second, 50*time.Millisecond,
		"wrong CA should cause TLS failure and event drop")

	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Delivery metrics tests (#53)
// ---------------------------------------------------------------------------

func TestWebhookOutput_DeliveryMetrics_SuccessOnHTTP200(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          3,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, out.Write([]byte(`{"event":"metric_test"}`+"\n")))
	}
	// Poll the success metric as the synchronisation signal — this
	// ensures the batch goroutine has fully processed the HTTP response
	// and recorded metrics before we close.
	name := out.Name()
	require.Eventually(t, func() bool {
		return metrics.GetEventCount(name, "success") == 3
	}, 5*time.Second, 10*time.Millisecond,
		"RecordEvent(success) should be called once per delivered event")

	require.NoError(t, out.Close())

	assert.Equal(t, 0, metrics.GetEventCount(name, "error"),
		"RecordEvent(error) should not be called on success")
}

func TestWebhookOutput_DeliveryMetrics_ErrorOnRetryExhausted(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	})
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          2,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	for range 2 {
		require.NoError(t, out.Write([]byte(`{"event":"drop_test"}`+"\n")))
	}
	require.NoError(t, out.Close())

	name := out.Name()
	assert.Equal(t, 2, metrics.GetEventCount(name, "error"),
		"RecordEvent(error) should be called once per dropped event")
	assert.Equal(t, 0, metrics.GetEventCount(name, "success"),
		"RecordEvent(success) should not be called when retries exhausted")
}

func TestWebhookOutput_DeliveryMetrics_ErrorOnBufferOverflow(t *testing.T) {
	// Slow server to keep batch goroutine busy.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	metrics := testhelper.NewMockMetrics()
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3,
	}, metrics, metrics)
	require.NoError(t, err)

	// Fill buffer — overflow events get RecordEvent(error).
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}` + "\n"))
	}
	require.NoError(t, out.Close())

	name := out.Name()
	assert.Greater(t, metrics.GetEventCount(name, "error"), 0,
		"RecordEvent(error) should be called for buffer overflow drops")
}

func TestWebhookOutput_CoreMetrics_SkippedForDeliveryReporter(t *testing.T) {
	// Verify that the core writeToOutput does NOT call RecordEvent
	// for webhook outputs (they report their own delivery).
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	metrics := testhelper.NewMockMetrics()

	webhookOut, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics, metrics)
	require.NoError(t, err)

	// Create a logger with the webhook output and metrics.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(webhookOut, &audit.EventRoute{}, nil),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))

	// Wait for the batch goroutine to finish delivery and record the
	// success metric. Polling the metric is the correct synchronisation
	// signal — waitForRequests only proves the HTTP handler fired, not
	// that the client has read the response and recorded metrics.
	name := webhookOut.Name()
	require.Eventually(t, func() bool {
		return metrics.GetEventCount(name, "success") == 1
	}, 5*time.Second, 10*time.Millisecond,
		"webhook should report delivery success from batch goroutine")

	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// Nil WebhookMetrics (#54)
// ---------------------------------------------------------------------------

// coreOnlyMetrics implements audit.Metrics but not webhook.Metrics.
type coreOnlyMetrics struct {
	events map[string]int
	mu     sync.Mutex
}

func (m *coreOnlyMetrics) RecordEvent(output, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[output+":"+status]++
}

func (m *coreOnlyMetrics) RecordOutputError(_ string)        {}
func (m *coreOnlyMetrics) RecordOutputFiltered(_ string)     {}
func (m *coreOnlyMetrics) RecordValidationError(_ string)    {}
func (m *coreOnlyMetrics) RecordFiltered(_ string)           {}
func (m *coreOnlyMetrics) RecordSerializationError(_ string) {}
func (m *coreOnlyMetrics) RecordBufferDrop()                 {}

var _ audit.Metrics = (*coreOnlyMetrics)(nil)

func TestWebhookOutput_NilWebhookMetrics(t *testing.T) {
	// Slow server to fill the buffer.
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	})
	m := &coreOnlyMetrics{events: make(map[string]int)}
	out, err := webhook.NewWebhookOutput(&webhook.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         3,
	}, m, nil) // Metrics but no WebhookMetrics
	require.NoError(t, err)

	// Overflow the buffer — should not panic despite nil WebhookMetrics.
	for range 15 {
		_ = out.Write([]byte(`{"event":"overflow"}` + "\n"))
	}
	require.NoError(t, out.Close())

	// RecordEvent should still have been called for errors.
	m.mu.Lock()
	errorCount := m.events[out.Name()+":error"]
	m.mu.Unlock()
	assert.Greater(t, errorCount, 0, "RecordEvent(error) should be called for drops")
}
