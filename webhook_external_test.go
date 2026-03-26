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

// ---------------------------------------------------------------------------
// Commit 5 tests: HTTP POST, NDJSON, retry
// ---------------------------------------------------------------------------

func TestWebhookOutput_Delivery(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1000,             // won't trigger on size
		FlushInterval:      10 * time.Second, // won't trigger on timer
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, nil)
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
	_ = newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
		cfg.FlushInterval = 20 * time.Millisecond
	})

	// Wait for 2+ flush intervals with no events.
	time.Sleep(60 * time.Millisecond) //nolint:gocritic // intentional: testing absence of action

	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
		"empty batch should not trigger HTTP request")
}

func TestWebhookOutput_TimerResets_AfterBatchFlush(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
		cfg.BatchSize = 2
		cfg.FlushInterval = 200 * time.Millisecond
	})

	// 2 events → batch-size flush.
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
			out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	out := newTestWebhookOutput(t, srv.url(), func(cfg *audit.WebhookConfig) {
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
	metrics := newMockMetrics()
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		MaxRetries:         2,
		Timeout:            5 * time.Second,
		BufferSize:         100,
	}, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"exhaust"}`+"\n")))
	// Wait for retries to complete.
	time.Sleep(2 * time.Second)
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.getWebhookDrops(), 0,
		"RecordWebhookDrop should be called on retry exhaustion")
}

// ---------------------------------------------------------------------------
// Concurrent writes (Commit 4, moved here for organization)
// ---------------------------------------------------------------------------

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

	metrics := newMockMetrics()
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: false, // SSRF blocks 127.0.0.1
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            1 * time.Second,
		MaxRetries:         1,
		BufferSize:         10,
	}, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"ssrf"}`+"\n")))
	// Wait for the batch to be attempted and fail.
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, out.Close())

	// No requests should reach the server — SSRF blocked the dial.
	assert.Equal(t, 0, srv.requestCount(), "SSRF should block connection to loopback")
}

func TestWebhookOutput_RequestTimeout(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second) // slow server
		w.WriteHeader(200)
	})
	metrics := newMockMetrics()
	out, err := audit.NewWebhookOutput(&audit.WebhookConfig{
		URL:                srv.url(),
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      50 * time.Millisecond,
		Timeout:            100 * time.Millisecond, // very short
		MaxRetries:         1,
		BufferSize:         100,
	}, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"timeout"}`+"\n")))
	// Wait for timeout + retries.
	time.Sleep(1 * time.Second)
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.getWebhookDrops(), 0,
		"timed out request should result in dropped batch")
}

func TestWebhookBackoff(t *testing.T) {
	d0 := audit.WebhookBackoff(0)
	assert.GreaterOrEqual(t, d0, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d0, 100*time.Millisecond)          // 100ms * 1.0

	d1 := audit.WebhookBackoff(1)
	assert.GreaterOrEqual(t, d1, 100*time.Millisecond)
	assert.Less(t, d1, 200*time.Millisecond)

	// Should be capped at 5s.
	d20 := audit.WebhookBackoff(20)
	assert.LessOrEqual(t, d20, 5*time.Second)
}

func TestBuildNDJSON(t *testing.T) {
	events := [][]byte{
		[]byte(`{"a":1}` + "\n"),
		[]byte(`{"b":2}`), // missing newline — should be added
		[]byte(`{"c":3}` + "\n"),
	}
	result := audit.BuildNDJSON(events)
	lines := strings.Split(strings.TrimSpace(string(result)), "\n")
	assert.Len(t, lines, 3)
	for _, line := range lines {
		assert.True(t, json.Valid([]byte(line)), "each line should be valid JSON: %s", line)
	}
}

func TestBuildNDJSON_Empty(t *testing.T) {
	result := audit.BuildNDJSON(nil)
	assert.Empty(t, result)
}

func TestWebhookOutput_NoInsecureSkipVerify(t *testing.T) {
	data, err := os.ReadFile("webhook.go")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "InsecureSkipVerify: true",
		"InsecureSkipVerify must never be set to true")
}
