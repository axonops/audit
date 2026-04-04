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

package loki_test

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/axonops/go-audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// HTTP delivery — success paths
// ---------------------------------------------------------------------------

func TestHTTP_Success_204(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusNoContent) // 204
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"success_204"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0, "should record a flush on 204")
	assert.Equal(t, 0, metrics.drops(), "no drops on 204")
	assert.Equal(t, int32(1), requestCount.Load(), "exactly 1 request for success")
}

func TestHTTP_Success_200(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // 200
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"success_200"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0, "200 should be treated as success")
}

// ---------------------------------------------------------------------------
// HTTP delivery — retry paths
// ---------------------------------------------------------------------------

func TestHTTP_429_Retried(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests) // 429 on first attempt
			return
		}
		w.WriteHeader(http.StatusNoContent) // 204 on retry
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.MaxRetries = 3

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"retry_429"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0, "should succeed after retry")
	assert.Equal(t, int32(2), requestCount.Load(), "should make 2 requests (1 fail + 1 success)")
}

func TestHTTP_5xx_Retried(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError) // 500
			return
		}
		w.WriteHeader(http.StatusNoContent) // 204
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.MaxRetries = 5

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"retry_5xx"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0, "should succeed after retries")
	assert.Equal(t, int32(3), requestCount.Load(), "2 failures + 1 success")
}

func TestHTTP_RetriesExhausted_Drops(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // always 500
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.MaxRetries = 2

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"exhausted"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.drops(), 0, "should drop when retries exhausted")
}

// ---------------------------------------------------------------------------
// HTTP delivery — non-retryable errors
// ---------------------------------------------------------------------------

func TestHTTP_4xx_NotRetried(t *testing.T) {
	t.Parallel()

	codes := []int{400, 401, 403, 404, 405, 413, 422}
	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()

			var requestCount atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requestCount.Add(1)
				w.WriteHeader(code)
			}))
			t.Cleanup(srv.Close)

			metrics := &testLokiMetrics{}
			cfg := validConfigWithURL(srv.URL)
			cfg.MaxRetries = 3

			out, err := loki.New(cfg, nil, metrics)
			require.NoError(t, err)

			require.NoError(t, out.Write([]byte(`{"event":"no_retry"}`)))
			require.NoError(t, out.Close())

			assert.Greater(t, metrics.drops(), 0, "%d should drop immediately", code)
			assert.Equal(t, int32(1), requestCount.Load(),
				"%d should not retry (exactly 1 request)", code)
		})
	}
}

// ---------------------------------------------------------------------------
// Auth headers
// ---------------------------------------------------------------------------

func TestHTTP_BasicAuth_Header(t *testing.T) {
	t.Parallel()

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.BasicAuth = &loki.BasicAuth{Username: "alice", Password: "secret"}

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"auth"}`)))
	require.NoError(t, out.Close())

	assert.Contains(t, capturedAuth, "Basic ",
		"BasicAuth should set Authorization: Basic header")
}

func TestHTTP_BearerToken_Header(t *testing.T) {
	t.Parallel()

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.BearerToken = "test-token-123"

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"bearer"}`)))
	require.NoError(t, out.Close())

	assert.Equal(t, "Bearer test-token-123", capturedAuth)
}

func TestHTTP_TenantID_Header(t *testing.T) {
	t.Parallel()

	var capturedTenant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = r.Header.Get("X-Scope-OrgID")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.TenantID = "my-tenant"

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tenant"}`)))
	require.NoError(t, out.Close())

	assert.Equal(t, "my-tenant", capturedTenant)
}

func TestHTTP_NoAuth_NoHeader(t *testing.T) {
	t.Parallel()

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"no_auth"}`)))
	require.NoError(t, out.Close())

	assert.Empty(t, capturedAuth, "no auth configured should mean no Authorization header")
}

// ---------------------------------------------------------------------------
// Content headers
// ---------------------------------------------------------------------------

func TestHTTP_ContentType_JSON(t *testing.T) {
	t.Parallel()

	var capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.Compress = false

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"ct"}`)))
	require.NoError(t, out.Close())

	assert.Equal(t, "application/json", capturedCT)
}

func TestHTTP_ContentEncoding_Gzip(t *testing.T) {
	t.Parallel()

	var capturedCE string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCE = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.Compress = true

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"gzip"}`)))
	require.NoError(t, out.Close())

	assert.Equal(t, "gzip", capturedCE)
}

func TestHTTP_CompressedBody_ValidJSON(t *testing.T) {
	t.Parallel()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.Compress = true

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"validate_gzip"}`)))
	require.NoError(t, out.Close())

	// Decompress and verify valid JSON.
	require.GreaterOrEqual(t, len(capturedBody), 2)
	gr, err := gzip.NewReader(bytesReader(capturedBody))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(gr)
	require.NoError(t, err)
	require.NoError(t, gr.Close())

	var p pushPayload
	require.NoError(t, json.Unmarshal(decompressed, &p),
		"decompressed body should be valid Loki push JSON: %s", string(decompressed))
}

// ---------------------------------------------------------------------------
// Retry-After
// ---------------------------------------------------------------------------

func TestHTTP_RetryAfter_Respected(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := requestCount.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.MaxRetries = 3

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"retry_after"}`)))
	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0, "should succeed after respecting Retry-After")
}

// ---------------------------------------------------------------------------
// Custom headers
// ---------------------------------------------------------------------------

func TestHTTP_CustomHeaders(t *testing.T) {
	t.Parallel()

	var capturedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfigWithURL(srv.URL)
	cfg.Headers = map[string]string{"X-Custom-Header": "test-value"}

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"custom_header"}`)))
	require.NoError(t, out.Close())

	assert.Equal(t, "test-value", capturedHeader)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type bytesReaderHelper struct{ data []byte }

func (r *bytesReaderHelper) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func bytesReader(data []byte) io.Reader {
	return &bytesReaderHelper{data: append([]byte(nil), data...)}
}
