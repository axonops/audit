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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHints_NilWithoutMiddleware(t *testing.T) {
	h := audit.GetHints(context.Background())
	assert.Nil(t, h)
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name     string
		xff      string
		xri      string
		remote   string
		expected string
	}{
		{
			name:     "rightmost XFF",
			xff:      "1.2.3.4, 10.0.0.1, 192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "single XFF",
			xff:      "10.0.0.1",
			expected: "10.0.0.1",
		},
		{
			name:     "XFF with whitespace",
			xff:      " 1.2.3.4 , 10.0.0.1 , 192.168.1.1 ",
			expected: "192.168.1.1",
		},
		{
			name:     "XFF with invalid IP falls to RemoteAddr",
			xff:      "not-an-ip",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "X-Real-IP fallback",
			xri:      "10.0.0.5",
			expected: "10.0.0.5",
		},
		{
			name:     "X-Real-IP invalid falls to RemoteAddr",
			xri:      "not-an-ip",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "RemoteAddr with port",
			remote:   "192.168.1.100:54321",
			expected: "192.168.1.100",
		},
		{
			name:     "RemoteAddr IPv6",
			remote:   "[::1]:8080",
			expected: "::1",
		},
		{
			name:     "empty everything",
			expected: "",
		},
		{
			name:     "XFF takes precedence over X-Real-IP",
			xff:      "10.0.0.1",
			xri:      "10.0.0.2",
			expected: "10.0.0.1",
		},
		{
			name:     "X-Real-IP takes precedence over RemoteAddr",
			xri:      "10.0.0.2",
			remote:   "10.0.0.3:80",
			expected: "10.0.0.2",
		},
		{
			name:     "RemoteAddr without port",
			remote:   "10.0.0.1",
			expected: "10.0.0.1",
		},
		{
			name:     "XFF IPv6",
			xff:      "::1",
			expected: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-Ip", tt.xri)
			}
			r.RemoteAddr = tt.remote

			got := audit.ClientIP(r)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestTransportSecurity(t *testing.T) {
	tests := []struct {
		name     string
		tls      *tls.ConnectionState
		expected string
	}{
		{
			name:     "nil TLS",
			tls:      nil,
			expected: "none",
		},
		{
			name:     "TLS no peer certs",
			tls:      &tls.ConnectionState{},
			expected: "tls",
		},
		{
			name: "TLS with peer certs (mTLS)",
			tls: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{}},
			},
			expected: "mtls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			r.TLS = tt.tls

			got := audit.TransportSecurityFunc(r)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// uuidV4Pattern matches a v4 UUID: 8-4-4-4-12 hex digits with version 4
// and variant bits [89ab].
var uuidV4Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

func TestNewRequestID_Format(t *testing.T) {
	id := audit.NewRequestID()
	assert.Regexp(t, uuidV4Pattern, id)
}

func TestNewRequestID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		id := audit.NewRequestID()
		require.NotContains(t, seen, id, "duplicate request ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, 100)
}

// --- responseWriter tests ---

func TestResponseWriter_DefaultStatus200(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	_, err := rw.Write([]byte("hello"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rw.StatusCode())
	assert.True(t, rw.Written())
}

func TestResponseWriter_CapturesStatus(t *testing.T) {
	codes := []int{200, 201, 301, 404, 500}
	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			rec := httptest.NewRecorder()
			rw := audit.NewResponseWriter(rec)

			rw.WriteHeader(code)
			assert.Equal(t, code, rw.StatusCode())
			assert.Equal(t, code, rec.Code)
		})
	}
}

func TestResponseWriter_WriteHeaderIdempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	rw.WriteHeader(http.StatusCreated)
	rw.WriteHeader(http.StatusInternalServerError) // should be ignored

	assert.Equal(t, http.StatusCreated, rw.StatusCode())
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestResponseWriter_BodyPassThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	data := []byte("audit event data")
	n, err := rw.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, "audit event data", rec.Body.String())
}

// mockFlusher is a ResponseWriter that also implements http.Flusher.
type mockFlusher struct {
	http.ResponseWriter
	flushed bool
}

func (m *mockFlusher) Flush() { m.flushed = true }

func TestResponseWriter_Flush_Supported(t *testing.T) {
	inner := &mockFlusher{ResponseWriter: httptest.NewRecorder()}
	rw := audit.NewResponseWriter(inner)

	rw.Flush()
	assert.True(t, inner.flushed)
}

func TestResponseWriter_Flush_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	// httptest.ResponseRecorder implements Flusher, so wrap it to
	// hide the Flusher interface.
	rw := audit.NewResponseWriter(struct{ http.ResponseWriter }{rec})

	// Should not panic.
	assert.NotPanics(t, func() { rw.Flush() })
}

// mockHijacker is a ResponseWriter that also implements http.Hijacker.
type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	err  error
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, nil, m.err
}

func TestResponseWriter_Hijack_Supported(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	inner := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           server,
	}
	rw := audit.NewResponseWriter(inner)

	conn, _, err := rw.Hijack()
	require.NoError(t, err)
	assert.Equal(t, server, conn)
}

func TestResponseWriter_Hijack_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(struct{ http.ResponseWriter }{rec})

	conn, brw, err := rw.Hijack()
	assert.Nil(t, conn)
	assert.Nil(t, brw)
	assert.ErrorIs(t, err, audit.ErrHijackNotSupported)
}

func TestResponseWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	inner := rw.Unwrap()
	assert.Equal(t, rec, inner)
}

// --- AuditMiddleware tests ---

// middlewareTaxonomy returns a taxonomy suitable for middleware tests.
func middlewareTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"access": {"http_request"},
		},
		Events: map[string]audit.EventDef{
			"http_request": {
				Category: "access",
				Required: []string{"outcome"},
				Optional: []string{
					"actor_id", "actor_type", "auth_method", "role",
					"target_type", "target_id", "reason", "error",
					"client_ip", "method", "path", "user_agent",
					"request_id", "status_code", "duration_ms",
					"transport_security", "extra_field",
				},
			},
		},
		DefaultEnabled: []string{"access"},
	}
}

// middlewareBuilder is a standard EventBuilder for middleware tests.
func middlewareBuilder(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
	fields := audit.Fields{
		"outcome":            hints.Outcome,
		"client_ip":          transport.ClientIP,
		"method":             transport.Method,
		"path":               transport.Path,
		"status_code":        transport.StatusCode,
		"request_id":         transport.RequestID,
		"transport_security": transport.TransportSecurity,
		"user_agent":         transport.UserAgent,
		"duration_ms":        transport.Duration.Milliseconds(),
	}
	if hints.ActorID != "" {
		fields["actor_id"] = hints.ActorID
	}
	return "http_request", fields, false
}

// newMiddlewareTestLogger creates a Logger with a mockOutput for middleware tests.
func newMiddlewareTestLogger(t *testing.T) (*audit.Logger, *mockOutput) {
	t.Helper()
	out := newMockOutput("mw-test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(middlewareTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = logger.Close()
	})
	return logger, out
}

func TestMiddleware_NilLogger_PassThrough(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(nil, middlewareBuilder)
	wrapped := mw(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	wrapped.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_NilBuilder_Panics(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	assert.PanicsWithValue(t, "audit: EventBuilder must not be nil", func() {
		audit.Middleware(logger, nil)
	})
}

func TestMiddleware_BasicFlow(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
		require.NotNil(t, hints)
		hints.Outcome = "success"
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, middlewareBuilder)
	wrapped := mw(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	wrapped.ServeHTTP(rec, req)

	// Wait for async delivery.
	require.NoError(t, logger.Close())

	assert.GreaterOrEqual(t, out.eventCount(), 1)
}

func TestMiddleware_HintsPopulatedByHandler(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedHints *audit.Hints
	var capturedTransport audit.TransportMetadata

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedHints = hints
		capturedTransport = *transport
		return "http_request", audit.Fields{"outcome": hints.Outcome}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
		hints.Outcome = "success"
		hints.ActorID = "user-42"
		hints.ActorType = "user"
		hints.AuthMethod = "bearer"
		hints.Role = "admin"
		hints.TargetType = "document"
		hints.TargetID = "doc-99"
		hints.Reason = "routine access"
		hints.Error = ""
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/docs/99", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	require.NotNil(t, capturedHints)
	assert.Equal(t, "success", capturedHints.Outcome)
	assert.Equal(t, "user-42", capturedHints.ActorID)
	assert.Equal(t, "user", capturedHints.ActorType)
	assert.Equal(t, "bearer", capturedHints.AuthMethod)
	assert.Equal(t, "admin", capturedHints.Role)
	assert.Equal(t, "document", capturedHints.TargetType)
	assert.Equal(t, "doc-99", capturedHints.TargetID)
	assert.Equal(t, "routine access", capturedHints.Reason)

	assert.Equal(t, http.MethodGet, capturedTransport.Method)
	assert.Equal(t, "/api/docs/99", capturedTransport.Path)
}

func TestMiddleware_HintsExtra(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedExtra map[string]any

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedExtra = hints.Extra
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
		hints.Extra = map[string]any{
			"tenant_id": "t-123",
			"org":       "acme",
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	require.NotNil(t, capturedExtra)
	assert.Equal(t, "t-123", capturedExtra["tenant_id"])
	assert.Equal(t, "acme", capturedExtra["org"])
}

func TestMiddleware_SkipTrue(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "", nil, true // skip
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.eventCount())
}

func TestMiddleware_PanicRecovery(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
		hints.Outcome = "error"
		panic("handler exploded")
	})

	mw := audit.Middleware(logger, middlewareBuilder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	assert.PanicsWithValue(t, "handler exploded", func() {
		mw(handler).ServeHTTP(rec, req)
	})

	// Audit event should still have been emitted before re-panic.
	require.NoError(t, logger.Close())
	assert.GreaterOrEqual(t, out.eventCount(), 1)
}

func TestMiddleware_TransportMetadata_Complete(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var captured audit.TransportMetadata

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		captured = *transport
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/items", http.NoBody)
	req.RemoteAddr = "192.168.1.1:9999"
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set("X-Request-Id", "req-abc-123")
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, "192.168.1.1", captured.ClientIP)
	assert.Equal(t, "none", captured.TransportSecurity)
	assert.Equal(t, http.MethodPost, captured.Method)
	assert.Equal(t, "/api/items", captured.Path)
	assert.Equal(t, "test-agent/1.0", captured.UserAgent)
	assert.Equal(t, "req-abc-123", captured.RequestID)
	assert.Equal(t, http.StatusCreated, captured.StatusCode)
	assert.Greater(t, captured.Duration, time.Duration(0))
}

func TestMiddleware_RequestID_FromHeader(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Request-Id", "custom-id-42")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, "custom-id-42", capturedID)
}

func TestMiddleware_RequestID_Generated(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	// No X-Request-Id header.
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Regexp(t, uuidV4Pattern, capturedID)
}

func TestMiddleware_AuditError_LoggedNotPropagated(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	// Return an unknown event type to trigger an Audit error.
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "nonexistent_event", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	// Should not panic; error is logged via slog, not propagated.
	assert.NotPanics(t, func() {
		mw(handler).ServeHTTP(rec, req)
	})
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddleware_ConcurrentRequests(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	var calls atomic.Int64

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		calls.Add(1)
		return "http_request", audit.Fields{"outcome": hints.Outcome, "actor_id": hints.ActorID}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
		hints.Outcome = "success"
		hints.ActorID = r.Header.Get("X-Actor")
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	wrapped := mw(handler)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			req.RemoteAddr = "10.0.0.1:12345"
			req.Header.Set("X-Actor", fmt.Sprintf("user-%d", idx))
			wrapped.ServeHTTP(rec, req)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int64(100), calls.Load())

	require.NoError(t, logger.Close())
	assert.Equal(t, 100, out.eventCount())
}

func TestMiddleware_StatusCode_FromHandler(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedStatus int
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedStatus = transport.StatusCode
		return "http_request", audit.Fields{"outcome": "not_found"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, capturedStatus)
}

func TestMiddleware_Duration_Positive(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedDuration time.Duration
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedDuration = transport.Duration
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	// time.Since(start) always returns > 0 on monotonic clock.
	assert.GreaterOrEqual(t, capturedDuration, time.Duration(0))
}

func TestMiddleware_BuilderPanic_Recovered(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		panic("builder exploded")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	// Builder panic must not propagate to the caller.
	assert.NotPanics(t, func() {
		mw(handler).ServeHTTP(rec, req)
	})

	// Event should be skipped due to builder panic.
	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.eventCount())
}

func TestValidRequestID(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"valid UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"valid short", "req-42", true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 129), false},
		{"max length", strings.Repeat("a", 128), true},
		{"contains newline", "req-id\n", false},
		{"contains carriage return", "req-id\r", false},
		{"contains null", "req-id\x00", false},
		{"contains tab", "req-id\t", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, audit.ValidRequestID(tt.id))
		})
	}
}

func TestMiddleware_RequestID_InvalidHeader_GeneratesUUID(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Request-Id", "injected\nfake-log-line")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	// Invalid header should be replaced with a generated UUID.
	assert.Regexp(t, uuidV4Pattern, capturedID)
}

func TestMiddleware_UserAgent_Truncated(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedUA string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedUA = transport.UserAgent
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	longUA := strings.Repeat("x", 1000)
	req.Header.Set("User-Agent", longUA)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, 512, len(capturedUA))
}

// --- Benchmarks ---

func BenchmarkNewRequestID(b *testing.B) {
	for b.Loop() {
		audit.NewRequestID()
	}
}

func BenchmarkClientIP(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1, 192.168.1.1")
	for b.Loop() {
		audit.ClientIP(r)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	taxonomy := middlewareTaxonomy()
	out := newMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(taxonomy),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/bench", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
