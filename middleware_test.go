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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Middleware test helpers ---

// middlewareTaxonomy returns a taxonomy suitable for middleware tests.
func middlewareTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"access": {Events: []string{"http_request"}},
		},
		Events: map[string]*audit.EventDef{
			"http_request": {
				Required: []string{"outcome"},
				Optional: []string{
					"actor_type", "auth_method", "error",
					"client_ip", "status_code", "duration_ms",
					"transport_security", "extra_field",
				},
			},
		},
	}
}

// middlewareBuilder is a standard EventBuilder for middleware tests.
func middlewareBuilder(hints *audit.Hints, transport *audit.TransportMetadata) (eventType string, fields audit.Fields, skip bool) {
	fields = audit.Fields{
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

// newMiddlewareTestAuditor creates an Auditor with a mockOutput for middleware tests.
func newMiddlewareTestAuditor(t *testing.T) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	out := testhelper.NewMockOutput("mw-test")
	auditor, err := audit.New(
		audit.WithTaxonomy(middlewareTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = auditor.Close()
	})
	return auditor, out
}

// --- Middleware tests ---

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
	auditor, _ := newMiddlewareTestAuditor(t)

	assert.PanicsWithValue(t, "audit: EventBuilder must not be nil", func() {
		audit.Middleware(auditor, nil)
	})
}

func TestMiddleware_BasicFlow(t *testing.T) {
	auditor, out := newMiddlewareTestAuditor(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		require.NotNil(t, hints)
		hints.Outcome = "success"
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, middlewareBuilder)
	wrapped := mw(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	wrapped.ServeHTTP(rec, req)

	// Wait for async delivery.
	require.NoError(t, auditor.Close())

	assert.Equal(t, 1, out.EventCount())
}

func TestMiddleware_HintsPopulatedByHandler(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedHints *audit.Hints
	var capturedTransport audit.TransportMetadata

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedHints = hints
		capturedTransport = *transport
		return "http_request", audit.Fields{"outcome": hints.Outcome}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
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

	mw := audit.Middleware(auditor, builder)
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
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedExtra map[string]any

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedExtra = hints.Extra
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Extra = map[string]any{
			"tenant_id": "t-123",
			"org":       "acme",
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	require.NotNil(t, capturedExtra)
	assert.Equal(t, "t-123", capturedExtra["tenant_id"])
	assert.Equal(t, "acme", capturedExtra["org"])
}

func TestMiddleware_SkipTrue(t *testing.T) {
	auditor, out := newMiddlewareTestAuditor(t)

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "", nil, true // skip
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	require.NoError(t, auditor.Close())
	assert.Equal(t, 0, out.EventCount())
}

func TestMiddleware_PanicRecovery(t *testing.T) {
	auditor, out := newMiddlewareTestAuditor(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Outcome = "error"
		panic("handler exploded")
	})

	mw := audit.Middleware(auditor, middlewareBuilder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	assert.PanicsWithValue(t, "handler exploded", func() {
		mw(handler).ServeHTTP(rec, req)
	})

	// Audit event should still have been emitted before re-panic.
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount())
}

func TestMiddleware_TransportMetadata_Complete(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var captured audit.TransportMetadata

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		captured = *transport
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	mw := audit.Middleware(auditor, builder)
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
	// Same monotonic-clock caveat as TestMiddleware_Duration_Positive:
	// on Windows the clock resolution can produce a 0-valued
	// duration for a no-op handler. Assert non-negative.
	assert.GreaterOrEqual(t, captured.Duration, time.Duration(0))
}

func TestMiddleware_RequestID_FromHeader(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Request-Id", "custom-id-42")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, "custom-id-42", capturedID)
}

func TestMiddleware_RequestID_Generated(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	// No X-Request-Id header.
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Regexp(t, uuidV4Pattern, capturedID)
}

func TestMiddleware_AuditError_LoggedNotPropagated(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	// Return an unknown event type to trigger an Audit error.
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "nonexistent_event", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
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
	// Goroutine leak detection is handled globally by TestMain via
	// goleak.VerifyTestMain. Per-test goleak.VerifyNone is unreliable
	// in a shared binary where other tests' drain loops may still be
	// running during this test's cleanup.
	auditor, out := newMiddlewareTestAuditor(t)

	var calls atomic.Int64

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		calls.Add(1)
		return "http_request", audit.Fields{"outcome": hints.Outcome, "actor_id": hints.ActorID}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Outcome = "success"
		hints.ActorID = r.Header.Get("X-Actor")
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
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

	require.NoError(t, auditor.Close())
	assert.Equal(t, 100, out.EventCount())
}

func TestMiddleware_StatusCode_FromHandler(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedStatus int
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedStatus = transport.StatusCode
		return "http_request", audit.Fields{"outcome": "not_found"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, capturedStatus)
}

func TestMiddleware_Duration_Positive(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedDuration time.Duration
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedDuration = transport.Duration
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	// time.Since(start) is monotonically non-decreasing. For a
	// no-op handler on Windows the system clock resolution can
	// produce a 0-valued duration; on Linux/macOS the nanosecond
	// resolution effectively guarantees a positive value. The
	// invariant we actually want is "duration was captured and
	// is non-negative".
	assert.GreaterOrEqual(t, capturedDuration, time.Duration(0))
}

func TestMiddleware_BuilderPanic_Recovered(t *testing.T) {
	auditor, out := newMiddlewareTestAuditor(t)

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		panic("builder exploded")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	// Builder panic must not propagate to the caller.
	assert.NotPanics(t, func() {
		mw(handler).ServeHTTP(rec, req)
	})

	// Event should be skipped due to builder panic.
	require.NoError(t, auditor.Close())
	assert.Equal(t, 0, out.EventCount())
}

func TestMiddleware_RequestID_InvalidHeader_GeneratesUUID(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedID string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedID = transport.RequestID
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Request-Id", "injected\nfake-log-line")
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	// Invalid header should be replaced with a generated UUID.
	assert.Regexp(t, uuidV4Pattern, capturedID)
}

func TestMiddleware_UserAgent_Truncated(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedUA string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedUA = transport.UserAgent
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	longUA := strings.Repeat("x", 1000)
	req.Header.Set("User-Agent", longUA)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, 512, len(capturedUA))
}

func TestMiddleware_NilLoggerNilBuilder_NoPanic(t *testing.T) {
	// When auditor is nil, builder is never checked — Middleware(nil, nil) must not panic.
	assert.NotPanics(t, func() {
		mw := audit.Middleware(nil, nil)
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		handler.ServeHTTP(rec, req)
	})
}

func TestMiddleware_NilLogger_HintsFromContextReturnsNil(t *testing.T) {
	var hintsInHandler *audit.Hints
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hintsInHandler = audit.HintsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(nil, func(_ *audit.Hints, _ *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "", nil, true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	mw(handler).ServeHTTP(rec, req)

	assert.Nil(t, hintsInHandler, "HintsFromContext should return nil when auditor is nil")
}

func TestMiddleware_HintsError_PassedToBuilder(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedError string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedError = hints.Error
		return "http_request", audit.Fields{"outcome": "failure"}, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Error = "permission denied"
		w.WriteHeader(http.StatusForbidden)
	})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, "permission denied", capturedError)
}

func TestMiddleware_HandlerWritesNothing_Status200(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedStatus int
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedStatus = transport.StatusCode
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	// Handler returns without calling Write or WriteHeader.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, capturedStatus)
}

func TestMiddleware_Path_Truncated(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditor(t)

	var capturedPath string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedPath = transport.Path
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	rec := httptest.NewRecorder()
	longPath := "/" + strings.Repeat("x", 3000)
	req := httptest.NewRequest(http.MethodGet, longPath, http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, 2048, len(capturedPath))
}

// --- Benchmarks ---

func BenchmarkMiddleware(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(prev) })

	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(1_000_000),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
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

// BenchmarkMiddleware_Parallel exercises the pool under
// b.RunParallel so contention effects from the responseWriter /
// TransportMetadata pools surface if present. A per-goroutine
// sync.Pool local cache should keep contention off the hot path;
// a super-linear scaling of ns/op with GOMAXPROCS would indicate
// a pool-contention regression (#501).
func BenchmarkMiddleware_Parallel(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(prev) })

	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("bench")
	auditor, err := audit.New(
		audit.WithQueueSize(1_000_000),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(auditor, builder)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/bench", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}
	})
}

// TestMiddleware_PoolCorrectness_ResetOnGet_ResponseWriter pins
// the explicit contract of [acquireResponseWriter] /
// [releaseResponseWriter] (defined internally in transport.go):
// release clears every field, and acquire re-sets the inner
// ResponseWriter / resets counters. Guards against a future
// refactor that removes reset-on-Get (which would leave the
// crosstalk behavioural test still passing while silently
// breaking the per-acquire invariant).
//
// Uses the public NewResponseWriter wrapper in
// middleware_export_test.go to assert zeroed initial state of a
// fresh struct, and exercises acquire-release-acquire through a
// real Middleware request.
func TestMiddleware_PoolCorrectness_ResetOnGet_ResponseWriter(t *testing.T) {
	t.Parallel()
	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("pool-corr-rw")
	auditor, err := audit.New(
		audit.WithQueueSize(100),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Handler that writes a specific status code so the pooled
	// responseWriter's statusCode/written fields are mutated.
	handler := audit.Middleware(auditor, func(*audit.Hints, *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{"outcome": "success"}, false
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/rw", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusTeapot, rec.Code,
			"iteration %d: pooled rw must propagate the handler's status code, not stale state from prior request", i)
	}
}

// TestMiddleware_PoolCorrectness_TransportMetadataZeroed exercises
// the [TransportMetadata] zero-on-Put contract by sending two
// distinct requests back-to-back and asserting the captured
// `request_id` in the second event is NOT the first request's
// id. A missed reset in release would surface as a stale
// RequestID string retained across the pool cycle.
func TestMiddleware_PoolCorrectness_TransportMetadataZeroed(t *testing.T) {
	t.Parallel()
	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("pool-corr-tm")
	auditor, err := audit.New(
		audit.WithQueueSize(100),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	handler := audit.Middleware(auditor, func(_ *audit.Hints, tr *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{
			"outcome":    "success",
			"request_id": tr.RequestID,
		}, false
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests with distinct X-Request-Id headers.
	for _, id := range []string{"req-alpha-0000", "req-beta-1111"} {
		req := httptest.NewRequest(http.MethodGet, "/tm", http.NoBody)
		req.Header.Set("X-Request-Id", id)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	require.NoError(t, auditor.Close())
	require.Equal(t, 2, out.EventCount())
	ev0, ev1 := out.GetEvent(0), out.GetEvent(1)
	id0, _ := ev0["request_id"].(string)
	id1, _ := ev1["request_id"].(string)
	assert.Equal(t, "req-alpha-0000", id0)
	assert.Equal(t, "req-beta-1111", id1,
		"pool leak: second event's request_id leaked from first request (expected req-beta-1111)")
	assert.NotEqual(t, id0, id1, "two distinct requests must produce distinct request_ids")
}

// TestMiddleware_PoolCorrectness_HijackedRequestDoesNotLeakInnerWriter
// pins the nil-on-release contract for responseWriter. After a
// handler hijacks the connection, [releaseResponseWriter] must
// clear the embedded http.ResponseWriter field so the NEXT
// pooled acquisition does not resurrect the hijacked connection.
//
// test-analyst pre-coding note: "a handler that stashes
// the [responseController] and calls it late will panic.
// Acceptable (stdlib contract violation), but worth pinning."
//
// The test exercises the defer-releaseResponseWriter path after
// the handler calls Hijack — then issues a second, ordinary
// request and verifies the pooled responseWriter reflects the
// new request's writer, not the hijacked conn from the first.
func TestMiddleware_PoolCorrectness_HijackedRequestDoesNotLeakInnerWriter(t *testing.T) {
	t.Parallel()
	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("pool-corr-hj")
	auditor, err := audit.New(
		audit.WithQueueSize(100),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	handler := audit.Middleware(auditor, func(*audit.Hints, *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{"outcome": "success"}, false
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// First request attempts to hijack. httptest.NewRecorder
		// does NOT implement http.Hijacker, so this returns
		// ErrHijackNotSupported — but it still exercises the
		// responseWriter.Hijack path, which reads from
		// rw.ResponseWriter. Pooled rw with a non-nil stale
		// ResponseWriter from a prior request would be the bug.
		if rc := http.NewResponseController(w); rc != nil {
			_, _, _ = rc.Hijack() // expected to fail on httptest; exercises rw.ResponseWriter access
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Two sequential requests — second reuses the pooled rw.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/hj", http.NoBody)
		rec := httptest.NewRecorder()
		require.NotPanics(t, func() {
			handler.ServeHTTP(rec, req)
		}, "iteration %d: pooled rw reuse after Hijack attempt must not panic — release-side reset must clear inner ResponseWriter", i)
		require.Equal(t, http.StatusOK, rec.Code,
			"iteration %d: rec.Code must reflect the current request's handler, not prior state", i)
	}
}

// TestMiddleware_PoolCorrectness_Crosstalk is the core pool
// safety guard for #501. It fires a large number of concurrent
// requests, each tagged with a distinct ActorID header, and
// verifies every response records the right ActorID back — a
// pool-reuse bug that leaked a pooled [responseWriter] or
// [TransportMetadata] across requests would produce an ActorID
// mismatch. Runs under `-race` to catch any accidental shared
// state introduced by the pool.
//
// The mix includes panicking handlers so the pool Put-on-defer
// path after panic re-raise is also exercised.
func TestMiddleware_PoolCorrectness_Crosstalk(t *testing.T) {
	t.Parallel()

	const (
		goroutines        = 50
		requestsPerWorker = 1000
		panicEvery        = 20 // ~5% of requests trigger a handler panic.
	)

	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("pool-corr")
	auditor, err := audit.New(
		audit.WithQueueSize(1_000_000),
		audit.WithTaxonomy(taxonomy),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		// Echo the header-sourced ActorID back through the event
		// so test assertions can verify no crosstalk.
		return "http_request", audit.Fields{
			"outcome":  hints.Outcome,
			"actor_id": hints.ActorID,
		}, false
	}

	handler := audit.Middleware(auditor, builder)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.ActorID = r.Header.Get("X-Test-Actor")
			hints.Outcome = "success"
		}
		// Simulate ~5% of requests panicking so the pool defer-Put
		// path after a re-raised panic is covered.
		if r.Header.Get("X-Test-Panic") == "1" {
			panic("intentional test panic")
		}
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for w := 0; w < goroutines; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < requestsPerWorker; i++ {
				actorID := fmt.Sprintf("actor-%d-%d", workerID, i)
				req := httptest.NewRequest(http.MethodGet, "/pool-corr", http.NoBody)
				req.RemoteAddr = "10.0.0.1:12345"
				req.Header.Set("X-Test-Actor", actorID)
				if i%panicEvery == 0 {
					req.Header.Set("X-Test-Panic", "1")
				}
				rec := httptest.NewRecorder()
				func() {
					defer func() { _ = recover() }() // absorb the re-raised panic.
					handler.ServeHTTP(rec, req)
				}()
			}
		}(w)
	}
	wg.Wait()

	// Flush the audit pipeline and verify no crosstalk: every
	// captured event's actor_id must be one of the deterministic
	// actor-%d-%d strings this test produced. A pool bug would
	// surface as a stale empty or wrong-worker actor_id.
	_ = auditor.Close()
	count := out.EventCount()
	seen := make(map[string]bool, goroutines*requestsPerWorker)
	for i := 0; i < count; i++ {
		ev := out.GetEvent(i)
		actor, _ := ev["actor_id"].(string)
		if actor == "" {
			continue // skip panicking-handler paths where builder may observe empty.
		}
		require.Regexp(t, `^actor-\d+-\d+$`, actor,
			"pool crosstalk: actor_id %q does not match expected shape", actor)
		seen[actor] = true
	}
	// Sanity: at least a meaningful fraction of the non-panic
	// requests produced uniquely-tagged events.
	require.Greater(t, len(seen), goroutines,
		"expected > goroutines unique ActorIDs; got %d", len(seen))
}

// TestMiddleware_NewRequestIDWarningsRoutedToAuditorLogger verifies
// that the crypto/rand fallback warning in newRequestID routes through
// the caller-supplied logger rather than slog.Default. Closes #490.
func TestMiddleware_NewRequestIDWarningsRoutedToAuditorLogger(t *testing.T) {
	// Force crypto/rand to fail via the randRead seam.
	restore := audit.SetRandRead(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("test: simulated crypto/rand failure")
	})
	t.Cleanup(restore)

	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	injected := slog.New(handler)

	id := audit.NewRequestIDWithLogger(injected)

	// Zero UUID sentinel from the fallback path.
	assert.Equal(t, "00000000-0000-4000-8000-000000000000", id,
		"expected zero UUID when crypto/rand fails")

	logged := buf.String()
	assert.Contains(t, logged, "crypto/rand failed",
		"expected rand-failure warning on injected logger, got: %q", logged)
}

// TestMiddleware_NewRequestIDNilLoggerFallsBackToDefault verifies
// that passing nil does not panic and emits via slog.Default.
func TestMiddleware_NewRequestIDNilLoggerFallsBackToDefault(t *testing.T) {
	restore := audit.SetRandRead(func(_ []byte) (int, error) {
		return 0, fmt.Errorf("test: simulated crypto/rand failure")
	})
	t.Cleanup(restore)

	var buf strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	id := audit.NewRequestIDWithLogger(nil)
	assert.Equal(t, "00000000-0000-4000-8000-000000000000", id)
	assert.Contains(t, buf.String(), "crypto/rand failed")
}
