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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Middleware test helpers ---

// middlewareTaxonomy returns a taxonomy suitable for middleware tests.
func middlewareTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"access": {"http_request"},
		},
		Events: map[string]*audit.EventDef{
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

// newMiddlewareTestLogger creates a Logger with a mockOutput for middleware tests.
func newMiddlewareTestLogger(t *testing.T) (*audit.Logger, *testhelper.MockOutput) {
	t.Helper()
	out := testhelper.NewMockOutput("mw-test")
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
	logger, _ := newMiddlewareTestLogger(t)

	assert.PanicsWithValue(t, "audit: EventBuilder must not be nil", func() {
		audit.Middleware(logger, nil)
	})
}

func TestMiddleware_BasicFlow(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
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

	assert.Equal(t, 1, out.EventCount())
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
		hints := audit.HintsFromContext(r.Context())
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
	assert.Equal(t, 0, out.EventCount())
}

func TestMiddleware_PanicRecovery(t *testing.T) {
	logger, out := newMiddlewareTestLogger(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
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
	assert.Equal(t, 1, out.EventCount())
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
	// Goroutine leak detection is handled globally by TestMain via
	// goleak.VerifyTestMain. Per-test goleak.VerifyNone is unreliable
	// in a shared binary where other tests' drain loops may still be
	// running during this test's cleanup.
	logger, out := newMiddlewareTestLogger(t)

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
	assert.Equal(t, 100, out.EventCount())
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
	assert.Greater(t, capturedDuration, time.Duration(0))
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
	assert.Equal(t, 0, out.EventCount())
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

func TestMiddleware_NilLoggerNilBuilder_NoPanic(t *testing.T) {
	// When logger is nil, builder is never checked — Middleware(nil, nil) must not panic.
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

	assert.Nil(t, hintsInHandler, "HintsFromContext should return nil when logger is nil")
}

func TestMiddleware_HintsError_PassedToBuilder(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

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

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, "permission denied", capturedError)
}

func TestMiddleware_HandlerWritesNothing_Status200(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedStatus int
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedStatus = transport.StatusCode
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	// Handler returns without calling Write or WriteHeader.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(handler).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, capturedStatus)
}

func TestMiddleware_Path_Truncated(t *testing.T) {
	logger, _ := newMiddlewareTestLogger(t)

	var capturedPath string
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		capturedPath = transport.Path
		return "http_request", audit.Fields{"outcome": "success"}, false
	}

	mw := audit.Middleware(logger, builder)
	rec := httptest.NewRecorder()
	longPath := "/" + strings.Repeat("x", 3000)
	req := httptest.NewRequest(http.MethodGet, longPath, http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, 2048, len(capturedPath))
}

// --- Benchmarks ---

func BenchmarkMiddleware(b *testing.B) {
	taxonomy := middlewareTaxonomy()
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 1_000_000},
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
