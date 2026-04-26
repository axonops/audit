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
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// newMiddlewareTestAuditorWithSanitizer mirrors newMiddlewareTestAuditor
// but registers a Sanitizer.
func newMiddlewareTestAuditorWithSanitizer(t *testing.T, s audit.Sanitizer) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	return newMiddlewareTestAuditorWithOptions(t, audit.WithSanitizer(s))
}

// newMiddlewareTestAuditorWithOptions allows arbitrary additional
// options on top of the middleware test auditor's defaults.
func newMiddlewareTestAuditorWithOptions(t *testing.T, opts ...audit.Option) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	out := testhelper.NewMockOutput("mw-test")
	all := []audit.Option{
		audit.WithTaxonomy(middlewareTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	}
	all = append(all, opts...)
	auditor, err := audit.New(all...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })
	return auditor, out
}

// panicValueRedactor transforms any recovered panic value into a
// fixed sentinel string so tests can assert the re-raise path.
type panicValueRedactor struct {
	audit.NoopSanitizer
}

func (panicValueRedactor) SanitizePanic(_ any) any {
	return "panic value redacted"
}

// TestMiddleware_SanitizePanic_AppliedToReRaise verifies the
// walkthrough #29 contract: when a handler panics, SanitizePanic is
// called and the SANITISED value is what flows out of the middleware
// to outer panic handlers.
func TestMiddleware_SanitizePanic_AppliedToReRaise(t *testing.T) {
	auditor, _ := newMiddlewareTestAuditorWithSanitizer(t, panicValueRedactor{})

	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Outcome = "error"
		panic("internal secret: token=abc-123")
	})

	mw := audit.Middleware(auditor, middlewareBuilder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	// The re-raised panic value MUST be the sanitised one, not the
	// original — that's the whole point.
	assert.PanicsWithValue(t, "panic value redacted", func() {
		mw(handler).ServeHTTP(rec, req)
	})
}

// panicSanitizePanicRedactor panics inside SanitizePanic itself,
// exercising the fail-open contract.
type panicSanitizePanicRedactor struct {
	audit.NoopSanitizer
}

func (panicSanitizePanicRedactor) SanitizePanic(_ any) any {
	panic("sanitiser of sanitiser exploded")
}

// TestMiddleware_SanitizePanic_SanitiserPanicsFailOpen locks the
// security S2 contract: when SanitizePanic itself panics, the
// ORIGINAL panic value is re-raised AND the audit event still emits
// (with the sanitizer_failed framework field set).
func TestMiddleware_SanitizePanic_SanitiserPanicsFailOpen(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor, out := newMiddlewareTestAuditorWithOptions(t,
		audit.WithSanitizer(panicSanitizePanicRedactor{}),
		audit.WithDiagnosticLogger(logger),
	)

	originalPanic := "the original panic"
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Outcome = "error"
		panic(originalPanic)
	})

	mw := audit.Middleware(auditor, middlewareBuilder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	// Original panic propagates (fail-open re-raise).
	assert.PanicsWithValue(t, originalPanic, func() {
		mw(handler).ServeHTTP(rec, req)
	})

	// Audit event was still emitted (fail-open audit).
	require.NoError(t, auditor.Close())
	require.Equal(t, 1, out.EventCount())
	ev := out.GetEvent(0)
	assert.Equal(t, true, ev[audit.FieldSanitizerFailed],
		"event MUST carry sanitizer_failed=true so SIEM can route on the failure")

	// Diagnostic log records the panic but NEVER the original value.
	logs := buf.String()
	assert.Contains(t, logs, "Sanitizer.SanitizePanic panicked")
	assert.NotContains(t, logs, originalPanic,
		"diagnostic log MUST NOT leak the original panic value")
}

// TestMiddleware_SanitizePanic_NoSanitizerSet_OriginalReRaises is a
// regression guard: when no Sanitizer is configured, the existing
// re-raise behaviour (#29 baseline) is unchanged.
func TestMiddleware_SanitizePanic_NoSanitizerSet_OriginalReRaises(t *testing.T) {
	auditor, out := newMiddlewareTestAuditor(t) // no sanitizer

	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		hints.Outcome = "error"
		panic("original panic value")
	})

	mw := audit.Middleware(auditor, middlewareBuilder)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", http.NoBody)
	req.RemoteAddr = "10.0.0.1:12345"

	assert.PanicsWithValue(t, "original panic value", func() {
		mw(handler).ServeHTTP(rec, req)
	})

	require.NoError(t, auditor.Close())
	require.Equal(t, 1, out.EventCount())
	ev := out.GetEvent(0)
	assert.NotContains(t, ev, audit.FieldSanitizerFailed,
		"sanitizer_failed must not be set when no Sanitizer is configured")
}
