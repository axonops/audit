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
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// redactSanitizer replaces the actor_id field with [redacted].
type redactSanitizer struct {
	audit.NoopSanitizer
}

func (redactSanitizer) SanitizeField(key string, value any) any {
	if key == "actor_id" {
		return "[redacted]"
	}
	return value
}

// panicSanitizer panics on a specific field, otherwise passes through.
type panicSanitizer struct {
	audit.NoopSanitizer
	panicKey string
	secret   string
}

func (p panicSanitizer) SanitizeField(key string, value any) any {
	if key == p.panicKey {
		panic("sanitizer crashed processing " + p.secret)
	}
	return value
}

// recordSanitizer counts SanitizeField calls under concurrency.
type recordSanitizer struct {
	audit.NoopSanitizer
	calls atomic.Int64
}

func (r *recordSanitizer) SanitizeField(_ string, value any) any {
	r.calls.Add(1)
	return value
}

// panicValueSanitizer transforms a recovered panic to a sentinel
// string and counts how many times it ran.
type panicValueSanitizer struct {
	audit.NoopSanitizer
	calls atomic.Int64
}

func (p *panicValueSanitizer) SanitizePanic(_ any) any {
	p.calls.Add(1)
	return "[panic_redacted]"
}

// newSanitizerAuditor builds a synchronous-delivery auditor with a
// MockOutput so tests can read what was actually emitted.
func newSanitizerAuditor(t *testing.T, opts ...audit.Option) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	mock := testhelper.NewMockOutput("test")
	tax := testhelper.ValidTaxonomy()
	all := []audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
		audit.WithOutputs(mock),
	}
	all = append(all, opts...)
	a, err := audit.New(all...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	return a, mock
}

// TestSanitizer_SanitizeField_TransformsValue verifies the basic
// happy path: a Sanitizer that transforms one field's value.
func TestSanitizer_SanitizeField_TransformsValue(t *testing.T) {
	t.Parallel()
	a, mock := newSanitizerAuditor(t, audit.WithSanitizer(redactSanitizer{}))

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice@example.com",
	})))

	require.True(t, mock.WaitForEvents(1, 0))
	ev := mock.GetEvent(0)
	assert.Equal(t, "[redacted]", ev["actor_id"], "Sanitizer must transform actor_id")
	assert.Equal(t, "failure", ev["outcome"], "untouched fields pass through")
}

// TestSanitizer_NilSanitizer_PassThrough confirms an unset Sanitizer
// is a no-op (and proves the nil-check fast path).
func TestSanitizer_NilSanitizer_PassThrough(t *testing.T) {
	t.Parallel()
	a, mock := newSanitizerAuditor(t) // no WithSanitizer

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice@example.com",
	})))

	require.True(t, mock.WaitForEvents(1, 0))
	ev := mock.GetEvent(0)
	assert.Equal(t, "alice@example.com", ev["actor_id"])
	assert.NotContains(t, ev, audit.FieldSanitizerFailedFields)
}

// TestSanitizer_SanitizeField_PanicReplacedWithSentinel verifies the
// per-field panic recovery: bad sanitiser → sentinel value + framework
// field listing the failed key. Other fields still emit normally.
func TestSanitizer_SanitizeField_PanicReplacedWithSentinel(t *testing.T) {
	t.Parallel()
	a, mock := newSanitizerAuditor(t, audit.WithSanitizer(panicSanitizer{
		panicKey: "actor_id",
		secret:   "alice@example.com",
	}))

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice@example.com",
	})))

	require.True(t, mock.WaitForEvents(1, 0))
	ev := mock.GetEvent(0)
	assert.Equal(t, audit.SanitizerPanicSentinel, ev["actor_id"])
	assert.Equal(t, "failure", ev["outcome"], "other fields emit normally")

	// MockOutput round-trips through JSON, so []string becomes
	// []any with string elements.
	failed, ok := ev[audit.FieldSanitizerFailedFields].([]any)
	require.True(t, ok, "%s must be a []any (JSON-decoded []string)", audit.FieldSanitizerFailedFields)
	require.Len(t, failed, 1)
	assert.Equal(t, "actor_id", failed[0])
}

// TestSanitizer_SanitizeField_DiagnosticLog_NeverContainsRawValue
// proves the security S6 contract: a sanitiser that panics on a
// secret value MUST NOT cause that secret to appear in the
// diagnostic log.
func TestSanitizer_SanitizeField_DiagnosticLog_NeverContainsRawValue(t *testing.T) {
	t.Parallel()
	const secret = "SECRET-PII-12345"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	a, _ := newSanitizerAuditor(t,
		audit.WithSanitizer(panicSanitizer{panicKey: "actor_id", secret: secret}),
		audit.WithDiagnosticLogger(logger),
	)

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": secret,
	})))

	logs := buf.String()
	assert.Contains(t, logs, "Sanitizer.SanitizeField panicked",
		"diagnostic log must record the panic")
	assert.NotContains(t, logs, secret,
		"diagnostic log MUST NOT contain the raw value the sanitiser saw")
}

// TestSanitizer_SanitizePanic_TransformsValue verifies the
// SanitizePanic API directly via the helper (independent of middleware
// wiring; that path is tested in middleware_external_test.go).
func TestSanitizer_SanitizePanic_TransformsValue(t *testing.T) {
	t.Parallel()
	s := &panicValueSanitizer{}
	// Direct test via NoopSanitizer override: the value flows through
	// the sanitiser's SanitizePanic.
	out := s.SanitizePanic("original")
	assert.Equal(t, "[panic_redacted]", out)
	assert.EqualValues(t, 1, s.calls.Load())
}

// TestSanitizer_ConcurrentSafe drives the sanitiser from many
// goroutines simultaneously. Run with `-race` to catch data races on
// stateful Sanitizers; this lock the documented concurrent-safety
// contract.
func TestSanitizer_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	rec := &recordSanitizer{}
	a, mock := newSanitizerAuditor(t, audit.WithSanitizer(rec))

	const goroutines = 100
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				_ = a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
					"outcome":  "failure",
					"actor_id": "alice",
				}))
			}
		}()
	}
	wg.Wait()

	require.True(t, mock.WaitForEvents(goroutines*perGoroutine, 0))
	// auth_failure carries exactly two fields (outcome + actor_id);
	// the library injects no defaults the sanitiser would also see in
	// this taxonomy, so the count is exact, not a lower bound.
	assert.Equal(t, int64(goroutines*perGoroutine*2), rec.calls.Load())
}

// TestNoopSanitizer_SanitizeField_ReturnsValueUnchanged locks the
// embed-helper contract: NoopSanitizer is a true pass-through.
func TestNoopSanitizer_SanitizeField_ReturnsValueUnchanged(t *testing.T) {
	t.Parallel()
	var n audit.NoopSanitizer
	cases := []struct {
		value any
		name  string
		key   string
	}{
		{"v", "string", "k"},
		{42, "int", "n"},
		{nil, "nil", "p"},
		{[]string{"a", "b"}, "slice", "s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.value, n.SanitizeField(tc.key, tc.value))
		})
	}
}

// TestNoopSanitizer_SanitizePanic_ReturnsValueUnchanged completes
// the NoopSanitizer pass-through coverage.
func TestNoopSanitizer_SanitizePanic_ReturnsValueUnchanged(t *testing.T) {
	t.Parallel()
	var n audit.NoopSanitizer
	assert.Equal(t, "boom", n.SanitizePanic("boom"))
	assert.Nil(t, n.SanitizePanic(nil))
}

// TestSanitizer_RunsAfterValidation verifies the post-validation
// placement (P1). Strict-mode validation must reject an unsupported
// type BEFORE the sanitiser sees it.
func TestSanitizer_RunsAfterValidation(t *testing.T) {
	t.Parallel()
	rec := &recordSanitizer{}
	a, _ := newSanitizerAuditor(t,
		audit.WithSanitizer(rec),
		audit.WithValidationMode(audit.ValidationStrict),
	)

	// auth_failure requires outcome + actor_id; missing outcome should
	// be rejected by validation BEFORE the sanitiser runs.
	err := a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"actor_id": "alice",
	}))
	require.Error(t, err)
	assert.EqualValues(t, 0, rec.calls.Load(),
		"sanitiser must NOT be invoked when validation rejects the event")
}

// TestSanitizer_FailedFields_AreSorted locks deterministic
// ordering of the framework field — important because the sentinel
// value is what consumers grep for; the order of failed keys must be
// stable across runs.
func TestSanitizer_FailedFields_AreSorted(t *testing.T) {
	t.Parallel()
	multiPanicS := multiPanicSanitizer{keys: map[string]struct{}{
		"actor_id": {},
		"outcome":  {},
	}}
	a, mock := newSanitizerAuditor(t, audit.WithSanitizer(multiPanicS))

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	})))

	require.True(t, mock.WaitForEvents(1, 0))
	ev := mock.GetEvent(0)
	failed, ok := ev[audit.FieldSanitizerFailedFields].([]any)
	require.True(t, ok)
	// Sorted alphabetically. JSON-decoded as []any.
	require.Len(t, failed, 2)
	assert.Equal(t, "actor_id", failed[0])
	assert.Equal(t, "outcome", failed[1])
}

// multiPanicSanitizer panics on every key in the configured set.
type multiPanicSanitizer struct {
	audit.NoopSanitizer
	keys map[string]struct{}
}

func (m multiPanicSanitizer) SanitizeField(key string, value any) any {
	if _, ok := m.keys[key]; ok {
		panic("multi panic: " + key)
	}
	return value
}

// TestSanitizer_StackNotIncludesValue is a belt-and-braces check that
// the runtime/debug.Stack output captured in the diagnostic log
// doesn't accidentally embed the sanitised value (defence against
// future refactors that might pass `value` through the panic chain).
func TestSanitizer_StackNotIncludesValue(t *testing.T) {
	t.Parallel()
	const secret = "SUPER-SECRET-VALUE-NEVER-LOG-ME"
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	a, _ := newSanitizerAuditor(t,
		audit.WithSanitizer(panicSanitizer{panicKey: "actor_id", secret: secret}),
		audit.WithDiagnosticLogger(logger),
	)

	require.NoError(t, a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": secret,
	})))

	logs := buf.String()
	if strings.Contains(logs, secret) {
		t.Fatalf("diagnostic log leaked secret value through stack trace; log was:\n%s", logs)
	}
}
