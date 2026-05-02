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
	"errors"
	"fmt"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// errors.Is — parent sentinel covers all validation failures (#400 AC-1)
// ---------------------------------------------------------------------------

func TestAuditEvent_AllValidationErrors_WrapErrValidation(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	tests := []struct { //nolint:govet // fieldalignment: test readability
		name      string
		eventType string
		fields    audit.Fields
	}{
		{
			name:      "unknown event type",
			eventType: "nonexistent",
			fields:    audit.Fields{},
		},
		{
			name:      "missing required field",
			eventType: "auth_failure",
			fields:    audit.Fields{}, // outcome and actor_id required
		},
		{
			name:      "unknown field strict",
			eventType: "auth_failure",
			fields:    audit.Fields{"outcome": "ok", "actor_id": "a", "bogus": "val"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := auditor.AuditEvent(audit.NewEvent(tt.eventType, tt.fields))
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrValidation, "all validation errors must wrap ErrValidation")
		})
	}
}

// ---------------------------------------------------------------------------
// errors.Is — specific sentinels (#400 AC-2, AC-3, AC-4)
// ---------------------------------------------------------------------------

func TestAuditEvent_UnknownEventType_WrapsErrUnknownEventType(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrUnknownEventType)
	assert.ErrorIs(t, err, audit.ErrValidation)
	// Mutual exclusivity: not the other sentinels.
	assert.False(t, errors.Is(err, audit.ErrMissingRequiredField))
	assert.False(t, errors.Is(err, audit.ErrUnknownField))
}

func TestAuditEvent_MissingRequired_WrapsErrMissingRequiredField(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
	assert.ErrorIs(t, err, audit.ErrValidation)
	// Mutual exclusivity.
	assert.False(t, errors.Is(err, audit.ErrUnknownEventType))
	assert.False(t, errors.Is(err, audit.ErrUnknownField))
}

func TestAuditEvent_UnknownFieldStrict_WrapsErrUnknownField(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrUnknownField)
	assert.ErrorIs(t, err, audit.ErrValidation)
	// Mutual exclusivity.
	assert.False(t, errors.Is(err, audit.ErrUnknownEventType))
	assert.False(t, errors.Is(err, audit.ErrMissingRequiredField))
}

// ---------------------------------------------------------------------------
// errors.Is — non-validation errors not affected (#400 AC-5, AC-6)
// ---------------------------------------------------------------------------

func TestErrQueueFull_NotErrValidation(t *testing.T) {
	t.Parallel()
	assert.False(t, errors.Is(audit.ErrQueueFull, audit.ErrValidation),
		"ErrQueueFull must NOT be ErrValidation")
}

func TestErrClosed_NotErrValidation(t *testing.T) {
	t.Parallel()
	assert.False(t, errors.Is(audit.ErrClosed, audit.ErrValidation),
		"ErrClosed must NOT be ErrValidation")
}

// ---------------------------------------------------------------------------
// errors.As — ValidationError struct access
// ---------------------------------------------------------------------------

func TestValidationError_ErrorsAs(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, err)

	var ve *audit.ValidationError
	require.True(t, errors.As(err, &ve), "should be extractable via errors.As")
	assert.Contains(t, ve.Error(), "nonexistent")
}

// ---------------------------------------------------------------------------
// Error message text unchanged (#400 AC-7)
// ---------------------------------------------------------------------------

func TestValidationError_MessageTextUnchanged(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Unknown event type — exact text check.
	err = auditor.AuditEvent(audit.NewEvent("bogus", audit.Fields{}))
	require.Error(t, err)
	assert.Equal(t, `audit: unknown event type "bogus"`, err.Error())

	// Missing required — text starts with expected prefix.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
	assert.Contains(t, err.Error(), `audit: event "auth_failure" missing required fields:`)
}

// ---------------------------------------------------------------------------
// Consumer wrapping preserves errors.Is
// ---------------------------------------------------------------------------

func TestValidationError_ConsumerWrapping_PreservesErrorsIs(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	inner := auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, inner)

	// Consumer wraps the error with additional context.
	wrapped := fmt.Errorf("my service: %w", inner)
	assert.ErrorIs(t, wrapped, audit.ErrValidation)
	assert.ErrorIs(t, wrapped, audit.ErrUnknownEventType)
}

// ---------------------------------------------------------------------------
// Warn/permissive modes do not leak sentinels
// ---------------------------------------------------------------------------

func TestAuditEvent_WarnMode_NoSentinelLeak(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationWarn),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	}))
	assert.NoError(t, err, "warn mode should not return an error")
}

func TestAuditEvent_PermissiveMode_NoSentinelLeak(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	}))
	assert.NoError(t, err, "permissive mode should not return an error")
}

// ---------------------------------------------------------------------------
// Reserved standard fields do not trigger ErrUnknownField
// ---------------------------------------------------------------------------

func TestAuditEvent_ReservedStandardField_NotErrUnknownField(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// actor_id is a reserved standard field — should not trigger unknown field.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":   "fail",
		"actor_id":  "bob",
		"source_ip": "10.0.0.1", // reserved standard field
	}))
	assert.NoError(t, err, "reserved standard fields must not trigger ErrUnknownField")
}

// ---------------------------------------------------------------------------
// Empty string event type wraps ErrUnknownEventType
// ---------------------------------------------------------------------------

func TestAuditEvent_EmptyEventType_WrapsErrUnknownEventType(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	err = auditor.AuditEvent(audit.NewEvent("", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrUnknownEventType)
	assert.ErrorIs(t, err, audit.ErrValidation)
}

// TestValidationError_Unwrap_ReturnsIndependentSlice verifies that
// [audit.ValidationError.Unwrap] returns a defensive copy — mutating
// the returned slice does NOT affect subsequent Unwrap calls or the
// underlying ValidationError. Before #590 Unwrap returned a shared
// slice over the internal array, so a caller that retained and mutated
// the result would corrupt future errors.Is / errors.As dispatches.
func TestValidationError_Unwrap_ReturnsIndependentSlice(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Trigger a ValidationError via an unknown event type.
	emitErr := auditor.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, emitErr)

	var vErr *audit.ValidationError
	require.True(t, errors.As(emitErr, &vErr), "emitErr must be a *ValidationError")

	// Baseline: errors.Is matches ErrValidation before any mutation.
	require.True(t, errors.Is(vErr, audit.ErrValidation))

	// Mutate the first returned slice — zero it out.
	first := vErr.Unwrap()
	require.Len(t, first, 2, "Unwrap should return a 2-element slice")
	first[0] = nil
	first[1] = nil

	// Unwrap called again must still return the original sentinels —
	// the first Unwrap returned a defensive copy, so our mutation
	// cannot have affected the underlying error.
	second := vErr.Unwrap()
	assert.NotNil(t, second[0], "second Unwrap[0] must not be nil (first Unwrap returned a copy)")
	assert.True(t, errors.Is(vErr, audit.ErrValidation),
		"errors.Is must still match after a caller mutates a previous Unwrap result")
}
