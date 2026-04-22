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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewStdout / NewStderr / NewWriter
// ---------------------------------------------------------------------------

func TestNewStdout_ReturnsWorkingOutput(t *testing.T) {
	t.Parallel()
	out, err := audit.NewStdout()
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "stdout", out.Name())
}

func TestNewStderr_ReturnsWorkingOutput(t *testing.T) {
	t.Parallel()
	out, err := audit.NewStderr()
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "stdout", out.Name())
}

func TestNewWriter_WithBuffer(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	out, err := audit.NewWriter(&buf)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Write([]byte("hello\n")))
	assert.Equal(t, "hello\n", buf.String())
}

func TestNewWriter_NilDefaultsToStdout(t *testing.T) {
	t.Parallel()
	out, err := audit.NewWriter(nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "stdout", out.Name())
}

// ---------------------------------------------------------------------------
// NewEventKV() / MustNewEventKV()
// ---------------------------------------------------------------------------

func TestNewEventKV_ValidPairs(t *testing.T) {
	t.Parallel()
	evt, err := audit.NewEventKV("user_create", "outcome", "success", "actor_id", "alice")
	require.NoError(t, err)
	assert.Equal(t, "user_create", evt.EventType())
	assert.Equal(t, "success", evt.Fields()["outcome"])
	assert.Equal(t, "alice", evt.Fields()["actor_id"])
}

func TestNewEventKV_EmptyFields(t *testing.T) {
	t.Parallel()
	evt, err := audit.NewEventKV("user_create")
	require.NoError(t, err)
	assert.Equal(t, "user_create", evt.EventType())
	assert.Empty(t, evt.Fields())
}

// TestNewEventKV_OddArgs_ReturnsError verifies that NewEventKV now
// returns a non-nil error wrapping [audit.ErrValidation] when called
// with an odd number of key-value arguments (#590 part 2 of 2). Prior
// to #590 the function panicked; the sibling MustNewEventKV preserves
// the panic contract for literal call sites.
func TestNewEventKV_OddArgs_ReturnsError(t *testing.T) {
	t.Parallel()
	args := []any{"orphan"}
	_, err := audit.NewEventKV("user_create", args...)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.Contains(t, err.Error(), "even number of arguments")
}

func TestNewEventKV_NonStringKey_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := audit.NewEventKV("user_create", 123, "value")
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.Contains(t, err.Error(), "must be string")
}

// TestMustNewEventKV_OddArgs_Panics verifies that the Must form of
// NewEventKV preserves the pre-#590 panic behaviour for programmer
// errors. This is the canonical regexp.MustCompile / template.Must
// pattern — consumers who use MustNewEventKV with literal input
// accept that programmer errors crash at startup.
func TestMustNewEventKV_OddArgs_Panics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t,
		"audit: validation error: NewEventKV requires even number of arguments, got 1",
		func() {
			args := []any{"orphan"}
			audit.MustNewEventKV("user_create", args...)
		},
	)
}

func TestMustNewEventKV_NonStringKey_Panics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t,
		"audit: validation error: NewEventKV key at index 0 must be string, got int",
		func() { audit.MustNewEventKV("user_create", 123, "value") },
	)
}

// ---------------------------------------------------------------------------
// DevTaxonomy()
// ---------------------------------------------------------------------------

func TestDevTaxonomy_CreatesPermissiveTaxonomy(t *testing.T) {
	t.Parallel()
	tax := audit.DevTaxonomy("user_create", "auth_failure")
	require.NotNil(t, tax)
	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "user_create")
	assert.Contains(t, tax.Events, "auth_failure")
	assert.Contains(t, tax.Categories, "dev")
}

func TestDevTaxonomy_WarnsAtConstruction(t *testing.T) {
	// Capture slog output to verify the warning is emitted.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	auditor, err := audit.New(
		audit.WithTaxonomy(audit.DevTaxonomy("ev1")),
		audit.WithOutputs(testhelper.NewMockOutput("test")),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	assert.Contains(t, buf.String(), "DevTaxonomy",
		"slog.Warn should mention DevTaxonomy for production warning")
}

// ---------------------------------------------------------------------------
// File-free evaluation path (end-to-end)
// ---------------------------------------------------------------------------

func TestFileFreePath_EndToEnd(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	// DevTaxonomy auto-forces permissive validation — no explicit
	// WithValidationMode needed.
	auditor, err := audit.New(
		audit.WithTaxonomy(audit.DevTaxonomy("user_create")),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.MustNewEventKV("user_create", "outcome", "success", "actor_id", "alice"))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount())
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkNewEventKV(b *testing.B) {
	for b.Loop() {
		_, _ = audit.NewEventKV("user_create", "outcome", "success", "actor_id", "alice")
	}
}
