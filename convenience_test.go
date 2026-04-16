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
// Stdout()
// ---------------------------------------------------------------------------

func TestStdout_ReturnsWorkingOutput(t *testing.T) {
	t.Parallel()
	out := audit.Stdout()
	require.NotNil(t, out)
	assert.Equal(t, "stdout", out.Name())
}

// ---------------------------------------------------------------------------
// NewEventKV()
// ---------------------------------------------------------------------------

func TestNewEventKV_ValidPairs(t *testing.T) {
	t.Parallel()
	evt := audit.NewEventKV("user_create", "outcome", "success", "actor_id", "alice")
	assert.Equal(t, "user_create", evt.EventType())
	assert.Equal(t, "success", evt.Fields()["outcome"])
	assert.Equal(t, "alice", evt.Fields()["actor_id"])
}

func TestNewEventKV_EmptyFields(t *testing.T) {
	t.Parallel()
	evt := audit.NewEventKV("user_create")
	assert.Equal(t, "user_create", evt.EventType())
	assert.Empty(t, evt.Fields())
}

func TestNewEventKV_OddArgs_Panics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t,
		"audit: NewEventKV requires even number of arguments, got 1",
		func() {
			args := []any{"orphan"}
			audit.NewEventKV("user_create", args...) //nolint:staticcheck // intentional odd-args test
		},
	)
}

func TestNewEventKV_NonStringKey_Panics(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t,
		"audit: NewEventKV key at index 0 must be string, got int",
		func() { audit.NewEventKV("user_create", 123, "value") },
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

	err = auditor.AuditEvent(audit.NewEventKV("user_create", "outcome", "success", "actor_id", "alice"))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount())
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkNewEventKV(b *testing.B) {
	for b.Loop() {
		_ = audit.NewEventKV("user_create", "outcome", "success", "actor_id", "alice")
	}
}
