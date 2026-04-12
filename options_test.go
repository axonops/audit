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
	"sync"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// ---------------------------------------------------------------------------
// NewLogger default config (#388 AC-1)
// ---------------------------------------------------------------------------

func TestNewLogger_NoConfigOptions_UsesDefaults(t *testing.T) {
	defer goleak.VerifyNone(t)
	out := testhelper.NewMockOutput("defaults")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Emit an event to verify the logger works with defaults.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())
	assert.Equal(t, 1, out.EventCount(), "default logger should deliver events")
}

// ---------------------------------------------------------------------------
// NewLogger without taxonomy (#388 AC-2)
// ---------------------------------------------------------------------------

func TestNewLogger_WithoutTaxonomy_ReturnsError(t *testing.T) {
	_, err := audit.NewLogger()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "taxonomy is required")
}

// ---------------------------------------------------------------------------
// WithDisabled (#388 AC-3)
// ---------------------------------------------------------------------------

func TestNewLogger_WithDisabled_CreatesNoOpLogger(t *testing.T) {
	defer goleak.VerifyNone(t)
	out := testhelper.NewMockOutput("disabled")
	logger, err := audit.NewLogger(
		audit.WithDisabled(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Disabled logger returns nil without delivering.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	assert.NoError(t, err)
	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.EventCount(), "disabled logger must not deliver events")
}

func TestNewLogger_WithDisabled_NoTaxonomy(t *testing.T) {
	defer goleak.VerifyNone(t)
	logger, err := audit.NewLogger(audit.WithDisabled())
	require.NoError(t, err, "disabled logger must not require a taxonomy")
	require.NotNil(t, logger)
	assert.True(t, logger.IsDisabled())

	// AuditEvent silently discards.
	err = logger.AuditEvent(audit.NewEvent("anything", audit.Fields{"k": "v"}))
	assert.NoError(t, err)

	// Close is safe.
	assert.NoError(t, logger.Close())
}

func TestDisabledLogger_EnableCategory_ReturnsErrDisabled(t *testing.T) {
	logger, err := audit.NewLogger(audit.WithDisabled())
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	assert.ErrorIs(t, logger.EnableCategory("foo"), audit.ErrDisabled)
	assert.ErrorIs(t, logger.DisableCategory("foo"), audit.ErrDisabled)
	assert.ErrorIs(t, logger.EnableEvent("foo"), audit.ErrDisabled)
	assert.ErrorIs(t, logger.DisableEvent("foo"), audit.ErrDisabled)
	assert.ErrorIs(t, logger.SetOutputRoute("foo", nil), audit.ErrDisabled)
}

func TestDisabledLogger_Handle_ReturnsValidHandle(t *testing.T) {
	logger, err := audit.NewLogger(audit.WithDisabled())
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	handle, handleErr := logger.Handle("anything")
	require.NoError(t, handleErr)
	require.NotNil(t, handle)
	assert.Equal(t, "anything", handle.EventType())

	// Audit on the handle silently discards.
	assert.NoError(t, handle.Audit(audit.Fields{"k": "v"}))
}

func TestDisabledLogger_MustHandle_DoesNotPanic(t *testing.T) {
	logger, err := audit.NewLogger(audit.WithDisabled())
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	assert.NotPanics(t, func() {
		h := logger.MustHandle("anything")
		assert.NotNil(t, h)
	})
}

// ---------------------------------------------------------------------------
// WithBufferSize (#388 AC-4)
// ---------------------------------------------------------------------------

func TestNewLogger_WithBufferSize_SetsCustomSize(t *testing.T) {
	defer goleak.VerifyNone(t)
	logger, err := audit.NewLogger(
		audit.WithBufferSize(50000),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_WithBufferSize_RejectsOverMax(t *testing.T) {
	_, err := audit.NewLogger(
		audit.WithBufferSize(audit.MaxBufferSize+1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// ---------------------------------------------------------------------------
// WithDrainTimeout (#388 AC-5)
// ---------------------------------------------------------------------------

func TestNewLogger_WithDrainTimeout_SetsCustomTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	logger, err := audit.NewLogger(
		audit.WithDrainTimeout(30*time.Second),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_WithDrainTimeout_RejectsOverMax(t *testing.T) {
	_, err := audit.NewLogger(
		audit.WithDrainTimeout(audit.MaxDrainTimeout+1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// ---------------------------------------------------------------------------
// WithValidationMode (#388 AC-6)
// ---------------------------------------------------------------------------

func TestNewLogger_WithValidationMode_SetsMode(t *testing.T) {
	defer goleak.VerifyNone(t)
	out := testhelper.NewMockOutput("permissive")
	logger, err := audit.NewLogger(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Unknown fields accepted in permissive mode.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"bogus":    "value",
	}))
	assert.NoError(t, err, "permissive mode should accept unknown fields")
	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// WithOmitEmpty (#388 AC-7)
// ---------------------------------------------------------------------------

func TestNewLogger_WithOmitEmpty_OmitsZeroFields(t *testing.T) {
	defer goleak.VerifyNone(t)
	out := testhelper.NewMockOutput("omit-empty")
	logger, err := audit.NewLogger(
		audit.WithOmitEmpty(),
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"empty":    "",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())
	require.Equal(t, 1, out.EventCount())

	ev := out.GetEvent(0)
	_, hasEmpty := ev["empty"]
	assert.False(t, hasEmpty, "empty string field should be omitted with WithOmitEmpty")
}

// ---------------------------------------------------------------------------
// WithConfig (#388 AC-8, AC-9)
// ---------------------------------------------------------------------------

func TestNewLogger_WithConfig_AppliesStructFields(t *testing.T) {
	defer goleak.VerifyNone(t)
	logger, err := audit.NewLogger(
		audit.WithConfig(audit.Config{BufferSize: 50000}),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_WithConfig_IndividualOptionOverrides(t *testing.T) {
	defer goleak.VerifyNone(t)
	// WithConfig sets BufferSize=100, then WithBufferSize(200) overrides.
	// Last option wins.
	logger, err := audit.NewLogger(
		audit.WithConfig(audit.Config{BufferSize: 100}),
		audit.WithBufferSize(200),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// Config.version unexported (#388 AC-10)
// ---------------------------------------------------------------------------

func TestConfig_VersionUnexported(t *testing.T) {
	// This test verifies that Config{} compiles without Version.
	// If Version were exported, this would be a different test.
	cfg := audit.Config{BufferSize: 100}
	assert.Equal(t, 100, cfg.BufferSize)
}

// ---------------------------------------------------------------------------
// Fields defined type (#388 AC-12, AC-13, AC-14)
// ---------------------------------------------------------------------------

func TestFields_DefinedType_Conversion(t *testing.T) {
	// Explicit conversion from map[string]any compiles.
	m := map[string]any{"k": "v"}
	f := audit.Fields(m)
	assert.Equal(t, "v", f["k"])
}

func TestFields_DefinedType_Has(t *testing.T) {
	f := audit.Fields{"k": "v"}
	assert.True(t, f.Has("k"))
	assert.False(t, f.Has("missing"))
}

func TestFields_DefinedType_String(t *testing.T) {
	f := audit.Fields{"name": "alice", "count": 42}
	assert.Equal(t, "alice", f.String("name"))
	assert.Equal(t, "", f.String("count"), "non-string should return empty")
	assert.Equal(t, "", f.String("missing"), "missing key should return empty")
}

func TestFields_DefinedType_Int(t *testing.T) {
	f := audit.Fields{"count": 42, "rate": 3.14, "name": "alice"}
	assert.Equal(t, 42, f.Int("count"))
	assert.Equal(t, 3, f.Int("rate"), "float64 should truncate to int")
	assert.Equal(t, 0, f.Int("name"), "non-numeric should return 0")
	assert.Equal(t, 0, f.Int("missing"), "missing key should return 0")
}

// ---------------------------------------------------------------------------
// SuppressEventCategory zero value (#388 AC-15)
// ---------------------------------------------------------------------------

func TestSuppressEventCategory_ZeroValue_EmitsCategory(t *testing.T) {
	var tax audit.Taxonomy
	assert.False(t, tax.SuppressEventCategory, "zero value should be false (emit category)")
}

func TestSuppressEventCategory_True_SuppressesCategory(t *testing.T) {
	defer goleak.VerifyNone(t)
	out := testhelper.NewMockOutput("suppress-cat")
	tax := &audit.Taxonomy{
		Version:               1,
		SuppressEventCategory: true,
		Categories:            map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events:                map[string]*audit.EventDef{"auth_failure": {Required: []string{"outcome", "actor_id"}}},
	}
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())
	require.Equal(t, 1, out.EventCount())

	ev := out.GetEvent(0)
	_, hasCategory := ev["event_category"]
	assert.False(t, hasCategory, "event_category should be suppressed when SuppressEventCategory=true")
}

// ---------------------------------------------------------------------------
// Concurrent construction (#388 AC-16 subset)
// ---------------------------------------------------------------------------

func TestNewLogger_ConcurrentConstruction_NoRace(t *testing.T) {
	defer goleak.VerifyNone(t)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine gets its own taxonomy to avoid data race
			// on internal precomputation (precomputeTaxonomy mutates
			// EventDef slices/maps).
			tax := testhelper.ValidTaxonomy()
			logger, err := audit.NewLogger(
				audit.WithTaxonomy(tax),
			)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			_ = logger.Close()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Benchmark: NewLogger construction (#388)
// ---------------------------------------------------------------------------

func BenchmarkNewLogger_Construction(b *testing.B) {
	tax := testhelper.ValidTaxonomy()
	out := testhelper.NewMockOutput("bench")

	for b.Loop() {
		logger, err := audit.NewLogger(
			audit.WithTaxonomy(tax),
			audit.WithOutputs(out),
		)
		if err != nil {
			b.Fatal(err)
		}
		_ = logger.Close()
	}
}
