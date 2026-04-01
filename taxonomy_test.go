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
	"testing"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger_ValidTaxonomy(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)
	require.NoError(t, logger.Close())
}

func TestNewLogger_TaxonomyValidation(t *testing.T) {
	tests := []struct {
		name      string
		wantError string
		taxonomy  audit.Taxonomy
	}{
		{
			name: "version zero",
			taxonomy: audit.Taxonomy{
				Version:    0,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"f1"}}},
			},
			wantError: "version is required",
		},
		{
			name: "version too high",
			taxonomy: audit.Taxonomy{
				Version:    999,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"f1"}}},
			},
			wantError: "not supported",
		},
		{
			name: "category member not in Events map",
			taxonomy: audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1", "ev_missing"}}},
				Events: map[string]*audit.EventDef{
					"ev1": {Required: []string{"f1"}},
				},
			},
			wantError: "not defined in Events",
		},
		{
			name: "DefaultEnabled references non-existent category",
			taxonomy: audit.Taxonomy{
				Version:        1,
				Categories:     map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events:         map[string]*audit.EventDef{"ev1": {Required: []string{"f1"}}},
				DefaultEnabled: []string{"write", "nonexistent"},
			},
			wantError: "does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := audit.NewLogger(
				audit.Config{Version: 1, Enabled: true},
				audit.WithTaxonomy(tt.taxonomy),
			)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestNewLogger_TaxonomyRequired(t *testing.T) {
	_, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "taxonomy is required")
}

func TestNewLogger_LifecycleEventsInjected(t *testing.T) {
	// The taxonomy does not define startup/shutdown — they should be
	// injected automatically.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, logger.Close()) }()

	// startup and shutdown should be valid event types.
	_, err = logger.Handle("startup")
	assert.NoError(t, err)

	_, err = logger.Handle("shutdown")
	assert.NoError(t, err)
}

func TestNewLogger_LifecycleEventsPreserved(t *testing.T) {
	// Consumer defines their own startup event — it should be preserved.
	tax := testhelper.ValidTaxonomy()
	tax.Categories["lifecycle"] = &audit.CategoryDef{Events: []string{"startup", "shutdown"}}
	tax.Events["startup"] = &audit.EventDef{
		Required: []string{"custom_field"},
	}
	tax.Events["shutdown"] = &audit.EventDef{
		Required: []string{"custom_field"},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, logger.Close()) }()

	// Consumer-defined startup should still require custom_field (not
	// the default app_name).
	err = logger.AuditEvent(audit.NewEvent("startup", audit.Fields{
		"app_name": "test",
	}))
	assert.Error(t, err, "should require custom_field, not app_name")
}

func TestNewLogger_TaxonomyValidation_SentinelError(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{Version: 0}),
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, audit.ErrTaxonomyInvalid))
}

func TestValidateTaxonomy(t *testing.T) {
	t.Run("valid taxonomy passes", func(t *testing.T) {
		tax := testhelper.ValidTaxonomy()
		audit.InjectLifecycleEvents(&tax)
		err := audit.ValidateTaxonomy(tax)
		assert.NoError(t, err)
	})

	t.Run("invalid taxonomy returns ErrTaxonomyInvalid", func(t *testing.T) {
		tax := audit.Taxonomy{Version: 0}
		err := audit.ValidateTaxonomy(tax)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	})

	t.Run("empty categories returns error", func(t *testing.T) {
		tax := audit.Taxonomy{Version: 1, Events: map[string]*audit.EventDef{}}
		err := audit.ValidateTaxonomy(tax)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
		assert.Contains(t, err.Error(), "at least one category")
	})
}

func TestInjectLifecycleEvents(t *testing.T) {
	t.Run("injects startup and shutdown", func(t *testing.T) {
		tax := testhelper.ValidTaxonomy()
		audit.InjectLifecycleEvents(&tax)

		assert.Contains(t, tax.Categories, "lifecycle")
		assert.Contains(t, tax.Events, "startup")
		assert.Contains(t, tax.Events, "shutdown")
		assert.Contains(t, tax.DefaultEnabled, "lifecycle")
	})

	t.Run("preserves consumer-defined lifecycle events", func(t *testing.T) {
		tax := testhelper.ValidTaxonomy()
		tax.Categories["lifecycle"] = &audit.CategoryDef{Events: []string{"startup", "shutdown"}}
		tax.Events["startup"] = &audit.EventDef{
			Required: []string{"custom_field"},
		}
		tax.Events["shutdown"] = &audit.EventDef{
			Required: []string{"custom_field"},
		}

		audit.InjectLifecycleEvents(&tax)

		assert.Equal(t, []string{"custom_field"}, tax.Events["startup"].Required)
		assert.Equal(t, []string{"custom_field"}, tax.Events["shutdown"].Required)
	})

	t.Run("idempotent on repeated calls", func(t *testing.T) {
		tax := testhelper.ValidTaxonomy()
		audit.InjectLifecycleEvents(&tax)
		first := tax

		audit.InjectLifecycleEvents(&tax)

		assert.Equal(t, first.Version, tax.Version)
		assert.Equal(t, len(first.Events), len(tax.Events))
		assert.Equal(t, len(first.Categories), len(tax.Categories))
		// DefaultEnabled should not have duplicate "lifecycle".
		count := 0
		for _, cat := range tax.DefaultEnabled {
			if cat == "lifecycle" {
				count++
			}
		}
		assert.Equal(t, 1, count, "lifecycle should appear exactly once in DefaultEnabled")
	})

	t.Run("handles nil maps", func(t *testing.T) {
		tax := audit.Taxonomy{Version: 1}
		audit.InjectLifecycleEvents(&tax)

		assert.NotNil(t, tax.Categories)
		assert.NotNil(t, tax.Events)
		assert.Contains(t, tax.Events, "startup")
		assert.Contains(t, tax.Events, "shutdown")
	})
}

func TestMigrateTaxonomy(t *testing.T) {
	t.Run("valid version passes", func(t *testing.T) {
		tax := testhelper.ValidTaxonomy()
		err := audit.MigrateTaxonomy(&tax)
		assert.NoError(t, err)
	})

	t.Run("version zero returns error", func(t *testing.T) {
		tax := audit.Taxonomy{Version: 0}
		err := audit.MigrateTaxonomy(&tax)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	})

	t.Run("version too high returns error", func(t *testing.T) {
		tax := audit.Taxonomy{Version: 999}
		err := audit.MigrateTaxonomy(&tax)
		require.Error(t, err)
		assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	})
}

func TestNewLogger_TaxonomyVersionNegative(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    -1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
			Events:     map[string]*audit.EventDef{"ev1": {Required: []string{"f1"}}},
		}),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "no longer supported")
}
