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

func TestValidateTaxonomy_AllReservedFields_RejectedAsRequired(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"timestamp", "event_type", "severity", "event_category"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events: map[string]*audit.EventDef{
					"ev1": {Required: []string{field}},
				},
			}
			err := audit.ValidateTaxonomy(tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
			assert.Contains(t, err.Error(), "reserved framework field")
			assert.Contains(t, err.Error(), field)
		})
	}
}

func TestValidateTaxonomy_AllReservedFields_RejectedAsOptional(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"timestamp", "event_type", "severity", "event_category"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
				Events: map[string]*audit.EventDef{
					"ev1": {Required: []string{"outcome"}, Optional: []string{field}},
				},
			}
			err := audit.ValidateTaxonomy(tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
			assert.Contains(t, err.Error(), "reserved framework field")
			assert.Contains(t, err.Error(), field)
		})
	}
}

func TestValidateTaxonomy_DurationMs_AllowedAsOptional(t *testing.T) {
	t.Parallel()
	// duration_ms is a framework field for sensitivity protection but
	// is NOT reserved — it can be used as an optional user field.
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"outcome"}, Optional: []string{"duration_ms"}},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	assert.NoError(t, err)
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
