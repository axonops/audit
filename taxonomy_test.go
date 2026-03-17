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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTaxonomy returns a well-formed taxonomy for testing.
func validTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"read":     {"schema_read", "config_read"},
			"write":    {"schema_register", "schema_delete"},
			"security": {"auth_failure"},
		},
		Events: map[string]audit.EventDef{
			"schema_read":     {Category: "read", Required: []string{"outcome"}, Optional: []string{"subject"}},
			"config_read":     {Category: "read", Required: []string{"outcome"}},
			"schema_register": {Category: "write", Required: []string{"outcome", "actor_id", "subject"}, Optional: []string{"schema_type"}},
			"schema_delete":   {Category: "write", Required: []string{"outcome", "actor_id", "subject"}},
			"auth_failure":    {Category: "security", Required: []string{"outcome", "actor_id"}, Optional: []string{"reason"}},
		},
		DefaultEnabled: []string{"write", "security"},
	}
}

func TestNewLogger_ValidTaxonomy(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(validTaxonomy()),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)
	require.NoError(t, logger.Close())
}

func TestNewLogger_TaxonomyValidation(t *testing.T) {
	tests := []struct {
		name      string
		taxonomy  audit.Taxonomy
		wantError string
	}{
		{
			name: "version zero",
			taxonomy: audit.Taxonomy{
				Version:    0,
				Categories: map[string][]string{"write": {"ev1"}},
				Events:     map[string]audit.EventDef{"ev1": {Category: "write", Required: []string{"f1"}}},
			},
			wantError: "version is required",
		},
		{
			name: "version too high",
			taxonomy: audit.Taxonomy{
				Version:    999,
				Categories: map[string][]string{"write": {"ev1"}},
				Events:     map[string]audit.EventDef{"ev1": {Category: "write", Required: []string{"f1"}}},
			},
			wantError: "not supported",
		},
		{
			name: "event references non-existent category",
			taxonomy: audit.Taxonomy{
				Version:    1,
				Categories: map[string][]string{"write": {"ev1"}},
				Events: map[string]audit.EventDef{
					"ev1": {Category: "nonexistent", Required: []string{"f1"}},
				},
			},
			wantError: "does not exist in Categories",
		},
		{
			name: "duplicate event across categories",
			taxonomy: audit.Taxonomy{
				Version: 1,
				Categories: map[string][]string{
					"read":  {"ev1"},
					"write": {"ev1"},
				},
				Events: map[string]audit.EventDef{
					"ev1": {Category: "read", Required: []string{"f1"}},
				},
			},
			wantError: "appears in multiple categories",
		},
		{
			name: "field in both required and optional",
			taxonomy: audit.Taxonomy{
				Version:    1,
				Categories: map[string][]string{"write": {"ev1"}},
				Events: map[string]audit.EventDef{
					"ev1": {Category: "write", Required: []string{"f1"}, Optional: []string{"f1"}},
				},
			},
			wantError: "in both Required and Optional",
		},
		{
			name: "category member not in Events map",
			taxonomy: audit.Taxonomy{
				Version:    1,
				Categories: map[string][]string{"write": {"ev1", "ev_missing"}},
				Events: map[string]audit.EventDef{
					"ev1": {Category: "write", Required: []string{"f1"}},
				},
			},
			wantError: "not defined in Events",
		},
		{
			name: "event not listed in any category",
			taxonomy: audit.Taxonomy{
				Version:    1,
				Categories: map[string][]string{"write": {"ev1"}},
				Events: map[string]audit.EventDef{
					"ev1":    {Category: "write", Required: []string{"f1"}},
					"orphan": {Category: "write", Required: []string{"f1"}},
				},
			},
			wantError: "not listed in Categories",
		},
		{
			name: "DefaultEnabled references non-existent category",
			taxonomy: audit.Taxonomy{
				Version:        1,
				Categories:     map[string][]string{"write": {"ev1"}},
				Events:         map[string]audit.EventDef{"ev1": {Category: "write", Required: []string{"f1"}}},
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
		audit.WithTaxonomy(validTaxonomy()),
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
	tax := validTaxonomy()
	tax.Categories["lifecycle"] = []string{"startup", "shutdown"}
	tax.Events["startup"] = audit.EventDef{
		Category: "lifecycle",
		Required: []string{"custom_field"},
	}
	tax.Events["shutdown"] = audit.EventDef{
		Category: "lifecycle",
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
	err = logger.Audit("startup", audit.Fields{
		"app_name": "test",
	})
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

func TestNewLogger_TaxonomyVersionNegative(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    -1,
			Categories: map[string][]string{"write": {"ev1"}},
			Events:     map[string]audit.EventDef{"ev1": {Category: "write", Required: []string{"f1"}}},
		}),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "no longer supported")
}
