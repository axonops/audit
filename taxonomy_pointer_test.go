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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseTaxonomyYAML returns *Taxonomy (#389 AC-1, AC-2)
// ---------------------------------------------------------------------------

func TestParseTaxonomyYAML_ValidInput_ReturnsPointer(t *testing.T) {
	t.Parallel()
	yaml := []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`)
	tax, err := audit.ParseTaxonomyYAML(yaml)
	require.NoError(t, err)
	require.NotNil(t, tax, "ParseTaxonomyYAML should return non-nil pointer on success")
	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "user_create")
}

func TestParseTaxonomyYAML_InvalidInput_ReturnsNilAndError(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte("not valid yaml: ["))
	require.Error(t, err)
	assert.Nil(t, tax, "ParseTaxonomyYAML should return nil on error")
}

func TestParseTaxonomyYAML_EmptyInput_ReturnsNilAndError(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML(nil)
	require.Error(t, err)
	assert.Nil(t, tax)
}

// ---------------------------------------------------------------------------
// WithTaxonomy nil check (#389 AC-3)
// ---------------------------------------------------------------------------

func TestWithTaxonomy_NilPointer_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := audit.New(
		audit.WithTaxonomy(nil),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "taxonomy must not be nil")
}

// ---------------------------------------------------------------------------
// WithTaxonomy skips re-validation (#389 AC-7)
// ---------------------------------------------------------------------------

func TestWithTaxonomy_ParsedTaxonomy_SkipsRevalidation(t *testing.T) {
	t.Parallel()

	// Parse a valid taxonomy — this sets the internal validated flag.
	yaml := []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`)
	tax, err := audit.ParseTaxonomyYAML(yaml)
	require.NoError(t, err)

	// Create auditor — should succeed without re-validating.
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Verify the auditor works.
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount())
}

// ---------------------------------------------------------------------------
// Deep copy prevents post-construction mutation (#389 AC-6)
// ---------------------------------------------------------------------------

func TestWithTaxonomy_PostConstructionMutation_DoesNotAffectAuditor(t *testing.T) {
	t.Parallel()

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Required: []string{"outcome"},
				Optional: []string{"details"},
			},
		},
	}

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Mutate the original taxonomy AFTER auditor creation.
	delete(tax.Events, "user_create")
	tax.Events["hacked_event"] = &audit.EventDef{Required: []string{"x"}}

	// The auditor should still accept user_create (uses the deep copy).
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
	}))
	require.NoError(t, err, "auditor should use deep copy, not the mutated original")

	// The auditor should NOT accept hacked_event (not in the copy).
	err = auditor.AuditEvent(audit.NewEvent("hacked_event", audit.Fields{
		"x": "y",
	}))
	require.Error(t, err, "hacked_event should not be in the auditor's taxonomy")
	assert.ErrorIs(t, err, audit.ErrUnknownEventType)
	assert.Contains(t, err.Error(), "unknown event type")

	require.NoError(t, auditor.Close())
}

// ---------------------------------------------------------------------------
// Inline taxonomy with & (#389 AC-9)
// ---------------------------------------------------------------------------

func TestWithTaxonomy_InlineTaxonomy_TakesAddress(t *testing.T) {
	t.Parallel()

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write": {Events: []string{"ev1"}},
			},
			Events: map[string]*audit.EventDef{
				"ev1": {Required: []string{"f1"}},
			},
		}),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}
