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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
)

// ---------------------------------------------------------------------------
// Label definition parsing
// ---------------------------------------------------------------------------

func TestSensitivityLabelDefinition(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email, phone_number]
      patterns: ["^customer_"]
    financial:
      description: "Financial data"
      fields: [card_number]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
      card_number: {}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	require.NotNil(t, tax.Sensitivity)
	assert.Len(t, tax.Sensitivity.Labels, 2)
	assert.Equal(t, "Personally identifiable information", tax.Sensitivity.Labels["pii"].Description)
	assert.Equal(t, []string{"email", "phone_number"}, tax.Sensitivity.Labels["pii"].Fields)
	assert.Equal(t, []string{"^customer_"}, tax.Sensitivity.Labels["pii"].Patterns)
}

func TestNoSensitivityConfig_ZeroOverhead(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.Nil(t, tax.Sensitivity)
	assert.Nil(t, tax.Events["user_create"].FieldLabels)
}

func TestSensitivityEmptyLabels_Valid(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels: {}
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	// Empty labels block → no sensitivity config.
	assert.Nil(t, tax.Sensitivity)
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

func TestCheckSensitivity_EmptyLabelName(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    "":
      fields: [email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "label name must not be empty")
}

func TestCheckSensitivity_InvalidLabelName(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    "PII-Data":
      fields: [email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "does not match required pattern")
}

func TestCheckSensitivity_InvalidRegex(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      patterns: ["[invalid"]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "invalid")
}

func TestCheckSensitivity_GlobalFieldProtected_Timestamp(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [timestamp]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "protected framework field")
}

func TestCheckSensitivity_GlobalFieldProtected_EventType(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [event_type]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "protected framework field")
}

func TestCheckSensitivity_RegexMatchesSeverity(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      patterns: ["severity"]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "protected framework field")
}

func TestCheckSensitivity_UndefinedLabelOnField(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email:
        labels: [nonexistent]
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "undefined sensitivity label")
}

func TestCheckSensitivity_ExplicitAnnotationOnFrameworkField(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      description: "test"
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      timestamp:
        labels: [pii]
default_enabled: [write]
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "protected framework field")
}

// ---------------------------------------------------------------------------
// Label resolution from all three mechanisms
// ---------------------------------------------------------------------------

func TestPrecomputeSensitivity_ExplicitAnnotation(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      description: "test"
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email:
        labels: [pii]
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	labels := tax.Events["user_create"].FieldLabels
	require.NotNil(t, labels)
	assert.Contains(t, labels, "email")
	assert.Contains(t, labels["email"], "pii")
	assert.NotContains(t, labels, "outcome")
}

func TestPrecomputeSensitivity_GlobalFieldMapping(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [email, source_ip]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
      source_ip: {}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	labels := tax.Events["user_create"].FieldLabels
	require.NotNil(t, labels)
	assert.Contains(t, labels["email"], "pii")
	assert.Contains(t, labels["source_ip"], "pii")
}

func TestPrecomputeSensitivity_RegexPattern(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    financial:
      patterns: ["^card_"]
categories:
  write:
    - payment
events:
  payment:
    fields:
      outcome: {required: true}
      card_number: {}
      card_expiry: {}
      merchant: {}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	labels := tax.Events["payment"].FieldLabels
	require.NotNil(t, labels)
	assert.Contains(t, labels["card_number"], "financial")
	assert.Contains(t, labels["card_expiry"], "financial")
	assert.NotContains(t, labels, "merchant")
	assert.NotContains(t, labels, "outcome")
}

func TestPrecomputeSensitivity_AllThreeMechanisms(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
      patterns: ["_email$"]
    financial:
      description: "financial data"
    confidential:
      description: "internal only"
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email:
        labels: [confidential]
      contact_email: {}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	labels := tax.Events["user_create"].FieldLabels
	require.NotNil(t, labels)

	// email: explicit [confidential] + global [pii] + regex [pii] = {confidential, pii}
	assert.Contains(t, labels["email"], "pii")
	assert.Contains(t, labels["email"], "confidential")

	// contact_email: regex [pii]
	assert.Contains(t, labels["contact_email"], "pii")
}

func TestPrecomputeSensitivity_LabelsAdditive(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
    financial:
      fields: [email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	labels := tax.Events["user_create"].FieldLabels
	require.NotNil(t, labels)
	// email has BOTH labels from global mapping.
	assert.Contains(t, labels["email"], "pii")
	assert.Contains(t, labels["email"], "financial")
}

func TestPrecomputeSensitivity_NoLabeledFields(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [nonexistent_field]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
default_enabled: [write]
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	// No fields matched any label → FieldLabels is nil.
	assert.Nil(t, tax.Events["user_create"].FieldLabels)
}
