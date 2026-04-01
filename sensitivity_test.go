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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
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
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	// No fields matched any label → FieldLabels is nil.
	assert.Nil(t, tax.Events["user_create"].FieldLabels)
}

// ---------------------------------------------------------------------------
// Field stripping pipeline tests
// ---------------------------------------------------------------------------

const sensitivityPipelineTaxonomyYAML = `
version: 1
sensitivity:
  labels:
    pii:
      fields: [email, phone_number]
    financial:
      fields: [card_number]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
      phone_number: {}
      card_number: {}
      nickname: {}
`

func TestFieldStripping_SingleLabel(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "pii"),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":      "success",
		"actor_id":     "alice",
		"email":        "alice@example.com",
		"phone_number": "555-0100",
		"card_number":  "4111111111111111",
		"nickname":     "ally",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	evt := events[0]

	// PII fields stripped.
	assert.NotContains(t, evt, "email")
	assert.NotContains(t, evt, "phone_number")

	// Non-PII fields present.
	assert.Equal(t, "4111111111111111", evt["card_number"])
	assert.Equal(t, "ally", evt["nickname"])
	assert.Equal(t, "success", evt["outcome"])
	assert.Equal(t, "alice", evt["actor_id"])

	// Framework fields present.
	assert.Contains(t, evt, "timestamp")
	assert.Contains(t, evt, "event_type")
	assert.Contains(t, evt, "severity")
}

func TestFieldStripping_MultiLabel_AnyOverlap(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	// Exclude financial only — card_number is stripped.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "financial"),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"email":       "alice@example.com",
		"card_number": "4111111111111111",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	evt := events[0]

	// Financial field stripped, PII field kept.
	assert.NotContains(t, evt, "card_number")
	assert.Equal(t, "alice@example.com", evt["email"])
}

func TestFieldStripping_DifferentOutputs(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	outAll := testhelper.NewMockOutput("all")
	outNoPII := testhelper.NewMockOutput("no-pii")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(outAll, nil, nil),          // no exclusions
		audit.WithNamedOutput(outNoPII, nil, nil, "pii"), // exclude PII
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	// "all" output gets all fields.
	require.True(t, outAll.WaitForEvents(1, 2*time.Second))
	allEvt := outAll.GetEvent(0)
	assert.Equal(t, "alice@example.com", allEvt["email"])

	// "no-pii" output has email stripped.
	require.True(t, outNoPII.WaitForEvents(1, 2*time.Second))
	noPIIEvt := outNoPII.GetEvent(0)
	_, hasEmail := noPIIEvt["email"]
	assert.False(t, hasEmail, "email field should be absent, not nil")
	assert.Equal(t, "alice", noPIIEvt["actor_id"])
}

func TestFieldStripping_NoExclusion_AllFields(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	// No exclude_labels → all fields delivered.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	assert.Equal(t, "alice@example.com", events[0]["email"])
}

func TestFieldStripping_AllFieldsExcluded_FrameworkRemains(t *testing.T) {
	t.Parallel()

	// Taxonomy where ALL user fields are labeled.
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [outcome, actor_id, email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "pii"),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	evt := events[0]

	// All user fields stripped.
	assert.NotContains(t, evt, "outcome")
	assert.NotContains(t, evt, "actor_id")
	assert.NotContains(t, evt, "email")

	// Framework fields remain.
	assert.Contains(t, evt, "timestamp")
	assert.Equal(t, "user_create", evt["event_type"])
	assert.Contains(t, evt, "severity")
}

func TestNewLogger_ExcludeLabels_NoSensitivity(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`))
	require.NoError(t, err)

	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	require.NoError(t, err)

	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "pii"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no sensitivity config")
}

func TestNewLogger_ExcludeLabels_UndefinedLabel(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
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
      email: {}
`))
	require.NoError(t, err)

	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	require.NoError(t, err)

	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "nonexistent"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined sensitivity label")
}

// ---------------------------------------------------------------------------
// Framework field protection in field stripping
// ---------------------------------------------------------------------------

func TestFieldStripping_FrameworkFieldProtected(t *testing.T) {
	t.Parallel()

	// Even if a user somehow passes a field named "timestamp" with a
	// sensitivity label, it must not be stripped.
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [actor_id]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "pii"),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	evt := events[0]

	// Framework fields always present.
	assert.Contains(t, evt, "timestamp")
	assert.Contains(t, evt, "event_type")
	assert.Contains(t, evt, "severity")

	// Labeled user field stripped.
	assert.NotContains(t, evt, "actor_id")
}

// ---------------------------------------------------------------------------
// Pre-computed filtered EventDef tests (#199)
// ---------------------------------------------------------------------------

func TestFormatWithExclusion_ExclusionPath(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	// Output with exclusions — formatOpts should be pre-allocated.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil, "pii"),
	)
	require.NoError(t, err)

	// Emit multiple events to verify pre-computed defs work correctly.
	for i := range 10 {
		err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": fmt.Sprintf("user-%d", i),
			"email":    fmt.Sprintf("user%d@example.com", i),
		}))
		require.NoError(t, err)
	}
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 10)

	// All events should have email stripped (PII excluded).
	for i, evt := range events {
		assert.NotContains(t, evt, "email", "event %d should not have email", i)
		assert.Contains(t, evt, "actor_id", "event %d should have actor_id", i)
	}
}

func TestFormatWithExclusion_NoExclusionNoOverhead(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	require.NoError(t, err)

	// Output WITHOUT exclusions — formatOpts should be nil.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(stdout, nil, nil),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	events := parseJSONEvents(t, buf)
	require.Len(t, events, 1)
	// All fields present — no stripping.
	assert.Equal(t, "alice@example.com", events[0]["email"])
}

func TestFormatWithExclusion_MultipleOutputsDifferentExclusions(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	outAll := testhelper.NewMockOutput("all")
	outNoPII := testhelper.NewMockOutput("no-pii")
	outNoFinancial := testhelper.NewMockOutput("no-financial")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(outAll, nil, nil),
		audit.WithNamedOutput(outNoPII, nil, nil, "pii"),
		audit.WithNamedOutput(outNoFinancial, nil, nil, "financial"),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"email":       "alice@example.com",
		"card_number": "4111111111111111",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	// "all" gets everything.
	require.True(t, outAll.WaitForEvents(1, 2*time.Second))
	allEvt := outAll.GetEvent(0)
	assert.Equal(t, "alice@example.com", allEvt["email"])
	assert.Equal(t, "4111111111111111", allEvt["card_number"])

	// "no-pii" gets card_number but not email.
	require.True(t, outNoPII.WaitForEvents(1, 2*time.Second))
	noPIIEvt := outNoPII.GetEvent(0)
	_, hasEmail := noPIIEvt["email"]
	assert.False(t, hasEmail, "no-pii output should not have email")
	assert.Equal(t, "4111111111111111", noPIIEvt["card_number"])

	// "no-financial" gets email but not card_number.
	require.True(t, outNoFinancial.WaitForEvents(1, 2*time.Second))
	noFinEvt := outNoFinancial.GetEvent(0)
	assert.Equal(t, "alice@example.com", noFinEvt["email"])
	_, hasCard := noFinEvt["card_number"]
	assert.False(t, hasCard, "no-financial output should not have card_number")
}

// ---------------------------------------------------------------------------
// Concurrent field stripping
// ---------------------------------------------------------------------------

func TestFieldStripping_Concurrent(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(sensitivityPipelineTaxonomyYAML))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("concurrent")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, nil, nil, "pii"),
	)
	require.NoError(t, err)

	const goroutines = 50
	const eventsPerGoroutine = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range eventsPerGoroutine {
				_ = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
					"outcome":  "success",
					"actor_id": "alice",
					"email":    "alice@example.com",
				}))
			}
		}()
	}
	wg.Wait()
	require.NoError(t, logger.Close())

	total := goroutines * eventsPerGoroutine
	require.True(t, out.WaitForEvents(total, 5*time.Second),
		"expected %d events, got %d", total, out.EventCount())

	// Verify ALL events had email stripped.
	for i := range out.EventCount() {
		evt := out.GetEvent(i)
		_, hasEmail := evt["email"]
		assert.False(t, hasEmail, "event %d should not have email", i)
		assert.Equal(t, "alice", evt["actor_id"], "event %d actor_id", i)
	}
}

// ---------------------------------------------------------------------------
// Global mapping across multiple events
// ---------------------------------------------------------------------------

func TestPrecomputeSensitivity_GlobalMappingAcrossMultipleEvents(t *testing.T) {
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
    - user_update
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
  user_update:
    fields:
      outcome: {required: true}
      email: {}
      reason: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// Both events should have email labeled pii.
	createLabels := tax.Events["user_create"].FieldLabels
	require.NotNil(t, createLabels)
	assert.Contains(t, createLabels["email"], "pii")

	updateLabels := tax.Events["user_update"].FieldLabels
	require.NotNil(t, updateLabels)
	assert.Contains(t, updateLabels["email"], "pii")

	// reason should NOT be labeled.
	assert.NotContains(t, updateLabels, "reason")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkDeliverToOutputs_NoSensitivity(b *testing.B) {
	yml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
`
	benchAuditWithExclusions(b, yml, nil)
}

func BenchmarkDeliverToOutputs_SensitivityNoExclusions(b *testing.B) {
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
      actor_id: {required: true}
      email: {}
`
	benchAuditWithExclusions(b, yml, nil)
}

func BenchmarkDeliverToOutputs_WithExclusions(b *testing.B) {
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
      actor_id: {required: true}
      email: {}
`
	benchAuditWithExclusions(b, yml, []string{"pii"})
}

func BenchmarkDeliverToOutputs_AllFieldsExcluded(b *testing.B) {
	yml := `
version: 1
sensitivity:
  labels:
    pii:
      fields: [outcome, actor_id, email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
`
	benchAuditWithExclusions(b, yml, []string{"pii"})
}

// BenchmarkDeliverToOutputs_MultiOutput_MixedExclusion measures delivery
// throughput when one output receives all fields and one output has PII
// sensitivity exclusions active, exercising the pre-computed filteredDefs
// lookup path under realistic mixed-output conditions.
func BenchmarkDeliverToOutputs_MultiOutput_MixedExclusion(b *testing.B) {
	yml := sensitivityPipelineTaxonomyYAML
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	if err != nil {
		b.Fatal(err)
	}
	outAll := testhelper.NewMockOutput("all")
	outFiltered := testhelper.NewMockOutput("filtered")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(outAll, nil, nil),
		audit.WithNamedOutput(outFiltered, nil, nil, "pii"),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = logger.AuditEvent(audit.NewEvent("user_create", fields))
	}
}

func benchAuditWithExclusions(b *testing.B, taxonomyYAML string, excludeLabels []string) {
	b.Helper()
	tax, err := audit.ParseTaxonomyYAML([]byte(taxonomyYAML))
	if err != nil {
		b.Fatal(err)
	}
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, nil, nil, excludeLabels...),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		_ = logger.AuditEvent(audit.NewEvent("user_create", fields))
	}
}

// parseJSONEvents parses newline-delimited JSON from a buffer.
func parseJSONEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		events = append(events, m)
	}
	return events
}
