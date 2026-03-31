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
	"strings"
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
default_enabled: [write]
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

	err = logger.Audit("user_create", audit.Fields{
		"outcome":      "success",
		"actor_id":     "alice",
		"email":        "alice@example.com",
		"phone_number": "555-0100",
		"card_number":  "4111111111111111",
		"nickname":     "ally",
	})
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

	err = logger.Audit("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"email":       "alice@example.com",
		"card_number": "4111111111111111",
	})
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

	err = logger.Audit("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	// "all" output gets all fields.
	require.True(t, outAll.WaitForEvents(1, 2*time.Second))
	allEvt := outAll.GetEvent(0)
	assert.Equal(t, "alice@example.com", allEvt["email"])

	// "no-pii" output has email stripped.
	require.True(t, outNoPII.WaitForEvents(1, 2*time.Second))
	noPIIEvt := outNoPII.GetEvent(0)
	assert.Nil(t, noPIIEvt["email"])
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

	err = logger.Audit("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	})
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
default_enabled: [write]
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

	err = logger.Audit("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	})
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
default_enabled: [write]
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
default_enabled: [write]
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
default_enabled: [write]
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
default_enabled: [write]
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
default_enabled: [write]
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
default_enabled: [write]
`
	benchAuditWithExclusions(b, yml, []string{"pii"})
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
		_ = logger.Audit("user_create", fields)
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
