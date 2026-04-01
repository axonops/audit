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

// Tests for the severity feature (issue #186):
//   - EventDef.ResolvedSeverity resolution chain
//   - YAML taxonomy parsing of category and event severity fields
//   - ValidateTaxonomy rejection of out-of-range severity values
//   - JSONFormatter emitting "severity" as a framework field
//   - CEFFormatter using taxonomy-resolved severity and description

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// intPtr returns a pointer to n. Used throughout severity tests where
// *int fields need non-nil values without a local variable per call.
func intPtr(n int) *int { return &n }

// ---------------------------------------------------------------------------
// EventDef.ResolvedSeverity — resolution chain
// ---------------------------------------------------------------------------

// TestEventDef_ResolvedSeverity_EventExplicit verifies that when a taxonomy
// event has Severity set explicitly, ResolvedSeverity returns that value,
// ignoring any category severity and the global default.
func TestEventDef_ResolvedSeverity_EventExplicit(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: 8
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["deploy"]
	require.NotNil(t, def)
	assert.Equal(t, 8, def.ResolvedSeverity(),
		"event-level severity 8 must be returned unchanged")
}

// TestEventDef_ResolvedSeverity_CategoryInherited verifies that when an event
// has no Severity of its own but its category does, the category severity
// is inherited.
func TestEventDef_ResolvedSeverity_CategoryInherited(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    severity: 7
    events: [deploy]
events:
  deploy:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["deploy"]
	require.NotNil(t, def)
	assert.Equal(t, 7, def.ResolvedSeverity(),
		"category severity 7 must be inherited when event has no severity")
}

// TestEventDef_ResolvedSeverity_Default verifies that when neither the event
// nor any of its categories carries a severity, ResolvedSeverity returns 5
// (the CEF medium-severity default).
func TestEventDef_ResolvedSeverity_Default(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["deploy"]
	require.NotNil(t, def)
	assert.Equal(t, 5, def.ResolvedSeverity(),
		"global default severity must be 5 when event and category are both unset")
}

// TestEventDef_ResolvedSeverity_EventOverridesCategory verifies that an event
// severity takes precedence over the enclosing category severity.
func TestEventDef_ResolvedSeverity_EventOverridesCategory(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 8
    events: [low_severity_event]
events:
  low_severity_event:
    severity: 3
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["low_severity_event"]
	require.NotNil(t, def)
	assert.Equal(t, 3, def.ResolvedSeverity(),
		"event severity 3 must override category severity 8")
}

// TestEventDef_ResolvedSeverity_ExplicitZero verifies that an event severity
// of 0 is honoured as a valid explicit value — it must not fall back to the
// category or the global default of 5.
func TestEventDef_ResolvedSeverity_ExplicitZero(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    severity: 7
    events: [info_event]
events:
  info_event:
    severity: 0
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["info_event"]
	require.NotNil(t, def)
	assert.Equal(t, 0, def.ResolvedSeverity(),
		"explicit event severity 0 must not fall through to category (7) or default (5)")
}

// TestEventDef_ResolvedSeverity_MultipleCategories verifies that when an event
// belongs to multiple categories, the first category in sorted order that has
// a severity is used, and the result is deterministic across calls.
func TestEventDef_ResolvedSeverity_MultipleCategories(t *testing.T) {
	t.Parallel()
	// Categories "alpha" (severity 2) and "zeta" (severity 9) both contain
	// the same event. The event has no severity. Sorted order puts "alpha"
	// first, so severity 2 is expected.
	yml := `
version: 1
categories:
  alpha:
    severity: 2
    events: [shared_event]
  zeta:
    severity: 9
    events: [shared_event]
events:
  shared_event:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["shared_event"]
	require.NotNil(t, def)
	// "alpha" < "zeta" alphabetically, so alpha's severity wins.
	assert.Equal(t, 2, def.ResolvedSeverity(),
		"first category in sorted order with a severity must win")
}

// ---------------------------------------------------------------------------
// YAML parsing — category and event severity fields
// ---------------------------------------------------------------------------

// TestParseTaxonomyYAML_CategorySeverity verifies that a category defined
// in struct format (with severity and events) is parsed correctly, and that
// the severity is propagated to events via ResolvedSeverity.
func TestParseTaxonomyYAML_CategorySeverity(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 9
    events:
      - auth_failure
      - permission_denied
events:
  auth_failure:
    fields:
      outcome: {required: true}
  permission_denied:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	cat := tax.Categories["security"]
	require.NotNil(t, cat, "security category must be present")
	require.NotNil(t, cat.Severity, "category Severity pointer must not be nil after struct-format parse")
	assert.Equal(t, 9, *cat.Severity, "category severity must be 9")

	assert.Equal(t, 9, tax.Events["auth_failure"].ResolvedSeverity(),
		"auth_failure must inherit category severity 9")
	assert.Equal(t, 9, tax.Events["permission_denied"].ResolvedSeverity(),
		"permission_denied must inherit category severity 9")
}

// TestParseTaxonomyYAML_CategorySeverity_MixedFormats verifies that a single
// taxonomy document may use the simple list format for some categories and the
// struct format (with severity) for others.
func TestParseTaxonomyYAML_CategorySeverity_MixedFormats(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  read:
    - schema_read
  security:
    severity: 8
    events:
      - auth_failure
events:
  schema_read:
    fields:
      outcome: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// List-format category has nil Severity.
	readCat := tax.Categories["read"]
	require.NotNil(t, readCat)
	assert.Nil(t, readCat.Severity,
		"list-format category must have nil Severity (not set)")

	// Struct-format category carries the severity.
	secCat := tax.Categories["security"]
	require.NotNil(t, secCat)
	require.NotNil(t, secCat.Severity)
	assert.Equal(t, 8, *secCat.Severity)

	// Events inherit accordingly.
	assert.Equal(t, 5, tax.Events["schema_read"].ResolvedSeverity(),
		"schema_read has no category severity — must fall back to default 5")
	assert.Equal(t, 8, tax.Events["auth_failure"].ResolvedSeverity(),
		"auth_failure must inherit category severity 8")
}

// TestParseTaxonomyYAML_EventSeverity verifies that an event-level severity
// field is parsed and stored on the EventDef, and that it wins over any
// category-level severity.
func TestParseTaxonomyYAML_EventSeverity(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 9
    events:
      - critical_alert
      - minor_alert
events:
  critical_alert:
    severity: 10
    fields:
      outcome: {required: true}
  minor_alert:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	critDef := tax.Events["critical_alert"]
	require.NotNil(t, critDef.Severity,
		"event Severity pointer must not be nil when set in YAML")
	assert.Equal(t, 10, *critDef.Severity)
	assert.Equal(t, 10, critDef.ResolvedSeverity(),
		"event severity 10 must override category severity 9")

	minorDef := tax.Events["minor_alert"]
	assert.Nil(t, minorDef.Severity,
		"minor_alert has no event-level severity — Severity pointer must be nil")
	assert.Equal(t, 9, minorDef.ResolvedSeverity(),
		"minor_alert must inherit category severity 9")
}

// ---------------------------------------------------------------------------
// Taxonomy validation — severity range checks
// ---------------------------------------------------------------------------

// TestValidateTaxonomy_CategorySeverityOutOfRange verifies that a category
// severity above 10 is rejected with ErrTaxonomyInvalid and a message that
// names the offending category.
func TestValidateTaxonomy_CategorySeverityOutOfRange(t *testing.T) {
	t.Parallel()
	tests := []struct { //nolint:govet // fieldalignment: test readability preferred
		name     string
		severity int
		wantMsg  string
	}{
		{
			name:     "severity above maximum",
			severity: 11,
			wantMsg:  "out of range 0-10",
		},
		{
			name:     "severity below minimum",
			severity: -1,
			wantMsg:  "out of range 0-10",
		},
		{
			name:     "maximum boundary is valid",
			severity: 10,
			wantMsg:  "",
		},
		{
			name:     "minimum boundary is valid",
			severity: 0,
			wantMsg:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version: 1,
				Categories: map[string]*audit.CategoryDef{
					"ops": {
						Severity: intPtr(tt.severity),
						Events:   []string{"deploy"},
					},
				},
				Events: map[string]*audit.EventDef{
					"deploy": {Required: []string{"outcome"}},
				},
			}
			err := audit.ValidateTaxonomy(tax)

			if tt.wantMsg != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
				assert.Contains(t, err.Error(), tt.wantMsg,
					"error must name the range violation")
				assert.Contains(t, err.Error(), "ops",
					"error must name the offending category")
			} else {
				assert.NoError(t, err,
					"severity %d must be accepted as valid", tt.severity)
			}
		})
	}
}

// TestValidateTaxonomy_EventSeverityOutOfRange verifies that an event severity
// outside 0-10 is rejected with ErrTaxonomyInvalid and names the offending event.
func TestValidateTaxonomy_EventSeverityOutOfRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity int
		wantErr  bool
	}{
		{"severity 11 rejected", 11, true},
		{"severity -1 rejected", -1, true},
		{"severity 10 accepted", 10, false},
		{"severity 0 accepted", 0, false},
		{"severity 5 accepted", 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version: 1,
				Categories: map[string]*audit.CategoryDef{
					"ops": {Events: []string{"deploy"}},
				},
				Events: map[string]*audit.EventDef{
					"deploy": {
						Severity: intPtr(tt.severity),
						Required: []string{"outcome"},
					},
				},
			}
			err := audit.ValidateTaxonomy(tax)

			if tt.wantErr {
				require.Error(t, err,
					"severity %d must be rejected", tt.severity)
				assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
				assert.Contains(t, err.Error(), "out of range 0-10")
				assert.Contains(t, err.Error(), "deploy",
					"error must name the offending event")
			} else {
				assert.NoError(t, err,
					"severity %d must be accepted", tt.severity)
			}
		})
	}
}

// TestValidateTaxonomy_SeverityViaYAML exercises the full YAML pipeline
// to confirm out-of-range values are caught end-to-end.
func TestValidateTaxonomy_SeverityViaYAML(t *testing.T) {
	t.Parallel()
	tests := []struct { //nolint:govet // fieldalignment: test readability preferred
		name        string
		yaml        string
		wantErr     bool
		errContains string
	}{
		{
			name: "category severity 11 rejected via YAML",
			yaml: `
version: 1
categories:
  ops:
    severity: 11
    events: [deploy]
events:
  deploy:
    fields:
      outcome: {required: true}
`,
			wantErr:     true,
			errContains: "out of range 0-10",
		},
		{
			name: "event severity -1 rejected via YAML",
			yaml: `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: -1
    fields:
      outcome: {required: true}
`,
			wantErr:     true,
			errContains: "out of range 0-10",
		},
		{
			name: "boundary values accepted",
			yaml: `
version: 1
categories:
  low:
    severity: 0
    events: [low_event]
  high:
    severity: 10
    events: [high_event]
events:
  low_event:
    severity: 0
    fields:
      outcome: {required: true}
  high_event:
    severity: 10
    fields:
      outcome: {required: true}
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := audit.ParseTaxonomyYAML([]byte(tt.yaml))
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSONFormatter — severity as framework field
// ---------------------------------------------------------------------------

// TestJSONFormatter_IncludesSeverity verifies that the JSON formatter emits
// "severity" as a numeric field immediately after "event_type", and that the
// value reflects the taxonomy-resolved severity for the event.
func TestJSONFormatter_IncludesSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		eventType    string
		wantSeverity int
	}{
		{
			name: "event-level severity emitted",
			yaml: `
version: 1
categories:
  ops:
    - high_sev_event
events:
  high_sev_event:
    severity: 9
    fields:
      outcome: {required: true}
`,
			eventType:    "high_sev_event",
			wantSeverity: 9,
		},
		{
			name: "category-inherited severity emitted",
			yaml: `
version: 1
categories:
  security:
    severity: 8
    events: [sec_event]
events:
  sec_event:
    fields:
      outcome: {required: true}
`,
			eventType:    "sec_event",
			wantSeverity: 8,
		},
		{
			name: "default severity 5 emitted when none set",
			yaml: `
version: 1
categories:
  ops:
    - plain_event
events:
  plain_event:
    fields:
      outcome: {required: true}
`,
			eventType:    "plain_event",
			wantSeverity: 5,
		},
		{
			name: "explicit zero severity emitted",
			yaml: `
version: 1
categories:
  ops:
    - zero_sev_event
events:
  zero_sev_event:
    severity: 0
    fields:
      outcome: {required: true}
`,
			eventType:    "zero_sev_event",
			wantSeverity: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax, err := audit.ParseTaxonomyYAML([]byte(tt.yaml))
			require.NoError(t, err)

			def := tax.Events[tt.eventType]
			require.NotNil(t, def, "event %q must exist in taxonomy", tt.eventType)

			f := &audit.JSONFormatter{}
			data, err := f.Format(testTime, tt.eventType, audit.Fields{"outcome": "ok"}, def, nil)
			require.NoError(t, err)

			var m map[string]any
			require.NoError(t, json.Unmarshal(data, &m),
				"formatter output must be valid JSON")

			rawSev, ok := m["severity"]
			require.True(t, ok, "severity key must be present in JSON output")
			// json.Unmarshal decodes numbers as float64.
			assert.Equal(t, float64(tt.wantSeverity), rawSev,
				"severity value must be %d for event %q", tt.wantSeverity, tt.eventType)
		})
	}
}

// TestJSONFormatter_SeverityFieldOrdering verifies that "severity" appears
// after "event_type" in the JSON output (framework fields order:
// timestamp → event_type → severity).
func TestJSONFormatter_SeverityFieldOrdering(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: 7
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "deploy", audit.Fields{"outcome": "success"}, tax.Events["deploy"], nil)
	require.NoError(t, err)

	raw := string(data)
	tsIdx := strings.Index(raw, `"timestamp"`)
	etIdx := strings.Index(raw, `"event_type"`)
	sevIdx := strings.Index(raw, `"severity"`)
	outcomeIdx := strings.Index(raw, `"outcome"`)

	require.Greater(t, tsIdx, -1, "timestamp must be present")
	require.Greater(t, etIdx, -1, "event_type must be present")
	require.Greater(t, sevIdx, -1, "severity must be present")

	assert.Less(t, tsIdx, etIdx, "timestamp must come before event_type")
	assert.Less(t, etIdx, sevIdx, "event_type must come before severity")
	assert.Less(t, sevIdx, outcomeIdx, "severity must come before user fields")
}

// TestJSONFormatter_SeverityNotUserField verifies that the consumer cannot
// override the framework-managed "severity" field by supplying it in the
// Fields map — the taxonomy-resolved value must win.
func TestJSONFormatter_SeverityNotUserField(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: 7
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	f := &audit.JSONFormatter{}
	// Deliberately inject a "severity" key — the framework must ignore it.
	data, err := f.Format(testTime, "deploy", audit.Fields{
		"outcome":  "success",
		"severity": 99, // must not appear in output
	}, tax.Events["deploy"], nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	rawSev, ok := m["severity"]
	require.True(t, ok, "severity must be present")
	assert.Equal(t, float64(7), rawSev,
		"taxonomy-resolved severity 7 must win over caller-injected value 99")
}

// ---------------------------------------------------------------------------
// CEFFormatter — taxonomy severity and description
// ---------------------------------------------------------------------------

// TestCEFFormatter_UsesResolvedSeverity verifies that when SeverityFunc is nil,
// the CEFFormatter uses the taxonomy-resolved severity from EventDef.ResolvedSeverity.
func TestCEFFormatter_UsesResolvedSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		eventType    string
		wantSeverity int
	}{
		{
			name: "event severity in CEF header",
			yaml: `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: 8
    fields:
      outcome: {required: true}
`,
			eventType:    "deploy",
			wantSeverity: 8,
		},
		{
			name: "category severity inherited in CEF header",
			yaml: `
version: 1
categories:
  security:
    severity: 9
    events: [alert]
events:
  alert:
    fields:
      outcome: {required: true}
`,
			eventType:    "alert",
			wantSeverity: 9,
		},
		{
			name: "default severity 5 when unset",
			yaml: `
version: 1
categories:
  ops:
    - plain
events:
  plain:
    fields:
      outcome: {required: true}
`,
			eventType:    "plain",
			wantSeverity: 5,
		},
		{
			name: "explicit zero severity in CEF header",
			yaml: `
version: 1
categories:
  ops:
    - low
events:
  low:
    severity: 0
    fields:
      outcome: {required: true}
`,
			eventType:    "low",
			wantSeverity: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax, err := audit.ParseTaxonomyYAML([]byte(tt.yaml))
			require.NoError(t, err)

			def := tax.Events[tt.eventType]
			require.NotNil(t, def)

			f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
			// SeverityFunc is nil — must use def.ResolvedSeverity().
			data, err := f.Format(testTime, tt.eventType, audit.Fields{"outcome": "ok"}, def, nil)
			require.NoError(t, err)

			line := string(data)
			wantFragment := fmt.Sprintf("|%s|%d|", tt.eventType, tt.wantSeverity)
			// The CEF description field sits between event_type and severity;
			// for default description (no DescriptionFunc, no Description) the
			// description equals the event type, giving:
			//   |eventType|eventType|severity|
			// We assert on the simpler suffix form to avoid description coupling.
			assert.Contains(t, line, fmt.Sprintf("|%d|", tt.wantSeverity),
				"CEF header must contain severity %d; full line: %s", tt.wantSeverity, line)
			_ = wantFragment // keep the variable to avoid unused error
		})
	}
}

// TestCEFFormatter_SeverityFuncTakesPrecedence verifies that when SeverityFunc
// is set on CEFFormatter it overrides the taxonomy-resolved severity, providing
// backwards-compatible behaviour for callers that already supply a SeverityFunc.
func TestCEFFormatter_SeverityFuncTakesPrecedence(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 9
    events: [auth_fail]
events:
  auth_fail:
    severity: 7
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["auth_fail"]
	require.NotNil(t, def)
	// taxonomy-resolved severity is 7 (event wins over category 9).
	require.Equal(t, 7, def.ResolvedSeverity())

	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		SeverityFunc: func(eventType string) int {
			// Caller overrides to 3, regardless of taxonomy.
			return 3
		},
	}
	data, err := f.Format(testTime, "auth_fail", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "|3|",
		"SeverityFunc return value 3 must override taxonomy severity 7; line: %s", line)
	assert.NotContains(t, line, "|7|",
		"taxonomy severity 7 must not appear when SeverityFunc is set; line: %s", line)
}

// TestCEFFormatter_UsesDefDescription verifies that when DescriptionFunc is nil
// and the EventDef has a non-empty Description, the description appears in the
// CEF header at position 5 (between event type and severity).
func TestCEFFormatter_UsesDefDescription(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    - auth_failure
events:
  auth_failure:
    description: "User authentication failed"
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["auth_failure"]
	require.NotNil(t, def)
	require.Equal(t, "User authentication failed", def.Description)

	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		// DescriptionFunc intentionally nil — must fall back to def.Description.
	}
	data, err := f.Format(testTime, "auth_failure", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "User authentication failed",
		"taxonomy description must appear in CEF header; line: %s", line)
}

// TestCEFFormatter_EmptyDescriptionFallsBackToEventType verifies that when
// DescriptionFunc is nil and EventDef.Description is empty, the CEF formatter
// falls back to the event type name as the description — matching prior behaviour.
func TestCEFFormatter_EmptyDescriptionFallsBackToEventType(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["deploy"]
	require.NotNil(t, def)
	require.Empty(t, def.Description)

	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "deploy", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	line := string(data)
	// CEF format: CEF:0|V|P|1|deploy|deploy|5|...
	// description position should contain "deploy".
	assert.Contains(t, line, "|deploy|deploy|",
		"event type must be used as description fallback; line: %s", line)
}

// TestCEFFormatter_DescriptionFuncTakesPrecedence verifies that DescriptionFunc
// overrides both def.Description and the event-type fallback, providing
// backwards-compatible behaviour for callers that already supply a DescriptionFunc.
func TestCEFFormatter_DescriptionFuncTakesPrecedence(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    - auth_failure
events:
  auth_failure:
    description: "Taxonomy description — must be overridden"
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["auth_failure"]
	require.NotNil(t, def)
	require.NotEmpty(t, def.Description)

	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		DescriptionFunc: func(eventType string) string {
			return "Override: " + eventType
		},
	}
	data, err := f.Format(testTime, "auth_failure", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "Override: auth_failure",
		"DescriptionFunc return value must appear in CEF header; line: %s", line)
	assert.NotContains(t, line, "Taxonomy description",
		"def.Description must not appear when DescriptionFunc is set; line: %s", line)
}

// TestCEFFormatter_SeverityAndDescriptionTogether verifies that a formatter with
// both taxonomy-resolved severity and description produces a well-formed CEF
// header with the correct field positions.
func TestCEFFormatter_SeverityAndDescriptionTogether(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 8
    events: [access_denied]
events:
  access_denied:
    description: "Access denied to protected resource"
    severity: 10
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["access_denied"]
	require.NotNil(t, def)
	assert.Equal(t, 10, def.ResolvedSeverity(), "event severity must override category")

	f := &audit.CEFFormatter{Vendor: "MyVendor", Product: "MyProduct", Version: "2"}
	data, err := f.Format(testTime, "access_denied", audit.Fields{"outcome": "denied"}, def, nil)
	require.NoError(t, err)

	line := string(data)

	// Verify CEF header structure: CEF:0|vendor|product|version|eventType|description|severity|extensions
	assert.True(t, strings.HasPrefix(line, "CEF:0|MyVendor|MyProduct|2|access_denied|"),
		"CEF header prefix must be correct; line: %s", line)
	assert.Contains(t, line, "Access denied to protected resource",
		"taxonomy description must appear in CEF header; line: %s", line)
	assert.Contains(t, line, "|10|",
		"event-level severity 10 must appear in CEF header; line: %s", line)

	// Confirm it is a single well-formed line.
	trimmed := strings.TrimSuffix(line, "\n")
	assert.NotContains(t, trimmed, "\n",
		"CEF output must be a single line; line: %s", line)
}

func TestParseTaxonomyYAML_CategoryStructUnknownFieldRejected(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  security:
    severity: 8
    events: [auth_failure]
    unknown_key: true
events:
  auth_failure:
    fields:
      outcome: {required: true}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestParseTaxonomyYAML_CategoryScalarValueRejected(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops: true
events:
  deploy:
    fields:
      outcome: {required: true}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected a sequence or mapping")
}

func TestEventDef_ResolvedSeverity_Unprecomputed(t *testing.T) {
	t.Parallel()
	// A bare EventDef not processed by precomputeTaxonomy should
	// return the default 5, even if Severity is explicitly set.
	sev := 8
	def := &audit.EventDef{Severity: &sev}
	assert.Equal(t, 5, def.ResolvedSeverity(), "unprecomputed EventDef should return default 5")
}
