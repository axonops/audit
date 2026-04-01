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

// Tests for the multi-category (#188) and severity (#186) features that
// span the full pipeline from taxonomy configuration through Logger
// delivery to formatted output. These complement the unit-level tests
// in severity_test.go with end-to-end and concurrency cases.

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Full pipeline: multi-category + severity end-to-end
// ---------------------------------------------------------------------------

// TestPipeline_MultiCategory_SeverityInJSON verifies the complete pipeline
// for an event that belongs to two categories with different severities.
// The event is in "compliance" (severity 3) and "security" (severity 8).
// Alphabetical ordering means "compliance" < "security", so the resolved
// severity is 3. Both category passes deliver to an unrouted output,
// producing exactly two JSON payloads each containing "severity":3.
func TestPipeline_MultiCategory_SeverityInJSON(t *testing.T) {
	t.Parallel()

	const yml = `
version: 1
categories:
  compliance:
    severity: 3
    events: [auth_failure]
  security:
    severity: 8
    events: [auth_failure]
events:
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// "compliance" < "security" alphabetically; resolved severity must be 3.
	require.Equal(t, 3, tax.Events["auth_failure"].ResolvedSeverity(),
		"pre-condition: resolved severity must be 3 (compliance wins alphabetically)")

	out := testhelper.NewMockOutput("pipeline")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.NoError(t, err)

	// Two categories → two deliveries to an unrouted output.
	require.True(t, out.WaitForEvents(2, 2*time.Second),
		"expected 2 deliveries (one per enabled category), got %d", out.EventCount())
	require.Equal(t, 2, out.EventCount())

	// Both deliveries must carry severity 3 (single precomputed value,
	// not per-category).
	for i := 0; i < 2; i++ {
		ev := out.GetEvent(i)
		rawSev, ok := ev["severity"]
		require.True(t, ok, "event[%d]: severity key must be present in JSON output", i)
		// json.Unmarshal decodes numbers as float64.
		assert.Equal(t, float64(3), rawSev,
			"event[%d]: severity must be 3 (compliance wins alphabetically over security)", i)
	}
}

// TestPipeline_MultiCategory_SeverityConsistentAcrossPasses verifies that
// the severity field in the JSON output is the same for both deliveries of
// a multi-category event. The value is precomputed once at taxonomy load
// time and must not vary between the compliance pass and the beta pass.
//
// Categories: "alpha" (severity 3), "beta" (severity 7).
// "alpha" < "beta" alphabetically → resolved severity is 3.
func TestPipeline_MultiCategory_SeverityConsistentAcrossPasses(t *testing.T) {
	t.Parallel()

	const yml = `
version: 1
categories:
  alpha:
    severity: 3
    events: [shared_event]
  beta:
    severity: 7
    events: [shared_event]
events:
  shared_event:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	require.Equal(t, 3, tax.Events["shared_event"].ResolvedSeverity(),
		"pre-condition: alpha (3) < beta (7) alphabetically, so severity must be 3")

	out := testhelper.NewMockOutput("consistent")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.AuditEvent(audit.NewEvent("shared_event", audit.Fields{"outcome": "success"})))

	require.True(t, out.WaitForEvents(2, 2*time.Second),
		"expected 2 deliveries, got %d", out.EventCount())

	// Parse both payloads and confirm severity is identical.
	sev0 := out.GetEvent(0)["severity"]
	sev1 := out.GetEvent(1)["severity"]
	assert.Equal(t, float64(3), sev0,
		"first delivery (alpha pass) must carry severity 3")
	assert.Equal(t, float64(3), sev1,
		"second delivery (beta pass) must carry severity 3 — same precomputed value")
	assert.Equal(t, sev0, sev1,
		"severity must be identical across all deliveries of the same event")
}

// TestPipeline_ThreeCategories_DeliveryCount verifies that an event in three
// enabled categories is delivered exactly three times to an unrouted output.
func TestPipeline_ThreeCategories_DeliveryCount(t *testing.T) {
	t.Parallel()

	const yml = `
version: 1
categories:
  alpha:
    - multi_event
  beta:
    - multi_event
  gamma:
    - multi_event
events:
  multi_event:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("three-cats")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.AuditEvent(audit.NewEvent("multi_event", audit.Fields{"outcome": "success"})))

	require.True(t, out.WaitForEvents(3, 2*time.Second),
		"expected 3 deliveries (one per category), got %d", out.EventCount())
	assert.Equal(t, 3, out.EventCount())
}

// TestPipeline_MultiCategory_ConcurrentFilterMutation verifies that
// concurrent EnableCategory / DisableCategory calls while a multi-category
// event is being audited from multiple goroutines produce no data race and
// no panic. The race detector validates the absence of unsafe concurrent
// access. We do not assert on the delivery count because the filter state
// is intentionally non-deterministic during the race.
func TestPipeline_MultiCategory_ConcurrentFilterMutation(t *testing.T) {
	t.Parallel()

	const yml = `
version: 1
categories:
  security:
    events: [auth_failure]
  compliance:
    events: [auth_failure]
events:
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("concurrent-filter")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	// Do not use t.Cleanup here: we close explicitly after WaitGroup so
	// the drain goroutine is still running during the concurrent phase.

	const writers = 25
	const mutators = 25

	var wg sync.WaitGroup
	wg.Add(writers + mutators)

	// Writers: audit the multi-category event concurrently.
	for i := 0; i < writers; i++ {
		go func(n int) {
			defer wg.Done()
			_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": fmt.Sprintf("writer-%d", n),
			}))
		}(i)
	}

	// Mutators: toggle categories concurrently with the writers.
	for i := 0; i < mutators; i++ {
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				_ = logger.EnableCategory("security")
				_ = logger.DisableCategory("compliance")
			} else {
				_ = logger.DisableCategory("security")
				_ = logger.EnableCategory("compliance")
			}
		}(i)
	}

	wg.Wait()

	// Close drains remaining events. If there is a data race the -race
	// detector will have already fired before we reach this point.
	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// Strengthened CEF severity assertion
// ---------------------------------------------------------------------------

// TestCEFFormatter_UsesResolvedSeverity_Positional rewrites the existing
// TestCEFFormatter_UsesResolvedSeverity assertion to check the exact
// pipe-delimited position of the severity field in the CEF header instead
// of relying on Contains("|N|"). A CEF header has the form:
//
//	CEF:0|vendor|product|version|eventType|description|severity|extensions
//
// That is 8 pipe-separated fields (index 0–7), where severity is at index 6.
// Contains("|5|") is weak because it would also match an extension value or
// the event type.
func TestCEFFormatter_UsesResolvedSeverity_Positional(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		eventType    string
		wantSeverity int
	}{
		{
			name: "event-level severity at CEF position 6",
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
			name: "category-inherited severity at CEF position 6",
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
			name: "default severity 5 at CEF position 6 when unset",
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
			name: "explicit zero severity at CEF position 6",
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
			data, err := f.Format(testTime, tt.eventType, audit.Fields{"outcome": "ok"}, def, nil)
			require.NoError(t, err)

			line := strings.TrimSuffix(string(data), "\n")

			// CEF format: CEF:0|vendor|product|version|eventType|description|severity|extensions
			// Split on "|" — SplitN with n=8 gives exactly 8 fields when
			// the extension section may contain "|"-delimited key=value pairs.
			parts := strings.SplitN(line, "|", 8)
			require.Len(t, parts, 8,
				"CEF line must have exactly 8 pipe-delimited sections; line: %s", line)

			// Index 6 is the severity field (0-indexed).
			gotSev := parts[6]
			wantStr := fmt.Sprintf("%d", tt.wantSeverity)
			assert.Equal(t, wantStr, gotSev,
				"CEF header severity at pipe position 6 must be %d; full line: %s",
				tt.wantSeverity, line)
		})
	}
}

// TestCEFFormatter_SeverityNotSubstringAmbiguous verifies that
// asserting on the positional CEF field catches cases where the
// event type or extensions happen to contain the severity digit,
// which a naive Contains("|N|") check would pass incorrectly.
//
// Concretely: event type "level5_event" contains "5"; if we only check
// Contains("|5|") the test passes even when severity is wrong. This test
// uses an event with severity 0 and an event type containing "5" to
// confirm that positional checking catches the ambiguity.
func TestCEFFormatter_SeverityNotSubstringAmbiguous(t *testing.T) {
	t.Parallel()

	const yml = `
version: 1
categories:
  ops:
    - level5_event
events:
  level5_event:
    severity: 0
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	def := tax.Events["level5_event"]
	require.NotNil(t, def)
	require.Equal(t, 0, def.ResolvedSeverity())

	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "level5_event", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	line := strings.TrimSuffix(string(data), "\n")
	parts := strings.SplitN(line, "|", 8)
	require.Len(t, parts, 8, "CEF line must have 8 sections; line: %s", line)

	// The event type "level5_event" is at position 4 and contains "5".
	// A Contains("|5|") check would incorrectly pass.
	// The positional check must find "0" at position 6.
	assert.Equal(t, "0", parts[6],
		"severity at pipe position 6 must be 0, not the '5' in the event type; line: %s", line)
}

// ---------------------------------------------------------------------------
// JSON output: severity field parsing via full logger pipeline
// ---------------------------------------------------------------------------

// TestPipeline_SeverityInJSONOutput exercises the complete async pipeline
// (Audit → channel → drainLoop → JSONFormatter → MockOutput) to confirm
// that the "severity" field in the JSON output reflects the taxonomy-resolved
// severity, not a zero value or a stale default.
func TestPipeline_SeverityInJSONOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		yaml         string
		eventType    string
		wantSeverity int
	}{
		{
			name: "event-level severity flows through pipeline",
			yaml: `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    severity: 7
    fields:
      outcome: {required: true}
`,
			eventType:    "deploy",
			wantSeverity: 7,
		},
		{
			name: "category severity inherited through pipeline",
			yaml: `
version: 1
categories:
  security:
    severity: 9
    events: [auth_fail]
events:
  auth_fail:
    fields:
      outcome: {required: true}
`,
			eventType:    "auth_fail",
			wantSeverity: 9,
		},
		{
			name: "default severity 5 emitted when no severity set",
			yaml: `
version: 1
categories:
  ops:
    - ping
events:
  ping:
    fields:
      outcome: {required: true}
`,
			eventType:    "ping",
			wantSeverity: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax, err := audit.ParseTaxonomyYAML([]byte(tt.yaml))
			require.NoError(t, err)

			out := testhelper.NewMockOutput("sev-pipeline")
			logger, err := audit.NewLogger(
				audit.Config{Version: 1, Enabled: true},
				audit.WithTaxonomy(tax),
				audit.WithOutputs(out),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = logger.Close() })

			require.NoError(t, logger.AuditEvent(audit.NewEvent(tt.eventType, audit.Fields{"outcome": "ok"})))
			require.True(t, out.WaitForEvents(1, 2*time.Second))

			ev := out.GetEvent(0)
			rawSev, ok := ev["severity"]
			require.True(t, ok, "severity key must be present in JSON output")

			// json.Unmarshal decodes numbers as float64.
			assert.Equal(t, float64(tt.wantSeverity), rawSev,
				"severity in JSON output must be %d", tt.wantSeverity)
		})
	}
}

// TestPipeline_MultiCategory_MixedCategoryFormats verifies that a taxonomy
// using both the simple list format (no severity) and the struct format
// (with severity) for different categories parses correctly and delivers
// events with the right resolved severity via the full pipeline.
func TestPipeline_MultiCategory_MixedCategoryFormats(t *testing.T) {
	t.Parallel()

	// "ops" uses list format (no severity → nil) and "security" uses
	// struct format (severity 8). auth_failure is in both; alphabetical
	// ordering "ops" < "security" so resolved severity would be 5 (ops has
	// no severity, falls through). Wait — ops has no severity so we skip it
	// and land on security's 8.
	//
	// Resolution: event Severity nil → iterate categories alphabetically →
	// ops: nil (skip) → security: 8 → return 8.
	const yml = `
version: 1
categories:
  ops:
    - auth_failure
  security:
    severity: 8
    events: [auth_failure]
events:
  auth_failure:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// Confirm the resolution: ops has no severity → skip; security has 8.
	assert.Equal(t, 8, tax.Events["auth_failure"].ResolvedSeverity(),
		"ops has no severity so security (8) wins")

	// Confirm ops category has nil Severity pointer.
	opsCat := tax.Categories["ops"]
	require.NotNil(t, opsCat)
	assert.Nil(t, opsCat.Severity, "list-format category must have nil Severity")

	// Confirm security category has non-nil Severity.
	secCat := tax.Categories["security"]
	require.NotNil(t, secCat)
	require.NotNil(t, secCat.Severity)
	assert.Equal(t, 8, *secCat.Severity)

	// Drive the full pipeline and check the JSON output.
	out := testhelper.NewMockOutput("mixed-fmt")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"})))

	// Two categories, both enabled → two deliveries.
	require.True(t, out.WaitForEvents(2, 2*time.Second),
		"expected 2 deliveries, got %d", out.EventCount())

	for i := 0; i < 2; i++ {
		var parsed map[string]any
		require.NoError(t, json.Unmarshal(out.GetEvents()[i], &parsed),
			"delivery[%d] must be valid JSON", i)
		rawSev, ok := parsed["severity"]
		require.True(t, ok, "delivery[%d]: severity must be present", i)
		assert.Equal(t, float64(8), rawSev,
			"delivery[%d]: severity must be 8 (security wins after ops has nil)", i)
	}
}
