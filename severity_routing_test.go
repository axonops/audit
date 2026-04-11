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

// Tests for severity-based event routing (issue #187).
//
// This file covers:
//   - MatchesRoute: severity filter combinations (min, max, range)
//   - MatchesRoute: severity AND category/event-type compound logic
//   - EventRoute.IsEmpty: routes containing only severity fields
//   - ValidateEventRoute: severity field validation (range, ordering)
//   - outputEntry.setRoute / getRoute: deep-copy isolation of *int pointers
//   - Boundary combinations: severity 0 and 10 (CEF floor/ceiling)
//   - Include/exclude interaction with severity filtering
//   - Full pipeline (Audit → drain → MockOutput) with severity routes
//   - Benchmarks for hot-path severity filtering scenarios

import (
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MatchesRoute — severity filtering
// ---------------------------------------------------------------------------

// TestMatchesRoute_MinSeverity_Match verifies that an event whose severity
// equals or exceeds the route's MinSeverity is delivered.
// Severity 8 >= MinSeverity 7 → match.
func TestMatchesRoute_MinSeverity_Match(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MinSeverity: intPtr(7)}
	got := audit.MatchesRoute(&route, "auth_failure", "security", 8)
	assert.True(t, got, "severity 8 must pass min_severity 7")
}

// TestMatchesRoute_MinSeverity_Reject verifies that an event whose severity
// falls below the route's MinSeverity is not delivered.
// Severity 6 < MinSeverity 7 → no match.
func TestMatchesRoute_MinSeverity_Reject(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MinSeverity: intPtr(7)}
	got := audit.MatchesRoute(&route, "auth_failure", "security", 6)
	assert.False(t, got, "severity 6 must not pass min_severity 7")
}

// TestMatchesRoute_MaxSeverity_Match verifies that an event whose severity
// is at or below the route's MaxSeverity is delivered.
// Severity 3 <= MaxSeverity 5 → match.
func TestMatchesRoute_MaxSeverity_Match(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MaxSeverity: intPtr(5)}
	got := audit.MatchesRoute(&route, "config_get", "read", 3)
	assert.True(t, got, "severity 3 must pass max_severity 5")
}

// TestMatchesRoute_MaxSeverity_Reject verifies that an event whose severity
// exceeds the route's MaxSeverity is not delivered.
// Severity 7 > MaxSeverity 5 → no match.
func TestMatchesRoute_MaxSeverity_Reject(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MaxSeverity: intPtr(5)}
	got := audit.MatchesRoute(&route, "auth_failure", "security", 7)
	assert.False(t, got, "severity 7 must not pass max_severity 5")
}

// TestMatchesRoute_MinAndMaxSeverity_Match verifies that an event whose
// severity falls within [MinSeverity, MaxSeverity] is delivered.
// Severity 5, min 3, max 7 → match.
func TestMatchesRoute_MinAndMaxSeverity_Match(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		MinSeverity: intPtr(3),
		MaxSeverity: intPtr(7),
	}
	got := audit.MatchesRoute(&route, "user_create", "write", 5)
	assert.True(t, got, "severity 5 must pass range [3, 7]")
}

// TestMatchesRoute_MinAndMaxSeverity_Reject verifies that an event whose
// severity falls outside [MinSeverity, MaxSeverity] is not delivered.
// Severity 9, min 3, max 7 → no match.
func TestMatchesRoute_MinAndMaxSeverity_Reject(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		MinSeverity: intPtr(3),
		MaxSeverity: intPtr(7),
	}
	got := audit.MatchesRoute(&route, "auth_failure", "security", 9)
	assert.False(t, got, "severity 9 must not pass range [3, 7]")
}

// TestMatchesRoute_SeverityWithCategoryFilter verifies that severity filtering
// is an AND condition with category filtering. Both conditions must pass.
// Case A: category matches "security" AND severity 8 >= min 6 → true.
// Case B: category matches "security" AND severity 3 < min 6 → false.
func TestMatchesRoute_SeverityWithCategoryFilter(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeCategories: []string{"security"},
		MinSeverity:       intPtr(6),
	}

	t.Run("category match and severity pass returns true", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "auth_failure", "security", 8)
		assert.True(t, got,
			"event in included category with severity 8 >= min 6 must be delivered")
	})

	t.Run("category match but severity fail returns false", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "auth_failure", "security", 3)
		assert.False(t, got,
			"event in included category with severity 3 < min 6 must not be delivered")
	})
}

// TestMatchesRoute_SeverityOnlyRoute verifies a severity-only route (MinSeverity
// set, no category or event type filters). Only events at or above the threshold
// are delivered; the route carries no category/event type constraints.
func TestMatchesRoute_SeverityOnlyRoute(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MinSeverity: intPtr(9)}

	tests := []struct {
		name      string
		eventType string
		category  string
		severity  int
		want      bool
	}{
		{
			name:      "severity 9 at threshold passes",
			eventType: "auth_failure",
			category:  "security",
			severity:  9,
			want:      true,
		},
		{
			name:      "severity 10 above threshold passes",
			eventType: "user_delete",
			category:  "write",
			severity:  10,
			want:      true,
		},
		{
			name:      "severity 8 below threshold rejected",
			eventType: "user_create",
			category:  "write",
			severity:  8,
			want:      false,
		},
		{
			name:      "severity 0 well below threshold rejected",
			eventType: "config_get",
			category:  "read",
			severity:  0,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := audit.MatchesRoute(&route, tt.eventType, tt.category, tt.severity)
			assert.Equal(t, tt.want, got,
				"severity-only route (min=9): event %q (sev=%d) want=%v",
				tt.eventType, tt.severity, tt.want)
		})
	}
}

// TestMatchesRoute_NilSeverity_NoFilter verifies that a route with nil
// MinSeverity and nil MaxSeverity applies no severity filter — all events
// pass regardless of severity.
func TestMatchesRoute_NilSeverity_NoFilter(t *testing.T) {
	t.Parallel()

	// Include-mode route with nil severity pointers: only the category
	// filter applies; severity plays no role.
	route := audit.EventRoute{
		IncludeCategories: []string{"security"},
		// MinSeverity and MaxSeverity are nil (zero value).
	}

	for _, sev := range []int{0, 1, 5, 9, 10} {
		t.Run("severity passes when severity pointers are nil", func(t *testing.T) {
			t.Parallel()
			got := audit.MatchesRoute(&route, "auth_failure", "security", sev)
			assert.True(t, got,
				"nil severity pointers must not filter out severity %d", sev)
		})
	}
}

// ---------------------------------------------------------------------------
// EventRoute.IsEmpty — severity-only routes must not be considered empty
// ---------------------------------------------------------------------------

// TestEventRoute_IsEmpty_SeverityOnlyRoute_NotEmpty verifies that a route
// containing only a MinSeverity (no categories or event types) is not empty.
// An empty route passes all events; a severity-only route filters on severity.
func TestEventRoute_IsEmpty_SeverityOnlyRoute_NotEmpty(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MinSeverity: intPtr(7)}
	assert.False(t, route.IsEmpty(),
		"route with MinSeverity set must not report IsEmpty=true")
}

// TestEventRoute_IsEmpty_MaxSeverityOnly_NotEmpty verifies that a route
// containing only a MaxSeverity (no categories or event types) is not empty.
func TestEventRoute_IsEmpty_MaxSeverityOnly_NotEmpty(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MaxSeverity: intPtr(3)}
	assert.False(t, route.IsEmpty(),
		"route with MaxSeverity set must not report IsEmpty=true")
}

// ---------------------------------------------------------------------------
// ValidateEventRoute — severity field validation
// ---------------------------------------------------------------------------

// TestValidateEventRoute_MinSeverityOutOfRange verifies that MinSeverity values
// below 0 or above 10 are rejected with a descriptive error.
func TestValidateEventRoute_MinSeverityOutOfRange(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	tests := []struct {
		name    string
		wantErr string
		minSev  int
	}{
		{
			name:    "min_severity -1 below range",
			wantErr: "min_severity -1 out of range",
			minSev:  -1,
		},
		{
			name:    "min_severity 11 above range",
			wantErr: "min_severity 11 out of range",
			minSev:  11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			route := audit.EventRoute{MinSeverity: intPtr(tt.minSev)}
			err := audit.ValidateEventRoute(&route, tax)
			require.Error(t, err,
				"min_severity %d must be rejected", tt.minSev)
			assert.Contains(t, err.Error(), tt.wantErr,
				"error message must identify the out-of-range value")
		})
	}
}

// TestValidateEventRoute_MaxSeverityOutOfRange verifies that MaxSeverity values
// below 0 or above 10 are rejected with a descriptive error.
func TestValidateEventRoute_MaxSeverityOutOfRange(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	tests := []struct {
		name    string
		wantErr string
		maxSev  int
	}{
		{
			name:    "max_severity -1 below range",
			wantErr: "max_severity -1 out of range",
			maxSev:  -1,
		},
		{
			name:    "max_severity 11 above range",
			wantErr: "max_severity 11 out of range",
			maxSev:  11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			route := audit.EventRoute{MaxSeverity: intPtr(tt.maxSev)}
			err := audit.ValidateEventRoute(&route, tax)
			require.Error(t, err,
				"max_severity %d must be rejected", tt.maxSev)
			assert.Contains(t, err.Error(), tt.wantErr,
				"error message must identify the out-of-range value")
		})
	}
}

// TestValidateEventRoute_MinGreaterThanMax verifies that a route where
// MinSeverity exceeds MaxSeverity is rejected. Such a range can never
// match any event and is almost certainly a misconfiguration.
func TestValidateEventRoute_MinGreaterThanMax(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	route := audit.EventRoute{
		MinSeverity: intPtr(8),
		MaxSeverity: intPtr(3),
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err, "min_severity 8 > max_severity 3 must be rejected")
	assert.Contains(t, err.Error(), "min_severity 8 exceeds max_severity 3",
		"error message must name both values")
}

// TestValidateEventRoute_ValidSeverityRange verifies that a well-formed
// severity range [3, 7] is accepted without error.
func TestValidateEventRoute_ValidSeverityRange(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	route := audit.EventRoute{
		MinSeverity: intPtr(3),
		MaxSeverity: intPtr(7),
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.NoError(t, err, "valid severity range [3, 7] must be accepted")
}

// TestValidateEventRoute_SeverityZero_Valid verifies that MinSeverity of 0
// is accepted. Zero is the lowest valid CEF severity and means "informational".
// A pointer-to-zero must not be treated the same as a nil pointer.
func TestValidateEventRoute_SeverityZero_Valid(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	route := audit.EventRoute{MinSeverity: intPtr(0)}
	err := audit.ValidateEventRoute(&route, tax)
	require.NoError(t, err, "min_severity 0 is a valid CEF severity and must be accepted")
}

// ---------------------------------------------------------------------------
// setRoute / getRoute — deep copy isolation of *int severity pointers
// ---------------------------------------------------------------------------

// TestSetRoute_CopiesMinSeverityPointer verifies that mutating the *int
// pointer that was passed to SetOutputRoute after the call does not affect
// the route stored internally by the output entry. The deep copy must sever
// the aliasing relationship.
func TestSetRoute_CopiesMinSeverityPointer(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	out := testhelper.NewMockOutput("copy-min")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// Set a severity route via the public API.
	original := intPtr(5)
	route := &audit.EventRoute{MinSeverity: original}
	require.NoError(t, logger.SetOutputRoute("copy-min", route))

	// Mutate the original pointer after SetOutputRoute returns.
	*original = 99

	// The stored route must reflect the value at the time of the call (5),
	// not the mutated value (99).
	stored, err := logger.OutputRoute("copy-min")
	require.NoError(t, err)
	require.NotNil(t, stored.MinSeverity,
		"stored route must have a non-nil MinSeverity")
	assert.Equal(t, 5, *stored.MinSeverity,
		"stored MinSeverity must be 5 (deep copy), not 99 (mutated original)")
}

// TestSetRoute_CopiesMaxSeverityPointer verifies the same deep-copy guarantee
// for MaxSeverity.
func TestSetRoute_CopiesMaxSeverityPointer(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	out := testhelper.NewMockOutput("copy-max")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	original := intPtr(8)
	route := &audit.EventRoute{MaxSeverity: original}
	require.NoError(t, logger.SetOutputRoute("copy-max", route))

	// Mutate after the call.
	*original = 1

	stored, err := logger.OutputRoute("copy-max")
	require.NoError(t, err)
	require.NotNil(t, stored.MaxSeverity,
		"stored route must have a non-nil MaxSeverity")
	assert.Equal(t, 8, *stored.MaxSeverity,
		"stored MaxSeverity must be 8 (deep copy), not 1 (mutated original)")
}

// TestGetRoute_ReturnsIndependentSeverityPointers verifies that mutating the
// *int pointers in the EventRoute returned by OutputRoute does not affect the
// internally stored route. Each call to OutputRoute returns an independent
// deep copy.
func TestGetRoute_ReturnsIndependentSeverityPointers(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	out := testhelper.NewMockOutput("get-copy")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{MinSeverity: intPtr(4)}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// First retrieval: mutate the returned copy.
	first, err := logger.OutputRoute("get-copy")
	require.NoError(t, err)
	require.NotNil(t, first.MinSeverity)
	*first.MinSeverity = 77 // mutate the copy

	// Second retrieval: must still reflect the original value (4).
	second, err := logger.OutputRoute("get-copy")
	require.NoError(t, err)
	require.NotNil(t, second.MinSeverity,
		"second OutputRoute call must return a non-nil MinSeverity")
	assert.Equal(t, 4, *second.MinSeverity,
		"internal route must be unaffected by mutation of the first returned copy")
}

// TestSetRoute_NilSeverityPointersPreserved verifies that a route with nil
// MinSeverity and nil MaxSeverity stored via SetOutputRoute round-trips
// through setRoute/getRoute with both fields still nil. A nil pointer must
// not be replaced with a pointer-to-zero.
func TestSetRoute_NilSeverityPointersPreserved(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	out := testhelper.NewMockOutput("nil-sev")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// Set a route that has no severity constraints.
	route := &audit.EventRoute{
		IncludeCategories: []string{"write"},
		// MinSeverity and MaxSeverity intentionally nil.
	}
	require.NoError(t, logger.SetOutputRoute("nil-sev", route))

	stored, err := logger.OutputRoute("nil-sev")
	require.NoError(t, err)
	assert.Nil(t, stored.MinSeverity,
		"nil MinSeverity must remain nil after setRoute/getRoute round-trip")
	assert.Nil(t, stored.MaxSeverity,
		"nil MaxSeverity must remain nil after setRoute/getRoute round-trip")
}

// ---------------------------------------------------------------------------
// Boundary combinations — CEF floor and ceiling
// ---------------------------------------------------------------------------

// TestMatchesRoute_MinSeverity0_MaxSeverity0 verifies that a route with both
// MinSeverity and MaxSeverity set to 0 only passes events with severity 0.
// Severity 0 is the CEF "informational" floor.
func TestMatchesRoute_MinSeverity0_MaxSeverity0(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		MinSeverity: intPtr(0),
		MaxSeverity: intPtr(0),
	}

	tests := []struct {
		severity int
		want     bool
	}{
		{0, true},
		{1, false},
		{5, false},
		{10, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got := audit.MatchesRoute(&route, "config_get", "read", tt.severity)
			assert.Equal(t, tt.want, got,
				"range [0,0]: severity %d want=%v", tt.severity, tt.want)
		})
	}
}

// TestMatchesRoute_MinSeverity10_MaxSeverity10 verifies that a route with both
// MinSeverity and MaxSeverity set to 10 only passes events with severity 10.
// Severity 10 is the CEF "critical" ceiling.
func TestMatchesRoute_MinSeverity10_MaxSeverity10(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		MinSeverity: intPtr(10),
		MaxSeverity: intPtr(10),
	}

	tests := []struct {
		severity int
		want     bool
	}{
		{10, true},
		{9, false},
		{5, false},
		{0, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got := audit.MatchesRoute(&route, "auth_failure", "security", tt.severity)
			assert.Equal(t, tt.want, got,
				"range [10,10]: severity %d want=%v", tt.severity, tt.want)
		})
	}
}

// TestMatchesRoute_SeverityWithEmptyCategory verifies that severity filtering
// works correctly for uncategorised events (empty category string). An
// uncategorised event has an empty category in the routing logic; a
// severity-only route must still filter on severity alone.
func TestMatchesRoute_SeverityWithEmptyCategory(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{MinSeverity: intPtr(6)}

	t.Run("uncategorised event passes severity threshold", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "startup", "", 6)
		assert.True(t, got,
			"uncategorised event (empty category) with severity 6 >= min 6 must match")
	})

	t.Run("uncategorised event below severity threshold rejected", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "startup", "", 4)
		assert.False(t, got,
			"uncategorised event (empty category) with severity 4 < min 6 must not match")
	})
}

// ---------------------------------------------------------------------------
// Include/exclude interactions with severity filtering
// ---------------------------------------------------------------------------

// TestMatchesRoute_SeverityWithIncludeEventType verifies that when an event
// type is in the include list but the event's severity is below the minimum,
// the event is still rejected. Severity is an AND condition — both the
// include filter and the severity filter must pass.
func TestMatchesRoute_SeverityWithIncludeEventType(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		IncludeEventTypes: []string{"auth_failure"},
		MinSeverity:       intPtr(8),
	}

	t.Run("included event type with severity pass is delivered", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "auth_failure", "security", 9)
		assert.True(t, got,
			"included event type 'auth_failure' with severity 9 >= min 8 must be delivered")
	})

	t.Run("included event type with severity miss is rejected", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "auth_failure", "security", 5)
		assert.False(t, got,
			"included event type 'auth_failure' with severity 5 < min 8 must not be delivered")
	})
}

// TestMatchesRoute_SeverityWithExcludeEventType verifies that an excluded event
// type is still rejected even when its severity would otherwise pass the filter.
// Exclude mode means the exclusion takes precedence over severity.
func TestMatchesRoute_SeverityWithExcludeEventType(t *testing.T) {
	t.Parallel()
	route := audit.EventRoute{
		ExcludeEventTypes: []string{"config_get"},
		MinSeverity:       intPtr(3),
	}

	t.Run("excluded event type rejected even at high severity", func(t *testing.T) {
		t.Parallel()
		// config_get is excluded; even though severity 9 passes min 3,
		// the exclude filter means the event is not delivered.
		got := audit.MatchesRoute(&route, "config_get", "read", 9)
		assert.False(t, got,
			"excluded event type 'config_get' must not be delivered regardless of severity")
	})

	t.Run("non-excluded event at sufficient severity is delivered", func(t *testing.T) {
		t.Parallel()
		got := audit.MatchesRoute(&route, "user_get", "read", 5)
		assert.True(t, got,
			"non-excluded event with severity 5 >= min 3 must be delivered")
	})
}

// ---------------------------------------------------------------------------
// Full pipeline — Audit → drainLoop → MockOutput
// ---------------------------------------------------------------------------

// severityTestTaxonomy builds a minimal YAML taxonomy where events carry
// distinct severity values, suitable for end-to-end severity routing tests.
// The taxonomy has:
//
//	category "critical"  (severity 9): event "critical_event"
//	category "low"       (severity 2): event "low_event"
//	category "medium"    (severity 5): event "medium_event"
//
// All three categories are enabled by default.
const severityRoutingYAML = `
version: 1
categories:
  critical:
    severity: 9
    events: [critical_event]
  low:
    severity: 2
    events: [low_event]
  medium:
    severity: 5
    events: [medium_event]
events:
  critical_event:
    fields:
      outcome: {required: true}
  low_event:
    fields:
      outcome: {required: true}
  medium_event:
    fields:
      outcome: {required: true}
`

// TestAudit_SeverityRouteFiltersInDrainLoop verifies the complete async
// pipeline with a severity route: events below the minimum severity must not
// reach the output. Only the high-severity event should arrive.
//
// Route: MinSeverity 7. Events: critical_event (9), medium_event (5), low_event (2).
// Expected deliveries: critical_event only.
func TestAudit_SeverityRouteFiltersInDrainLoop(t *testing.T) {
	t.Parallel()

	tax, err := audit.ParseTaxonomyYAML([]byte(severityRoutingYAML))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("sev-filter")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{MinSeverity: intPtr(7)}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	require.NoError(t, logger.AuditEvent(audit.NewEvent("critical_event", audit.Fields{"outcome": "failure"})))
	require.NoError(t, logger.AuditEvent(audit.NewEvent("medium_event", audit.Fields{"outcome": "success"})))
	require.NoError(t, logger.AuditEvent(audit.NewEvent("low_event", audit.Fields{"outcome": "success"})))

	// t.Cleanup calls logger.Close() which flushes the drain buffer.
	// Wait for events to be processed.
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Only critical_event (severity 9) must pass min_severity 7.
	assert.Equal(t, 1, out.EventCount(),
		"only events with severity >= 7 must be delivered; got %d events", out.EventCount())

	ev := out.GetEvent(0)
	assert.Equal(t, "critical_event", ev["event_type"],
		"the single delivered event must be critical_event")
}

// TestAudit_EnabledEvent_SeverityRouteStillApplied verifies that a per-event
// force-enable override (EnableEvent) does not bypass the per-output severity
// route. The global filter and the per-output route are independent. An event
// that is force-enabled globally still must satisfy the output's severity
// route to be delivered to that output.
func TestAudit_EnabledEvent_SeverityRouteStillApplied(t *testing.T) {
	t.Parallel()

	// Taxonomy: "restricted" category is disabled by default.
	// "restricted_event" (severity 2) will be force-enabled via EnableEvent.
	const yml = `
version: 1
categories:
  restricted:
    severity: 2
    events: [restricted_event]
  normal:
    severity: 7
    events: [normal_event]
events:
  restricted_event:
    fields:
      outcome: {required: true}
  normal_event:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	out := testhelper.NewMockOutput("force-enabled")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
		// Output route: MinSeverity 5 — only events with severity >= 5 delivered.
		audit.WithNamedOutput(out, &audit.EventRoute{MinSeverity: intPtr(5)}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// Force-enable the restricted event globally so it passes the global filter.
	require.NoError(t, logger.EnableEvent("restricted_event"))

	// Emit restricted_event (severity 2 < min 5 on the output route).
	require.NoError(t, logger.AuditEvent(audit.NewEvent("restricted_event", audit.Fields{"outcome": "ok"})))
	// Emit normal_event (severity 7 >= min 5 on the output route).
	require.NoError(t, logger.AuditEvent(audit.NewEvent("normal_event", audit.Fields{"outcome": "ok"})))

	// t.Cleanup calls logger.Close() which flushes the drain buffer.
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// restricted_event is globally enabled but its severity (2) is below the
	// output route's min_severity (5). It must not be delivered.
	assert.Equal(t, 1, out.EventCount(),
		"restricted_event (sev=2, min_sev=5) must not be delivered despite force-enable; "+
			"only normal_event (sev=7) must arrive")

	if out.EventCount() == 1 {
		ev := out.GetEvent(0)
		assert.Equal(t, "normal_event", ev["event_type"],
			"the delivered event must be normal_event, not restricted_event")
	}
}

// TestValidateEventRoute_SeverityWithMixedIncludeExclude verifies that a route
// specifying both include and exclude fields (the mutually exclusive combination)
// is still rejected at validation time even when a valid severity range is also
// present. Severity fields do not bypass the include/exclude mutual-exclusivity
// check.
func TestValidateEventRoute_SeverityWithMixedIncludeExclude(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	route := audit.EventRoute{
		IncludeCategories: []string{"write"},
		ExcludeCategories: []string{"read"},
		MinSeverity:       intPtr(3),
		MaxSeverity:       intPtr(8),
	}
	err := audit.ValidateEventRoute(&route, tax)
	require.Error(t, err,
		"mixed include+exclude route with valid severity must still be rejected")
	assert.Contains(t, err.Error(), "either include or exclude, not both",
		"error message must identify the include/exclude conflict")
}

// ---------------------------------------------------------------------------
// Benchmarks — severity filtering on the hot path
// ---------------------------------------------------------------------------

// BenchmarkMatchesRoute_Severity exercises the various severity filtering
// scenarios to confirm that severity checks do not regress the hot path.
// These sub-benchmarks complement the existing BenchmarkMatchesRoute suite
// in filter_test.go.
func BenchmarkMatchesRoute_Severity(b *testing.B) {
	b.Run("nil_severity", func(b *testing.B) {
		// No severity filter: IsEmpty short-circuit path.
		route := audit.EventRoute{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "auth_failure", "security", 5)
		}
	})

	b.Run("severity_only_min", func(b *testing.B) {
		// Severity-only route: two nil checks + one int comparison.
		route := audit.EventRoute{MinSeverity: intPtr(7)}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "auth_failure", "security", 9)
		}
	})

	b.Run("severity_only_range", func(b *testing.B) {
		// Min+max range: two nil checks + two int comparisons.
		route := audit.EventRoute{
			MinSeverity: intPtr(3),
			MaxSeverity: intPtr(8),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "auth_failure", "security", 5)
		}
	})

	b.Run("include_categories_with_severity", func(b *testing.B) {
		// Category include filter combined with severity range.
		route := audit.EventRoute{
			IncludeCategories: []string{"write", "security", "admin", "read"},
			MinSeverity:       intPtr(5),
			MaxSeverity:       intPtr(9),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			audit.MatchesRoute(&route, "user_create", "write", 7)
		}
	})

	b.Run("severity_reject", func(b *testing.B) {
		// Severity fails first — short-circuit before category lookup.
		route := audit.EventRoute{
			IncludeCategories: []string{"write", "security"},
			MinSeverity:       intPtr(9),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Severity 3 < min 9 → rejected before category check.
			audit.MatchesRoute(&route, "user_create", "write", 3)
		}
	})

	b.Run("severity_accept", func(b *testing.B) {
		// Severity passes, then category passes — no short-circuit.
		route := audit.EventRoute{
			IncludeCategories: []string{"write", "security"},
			MinSeverity:       intPtr(5),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Severity 8 >= min 5 → proceed to category check.
			audit.MatchesRoute(&route, "user_create", "write", 8)
		}
	})
}

func TestConcurrentSetRouteWithSeverity(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()
	out := testhelper.NewMockOutput("concurrent_sev")
	logger, err := audit.NewLogger(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: audit events continuously.
	go func() {
		defer wg.Done()
		for range 200 {
			_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
		}
	}()

	// Goroutine 2: toggle severity route concurrently.
	go func() {
		defer wg.Done()
		for range 100 {
			minSev := 5
			_ = logger.SetOutputRoute("concurrent_sev", &audit.EventRoute{
				MinSeverity: &minSev,
			})
			_ = logger.ClearOutputRoute("concurrent_sev")
		}
	}()

	wg.Wait()
	require.NoError(t, logger.Close())
	// Events may or may not be filtered depending on timing —
	// the test verifies no data race, not a specific count.
	assert.True(t, out.EventCount() > 0, "at least some events should arrive")
}
