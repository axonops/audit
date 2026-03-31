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

package audit

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rgooding/go-syncmap"
)

// EventRoute restricts which events are delivered to a specific output.
// Routes operate in one of two mutually exclusive modes:
//
// Include mode (allow-list): events are delivered only if their category
// is in [EventRoute.IncludeCategories] OR their event type is in
// [EventRoute.IncludeEventTypes]. The two fields form a union.
//
// Exclude mode (deny-list): events are delivered unless their category
// is in [EventRoute.ExcludeCategories] OR their event type is in
// [EventRoute.ExcludeEventTypes]. The two fields form a union.
//
// Setting both include and exclude fields on the same route is a
// bootstrap error. An empty route (all fields nil/empty) delivers all
// globally-enabled events.
//
//nolint:govet // field order: exported fields first for API clarity, then pre-computed sets
type EventRoute struct {
	// IncludeCategories lists category names to allow. Events whose
	// category is in this list are delivered. Mutually exclusive with
	// ExcludeCategories and ExcludeEventTypes.
	IncludeCategories []string

	// IncludeEventTypes lists event type names to allow. Events whose
	// type is in this list are delivered regardless of category.
	// Mutually exclusive with ExcludeCategories and ExcludeEventTypes.
	IncludeEventTypes []string

	// ExcludeCategories lists category names to deny. Events whose
	// category is in this list are skipped. Mutually exclusive with
	// IncludeCategories and IncludeEventTypes.
	ExcludeCategories []string

	// ExcludeEventTypes lists event type names to deny. Events whose
	// type is in this list are skipped regardless of category.
	// Mutually exclusive with IncludeCategories and IncludeEventTypes.
	ExcludeEventTypes []string

	// MinSeverity sets a minimum severity threshold. Events with
	// severity below this value are not delivered. Nil means no
	// minimum filter. A non-nil pointer to 0 means "severity >= 0"
	// (effectively no filter). Severity filtering is an AND condition
	// with category/event type filtering.
	MinSeverity *int

	// MaxSeverity sets a maximum severity threshold. Events with
	// severity above this value are not delivered. Nil means no
	// maximum filter. Combined with MinSeverity to create a range.
	MaxSeverity *int

	// Pre-computed sets for O(1) lookup, populated by buildRouteSets.
	// Nil when the route was constructed without buildRouteSets (e.g.
	// direct struct literal in tests); MatchesRoute falls back to
	// slices.Contains in that case.
	includeCatSet map[string]struct{}
	includeEvtSet map[string]struct{}
	excludeCatSet map[string]struct{}
	excludeEvtSet map[string]struct{}
}

// IsEmpty reports whether all route fields are empty, meaning the
// output receives all globally-enabled events.
func (r *EventRoute) IsEmpty() bool {
	return len(r.IncludeCategories) == 0 &&
		len(r.IncludeEventTypes) == 0 &&
		len(r.ExcludeCategories) == 0 &&
		len(r.ExcludeEventTypes) == 0 &&
		r.MinSeverity == nil &&
		r.MaxSeverity == nil
}

func (r *EventRoute) isIncludeMode() bool {
	return len(r.IncludeCategories) > 0 || len(r.IncludeEventTypes) > 0
}

func (r *EventRoute) isExcludeMode() bool {
	return len(r.ExcludeCategories) > 0 || len(r.ExcludeEventTypes) > 0
}

// ValidateEventRoute checks that the route is well-formed and all
// referenced categories and event types exist in the taxonomy.
func ValidateEventRoute(route *EventRoute, taxonomy *Taxonomy) error {
	if route.isIncludeMode() && route.isExcludeMode() {
		return fmt.Errorf("audit: EventRoute must use either include or exclude, not both")
	}
	if err := validateSeverityRange(route); err != nil {
		return err
	}
	return validateRouteEntries(route, taxonomy)
}

// validateSeverityRange checks that MinSeverity and MaxSeverity are
// within the valid CEF range 0-10 and that min does not exceed max.
func validateSeverityRange(route *EventRoute) error {
	if route.MinSeverity != nil && (*route.MinSeverity < 0 || *route.MinSeverity > 10) {
		return fmt.Errorf("audit: EventRoute min_severity %d out of range 0-10", *route.MinSeverity)
	}
	if route.MaxSeverity != nil && (*route.MaxSeverity < 0 || *route.MaxSeverity > 10) {
		return fmt.Errorf("audit: EventRoute max_severity %d out of range 0-10", *route.MaxSeverity)
	}
	if route.MinSeverity != nil && route.MaxSeverity != nil && *route.MinSeverity > *route.MaxSeverity {
		return fmt.Errorf("audit: EventRoute min_severity %d exceeds max_severity %d",
			*route.MinSeverity, *route.MaxSeverity)
	}
	return nil
}

// validateRouteEntries checks that all categories and event types
// referenced by the route exist in the taxonomy.
func validateRouteEntries(route *EventRoute, taxonomy *Taxonomy) error {
	var unknown []string
	unknown = checkCategories(unknown, route.IncludeCategories, taxonomy)
	unknown = checkCategories(unknown, route.ExcludeCategories, taxonomy)
	unknown = checkEventTypes(unknown, route.IncludeEventTypes, taxonomy)
	unknown = checkEventTypes(unknown, route.ExcludeEventTypes, taxonomy)

	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("audit: EventRoute references unknown taxonomy entries: [%s]",
			strings.Join(unknown, ", "))
	}
	return nil
}

func checkCategories(unknown, cats []string, taxonomy *Taxonomy) []string {
	for _, cat := range cats {
		if _, ok := taxonomy.Categories[cat]; !ok {
			unknown = append(unknown, "category "+cat)
		}
	}
	return unknown
}

func checkEventTypes(unknown, evts []string, taxonomy *Taxonomy) []string {
	for _, evt := range evts {
		if _, ok := taxonomy.Events[evt]; !ok {
			unknown = append(unknown, "event type "+evt)
		}
	}
	return unknown
}

// buildRouteSets populates the pre-computed lookup sets on the route
// for O(1) matching in MatchesRoute. Called by setRoute in fanout.go.
func buildRouteSets(r *EventRoute) {
	r.includeCatSet = toSet(r.IncludeCategories)
	r.includeEvtSet = toSet(r.IncludeEventTypes)
	r.excludeCatSet = toSet(r.ExcludeCategories)
	r.excludeEvtSet = toSet(r.ExcludeEventTypes)
}

// toSet converts a string slice to a set. Returns nil for empty slices.
func toSet(ss []string) map[string]struct{} {
	if len(ss) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// MatchesRoute reports whether an event should be delivered to an
// output with the given route. eventType is the event name, category
// is its taxonomy category, severity is the event's resolved severity
// (0-10). An empty route matches all events.
//
// Severity filtering is an AND condition: the event must pass both
// the severity check and the category/event type check. Severity is
// checked first for performance — severity-only routes (the PagerDuty
// use case) short-circuit without entering the category/event type
// logic.
//
// When pre-computed sets are available (route created via setRoute),
// category/event type lookups are O(1). Falls back to slices.Contains
// for routes constructed as direct struct literals.
func MatchesRoute(route *EventRoute, eventType, category string, severity int) bool {
	if route.IsEmpty() {
		return true
	}

	// Severity filter first — two nil checks + int comparisons.
	// Short-circuits severity-only routes without entering the
	// category/event type logic.
	if !checkSeverity(route, severity) {
		return false
	}

	// Category/event type filter.
	if route.isIncludeMode() {
		return inSet(route.includeCatSet, route.IncludeCategories, category) ||
			inSet(route.includeEvtSet, route.IncludeEventTypes, eventType)
	}

	if route.isExcludeMode() {
		return !inSet(route.excludeCatSet, route.ExcludeCategories, category) &&
			!inSet(route.excludeEvtSet, route.ExcludeEventTypes, eventType)
	}

	// Severity-only route — no category/event type filters.
	// Severity already passed above.
	return true
}

// checkSeverity returns true if the event's severity passes the
// route's min/max severity filters. Returns true if no severity
// filter is set (nil pointers).
func checkSeverity(route *EventRoute, severity int) bool {
	if route.MinSeverity != nil && severity < *route.MinSeverity {
		return false
	}
	if route.MaxSeverity != nil && severity > *route.MaxSeverity {
		return false
	}
	return true
}

// inSet checks membership using the pre-computed set if available,
// falling back to slices.Contains for routes without pre-computed sets.
func inSet(set map[string]struct{}, fallback []string, key string) bool {
	if set != nil {
		_, ok := set[key]
		return ok
	}
	return slices.Contains(fallback, key)
}

// filterState tracks which categories and individual event types are
// enabled. It is safe for concurrent use — reads are lock-free via
// syncmap.SyncMap (backed by sync.Map internally).
type filterState struct {
	// enabledCategories tracks the enabled state of each category.
	// Reads are lock-free for stable keys after initial population.
	enabledCategories syncmap.SyncMap[string, bool]

	// eventOverrides tracks per-event-type overrides. A true value
	// forces the event to be enabled regardless of its category; a
	// false value forces it disabled. Events not in this map inherit
	// their category's state.
	eventOverrides syncmap.SyncMap[string, bool]
}

// newFilterState initialises a filterState from the taxonomy's
// DefaultEnabled list and the full set of categories.
func newFilterState(t *Taxonomy) *filterState {
	f := &filterState{}
	for cat := range t.Categories {
		f.enabledCategories.Store(cat, false)
	}
	for _, cat := range t.DefaultEnabled {
		f.enabledCategories.Store(cat, true)
	}
	return f
}

// isEnabled reports whether the given event type should be processed.
// It checks per-event overrides first, then falls back to the event's
// category state. An event is enabled if ANY of its categories is
// enabled. Uncategorised events (empty Categories) are always enabled
// at the global level. Lock-free on the read path.
func (f *filterState) isEnabled(eventType string, taxonomy *Taxonomy) bool {
	// Per-event override takes precedence.
	if override, ok := f.eventOverrides.Load(eventType); ok {
		return override
	}

	// Fall back to category state.
	def, ok := taxonomy.Events[eventType]
	if !ok {
		return false
	}

	// Uncategorised events are always globally enabled.
	if len(def.Categories) == 0 {
		return true
	}

	// Enabled if ANY category is enabled.
	for _, cat := range def.Categories {
		if enabled, _ := f.enabledCategories.Load(cat); enabled {
			return true
		}
	}
	return false
}

// isCategoryEnabled reports whether the given category is currently
// enabled. Used by the drain loop to skip disabled category passes.
func (f *filterState) isCategoryEnabled(category string) bool {
	enabled, _ := f.enabledCategories.Load(category)
	return enabled
}
