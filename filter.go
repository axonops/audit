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
}

// IsEmpty reports whether all route fields are empty, meaning the
// output receives all globally-enabled events.
func (r *EventRoute) IsEmpty() bool {
	return len(r.IncludeCategories) == 0 &&
		len(r.IncludeEventTypes) == 0 &&
		len(r.ExcludeCategories) == 0 &&
		len(r.ExcludeEventTypes) == 0
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
	return validateRouteEntries(route, taxonomy)
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

// MatchesRoute reports whether an event should be delivered to an
// output with the given route. eventType is the event name, category
// is its taxonomy category. An empty route matches all events.
func MatchesRoute(route *EventRoute, eventType, category string) bool {
	if route.IsEmpty() {
		return true
	}

	if route.isIncludeMode() {
		return slices.Contains(route.IncludeCategories, category) ||
			slices.Contains(route.IncludeEventTypes, eventType)
	}

	// Exclude mode.
	if slices.Contains(route.ExcludeCategories, category) ||
		slices.Contains(route.ExcludeEventTypes, eventType) {
		return false
	}
	return true
}

// filterState tracks which categories and individual event types are
// enabled. It is safe for concurrent use — reads are lock-free via
// syncmap.Map (backed by sync.Map internally).
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
func newFilterState(t *Taxonomy) filterState {
	var f filterState
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
// category state. Lock-free on the read path.
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
	enabled, _ := f.enabledCategories.Load(def.Category)
	return enabled
}
