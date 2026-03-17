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

// filterState tracks which categories and individual event types are
// enabled. It is protected by the Logger's sync.RWMutex.
type filterState struct {
	// enabledCategories tracks the enabled state of each category.
	enabledCategories map[string]bool

	// eventOverrides tracks per-event-type overrides. A true value
	// forces the event to be enabled regardless of its category; a
	// false value forces it disabled. Events not in this map inherit
	// their category's state.
	eventOverrides map[string]bool
}

// newFilterState initialises a filterState from the taxonomy's
// DefaultEnabled list and the full set of categories.
func newFilterState(t *Taxonomy) filterState {
	enabled := make(map[string]bool, len(t.Categories))
	for cat := range t.Categories {
		enabled[cat] = false
	}
	for _, cat := range t.DefaultEnabled {
		enabled[cat] = true
	}
	return filterState{
		enabledCategories: enabled,
		eventOverrides:    make(map[string]bool),
	}
}

// isEnabled reports whether the given event type should be processed.
// It checks per-event overrides first, then falls back to the event's
// category state.
func (f *filterState) isEnabled(eventType string, taxonomy *Taxonomy) bool {
	// Per-event override takes precedence.
	if override, ok := f.eventOverrides[eventType]; ok {
		return override
	}

	// Fall back to category state.
	def, ok := taxonomy.Events[eventType]
	if !ok {
		return false
	}
	return f.enabledCategories[def.Category]
}
