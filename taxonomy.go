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
	"regexp"
	"slices"
)

// Fields is the map type for audit event fields. Consumers pass
// field values as Fields to [Logger.AuditEvent] and generated event
// builders.
//
// Fields is a defined type (not an alias) so it can carry convenience
// methods. Callers constructing fields from a plain map must convert
// explicitly: audit.Fields(m).
//
// Comparable pattern: [net/url.Values], [net/http.Header].
type Fields map[string]any

// Has reports whether the field map contains a value for key.
func (f Fields) Has(key string) bool {
	_, ok := f[key]
	return ok
}

// String returns the value for key as a string. If the key is missing
// or the value is not a string, it returns the empty string.
func (f Fields) String(key string) string {
	v, _ := f[key].(string)
	return v
}

// Int returns the value for key as an int. If the key is missing or
// the value is not an int, it returns 0. Float64 values (common from
// JSON unmarshalling) are truncated toward zero (e.g. 99.9 → 99).
func (f Fields) Int(key string) int {
	switch v := f[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

// SensitivityConfig holds all sensitivity label definitions for a
// taxonomy. It is optional; a nil SensitivityConfig means no
// sensitivity labels are defined and the feature is fully disabled
// with zero overhead.
type SensitivityConfig struct {
	// Labels maps label names (e.g., "pii", "financial") to their
	// definitions. Label names MUST be non-empty and match the
	// pattern `^[a-z][a-z0-9_]*$` for code generation safety.
	// [ValidateTaxonomy] rejects any name that does not conform.
	Labels map[string]*SensitivityLabel
}

// SensitivityLabel defines a single sensitivity label with optional
// global field mappings and regex patterns. Labels are defined in the
// taxonomy's sensitivity section and can be associated with fields via
// three mechanisms: explicit per-event annotation, global field name
// mapping, and regex patterns.
type SensitivityLabel struct {
	// Description is an optional human-readable explanation of what
	// this label represents.
	Description string

	// Fields lists field names that are globally assigned this label
	// across all events. A field listed here receives this label in
	// every event where it appears, regardless of per-event annotation.
	Fields []string

	// Patterns lists regex patterns. Any field name matching a pattern
	// is assigned this label. Patterns are compiled once at parse time.
	Patterns []string

	// compiled holds the compiled regexes. Populated by
	// compileSensitivityPatterns at taxonomy parse time.
	compiled []*regexp.Regexp
}

// CategoryDef defines a taxonomy category with its member events and
// optional default severity.
type CategoryDef struct {
	// Severity is the default CEF severity (0-10) for all events in
	// this category. Nil means not set — events inherit the global
	// default (5). A non-nil pointer to 0 means explicitly severity 0.
	Severity *int

	// Events lists the event type names belonging to this category.
	Events []string
}

// EventDef defines a single audit event type in the taxonomy.
type EventDef struct {
	// Categories lists the taxonomy categories this event belongs to
	// (e.g. ["write"], ["security", "access"]). Derived from the
	// [Taxonomy.Categories] map during parsing — not set by consumers.
	// Sorted alphabetically. May be empty for uncategorised events.
	Categories []string

	// Description is an optional human-readable explanation of what
	// this event type represents. It is informational metadata only
	// — it has no effect on validation, routing, or serialisation.
	// When present, [audit-gen] emits it as a Go comment above the
	// generated constant. Also used as the default CEF description.
	Description string

	// Severity is the event-level CEF severity (0-10). Nil means
	// inherit from the category. A non-nil pointer to 0 means
	// explicitly severity 0. Resolution: event → category → 5.
	Severity *int

	// Required lists field names that must be present in every
	// [Logger.AuditEvent] call for this event type. Missing required
	// fields always produce an error regardless of validation mode.
	Required []string

	// Optional lists field names that may be present. In strict
	// validation mode, any field not in Required or Optional
	// produces an error.
	Optional []string

	// FieldLabels maps field names to their resolved sensitivity labels,
	// represented as a set (map key = label name, value always struct{}).
	// Populated at taxonomy registration time from all three label
	// sources: explicit per-event annotation, global field name mapping,
	// and regex patterns. Nil when no sensitivity config is defined.
	// Read-only after construction — consumers MUST NOT modify this map.
	FieldLabels map[string]map[string]struct{}

	// Pre-computed fields populated by precomputeTaxonomy at
	// registration time. These are read-only after construction
	// and eliminate per-event allocations in validation and
	// formatting.
	fieldAnnotations map[string][]string // per-event label annotations from YAML
	knownFields      map[string]struct{} // union of Required + Optional
	sortedRequired   []string            // Required, sorted alphabetically
	sortedOptional   []string            // Optional, sorted alphabetically
	sortedAllKeys    []string            // Required + Optional, merged, deduped, sorted
	resolvedSeverity int                 // event → category → 5; precomputed
	severityResolved bool                // true once resolvedSeverity has been set
}

// ResolvedSeverity returns the effective severity for this event type.
// The value is precomputed during taxonomy registration and is always
// in the range 0-10. Resolution chain: event Severity (if non-nil) →
// first category Severity in alphabetical order (if non-nil) → 5.
// For events in multiple categories, set event-level Severity to
// avoid depending on alphabetical category ordering.
func (d *EventDef) ResolvedSeverity() int {
	if !d.severityResolved {
		return 5 // default for EventDefs not processed by precomputeTaxonomy
	}
	return d.resolvedSeverity
}

// Taxonomy defines the complete set of audit event types, their
// categories, required and optional fields, and which categories are
// enabled by default. Consumers register a taxonomy at bootstrap via
// [WithTaxonomy].
//
// The framework does not hardcode any event types, field names, or
// categories. The only events the framework injects are "startup" and
// "shutdown" lifecycle events, which are added automatically if not
// already present.
type Taxonomy struct {
	// Categories maps category names to their definitions. An event
	// type may appear in multiple categories or in none (uncategorised
	// events are always globally enabled).
	Categories map[string]*CategoryDef

	// Events maps event type names to their definitions. Every event
	// type listed in Categories MUST have a corresponding entry here.
	// Pointers are used to avoid per-event heap escapes when passing
	// definitions through the drain path.
	Events map[string]*EventDef

	// Sensitivity defines the sensitivity label configuration. Nil
	// means no sensitivity labels are defined; the feature is fully
	// disabled with zero overhead.
	Sensitivity *SensitivityConfig

	// SuppressEventCategory controls whether the `event_category` field
	// is omitted from serialised output. The zero value (false) means
	// the category IS emitted — matching the YAML default when
	// `emit_event_category` is absent. Set to true to suppress.
	SuppressEventCategory bool

	// Version is the taxonomy schema version. MUST be > 0. Currently
	// only version 1 is supported; higher values cause [WithTaxonomy]
	// to return an error wrapping [ErrTaxonomyInvalid].
	Version int
}

const (
	// currentTaxonomyVersion is the latest taxonomy schema version
	// supported by this library.
	currentTaxonomyVersion = 1

	// minSupportedTaxonomyVersion is the oldest taxonomy schema
	// version the library can migrate from.
	minSupportedTaxonomyVersion = 1
)

// precomputeTaxonomy populates the pre-computed fields on every
// EventDef in the taxonomy. This includes deriving Categories from
// the categories map (for Go-level construction where categories
// are not set on EventDef directly) and building the field lookup
// structures. Must be called after validation succeeds.
func precomputeTaxonomy(t *Taxonomy) error {
	// Derive EventDef.Categories from the categories map. This
	// ensures Categories is populated for both YAML-parsed and
	// Go-constructed taxonomies.
	for catName, catDef := range t.Categories {
		if catDef == nil {
			continue
		}
		for _, eventName := range catDef.Events {
			if def, ok := t.Events[eventName]; ok {
				if !slices.Contains(def.Categories, catName) {
					def.Categories = append(def.Categories, catName)
				}
			}
		}
	}
	for _, def := range t.Events {
		slices.Sort(def.Categories)
	}

	// Resolve severity for each event. Resolution chain:
	// event Severity (if non-nil) → first category Severity (if non-nil) → 5.
	for _, def := range t.Events {
		def.resolvedSeverity = resolveEventSeverity(def, t)
		def.severityResolved = true
	}

	for _, def := range t.Events {
		precomputeEventDef(def)
	}

	return precomputeSensitivity(t)
}

// resolveEventSeverity computes the effective severity for an event.
// Resolution: event Severity → first category Severity → 5.
func resolveEventSeverity(def *EventDef, t *Taxonomy) int {
	if def.Severity != nil {
		return clampSeverity(*def.Severity)
	}
	// Check categories in sorted order for determinism.
	for _, catName := range def.Categories {
		if catDef, ok := t.Categories[catName]; ok && catDef.Severity != nil {
			return clampSeverity(*catDef.Severity)
		}
	}
	return 5
}

// clampSeverity restricts a severity value to the valid CEF range 0-10.
func clampSeverity(s int) int {
	if s < 0 {
		return 0
	}
	if s > 10 {
		return 10
	}
	return s
}

// precomputeEventDef populates the pre-computed lookup structures
// on a single EventDef: knownFields set, sorted field lists, and
// merged sorted key list.
func precomputeEventDef(def *EventDef) {
	def.knownFields = make(map[string]struct{}, len(def.Required)+len(def.Optional))
	for _, f := range def.Required {
		def.knownFields[f] = struct{}{}
	}
	for _, f := range def.Optional {
		def.knownFields[f] = struct{}{}
	}

	def.sortedRequired = sortedCopy(def.Required)
	def.sortedOptional = sortedCopy(def.Optional)

	// Build sorted all-keys from the already-deduped knownFields set.
	all := make([]string, 0, len(def.knownFields))
	for k := range def.knownFields {
		all = append(all, k)
	}
	slices.Sort(all)
	def.sortedAllKeys = all
}

// sortedCopy returns a sorted copy of the input slice.
func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	slices.Sort(cp)
	return cp
}

// ValidateTaxonomy checks t for internal consistency. If any problems
// are found, it returns a single error wrapping [ErrTaxonomyInvalid]
// whose message lists every problem on a separate line, sorted for
// deterministic output. Callers MUST use [errors.Is] to test for
// [ErrTaxonomyInvalid]; do not parse the error string.
//
// This function is called automatically by [WithTaxonomy]; it is
// exported so that [ParseTaxonomyYAML] and other callers can
// validate a taxonomy constructed from external sources.
