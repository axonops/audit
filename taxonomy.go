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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Fields is a typed alias for audit event field maps. Consumers pass
// field values as Fields to [Logger.Audit].
type Fields = map[string]any

// SensitivityConfig holds all sensitivity label definitions for a
// taxonomy. It is optional; a nil SensitivityConfig means no
// sensitivity labels are defined and the feature is fully disabled
// with zero overhead.
type SensitivityConfig struct {
	// Labels maps label names (e.g., "pii", "financial") to their
	// definitions. Label names must be non-empty and match
	// [a-z][a-z0-9_]* for code generation safety.
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
	// [Logger.Audit] call for this event type. Missing required
	// fields always produce an error regardless of validation mode.
	Required []string

	// Optional lists field names that may be present. In strict
	// validation mode, any field not in Required or Optional
	// produces an error.
	Optional []string

	// FieldLabels maps field names to their resolved sensitivity
	// labels. Populated by [precomputeSensitivity] at taxonomy parse
	// time from all three label sources: explicit per-event annotation,
	// global field name mapping, and regex patterns. Nil when no
	// sensitivity config is defined. Read-only after construction.
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

	// DefaultEnabled lists category names that are enabled at startup.
	// Events in categories not listed here are silently discarded
	// unless explicitly enabled at runtime via [Logger.EnableCategory].
	// An empty slice means all non-lifecycle categories are disabled;
	// all events will be silently discarded until enabled at runtime.
	DefaultEnabled []string

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

	// lifecycleCategory is the category name used for framework-
	// provided lifecycle events.
	lifecycleCategory = "lifecycle"
)

// ErrTaxonomyInvalid is the sentinel error wrapped by taxonomy
// validation failures.
var ErrTaxonomyInvalid = errors.New("audit: taxonomy validation failed")

// InjectLifecycleEvents adds the "lifecycle" category with "startup"
// and "shutdown" events to t if they are not already defined:
//
//   - startup:  required [app_name], optional [version, config]
//   - shutdown: required [app_name], optional [reason, uptime_ms]
//
// If the consumer has already defined events with these names, their
// definitions are preserved unchanged. The "lifecycle" category is
// always added to [Taxonomy.DefaultEnabled].
//
// Calling InjectLifecycleEvents multiple times is safe and idempotent.
// [WithTaxonomy] calls it automatically; it is exported so that
// [ParseTaxonomyYAML] can apply the same
// injection before calling [ValidateTaxonomy].
func InjectLifecycleEvents(t *Taxonomy) {
	if t.Categories == nil {
		t.Categories = make(map[string]*CategoryDef)
	}
	if t.Events == nil {
		t.Events = make(map[string]*EventDef)
	}

	// Ensure lifecycle category exists.
	if _, ok := t.Categories[lifecycleCategory]; !ok {
		t.Categories[lifecycleCategory] = &CategoryDef{}
	}

	lc := t.Categories[lifecycleCategory]

	// Inject startup if not already defined.
	if _, ok := t.Events["startup"]; !ok {
		startupSev := 6 // Notice — application started
		t.Events["startup"] = &EventDef{
			Categories:  []string{lifecycleCategory},
			Description: "Application started",
			Severity:    &startupSev,
			Required:    []string{"app_name"},
			Optional:    []string{"version", "config"},
		}
		if !slices.Contains(lc.Events, "startup") {
			lc.Events = append(lc.Events, "startup")
		}
	}

	// Inject shutdown if not already defined.
	if _, ok := t.Events["shutdown"]; !ok {
		shutdownSev := 7 // High — audit coverage ending
		t.Events["shutdown"] = &EventDef{
			Categories:  []string{lifecycleCategory},
			Description: "Application shutting down",
			Severity:    &shutdownSev,
			Required:    []string{"app_name"},
			Optional:    []string{"reason", "uptime_ms"},
		}
		if !slices.Contains(lc.Events, "shutdown") {
			lc.Events = append(lc.Events, "shutdown")
		}
	}

	// Ensure lifecycle category is in DefaultEnabled.
	if !slices.Contains(t.DefaultEnabled, lifecycleCategory) {
		t.DefaultEnabled = append(t.DefaultEnabled, lifecycleCategory)
	}
}

// precomputeTaxonomy populates the pre-computed fields on every
// EventDef in the taxonomy. This includes deriving Categories from
// the categories map (for Go-level construction where categories
// are not set on EventDef directly) and building the field lookup
// structures. Must be called after validation succeeds.
func precomputeTaxonomy(t *Taxonomy) {
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

	precomputeSensitivity(t)
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
func ValidateTaxonomy(t Taxonomy) error {
	var errs []string
	errs = append(errs, checkTaxonomyVersion(t)...)
	errs = append(errs, checkCategoryConsistency(t)...)
	errs = append(errs, checkSeverityRanges(t)...)
	errs = append(errs, checkFieldOverlap(t)...)
	errs = append(errs, checkDefaultEnabled(t)...)
	errs = append(errs, checkSensitivity(t)...)

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%w:\n- %s", ErrTaxonomyInvalid, strings.Join(errs, "\n- "))
	}
	return nil
}

// checkTaxonomyVersion validates the taxonomy version field.
func checkTaxonomyVersion(t Taxonomy) []string {
	if t.Version == 0 {
		return []string{"taxonomy version is required: set version to 1"}
	}
	if t.Version > currentTaxonomyVersion {
		return []string{fmt.Sprintf(
			"taxonomy version %d is not supported by this library version (max: %d), upgrade the library",
			t.Version, currentTaxonomyVersion)}
	}
	if t.Version < minSupportedTaxonomyVersion {
		return []string{fmt.Sprintf(
			"taxonomy version %d is no longer supported, minimum supported is %d",
			t.Version, minSupportedTaxonomyVersion)}
	}
	return nil
}

// checkCategoryConsistency validates categories and their members.
// Events MAY appear in multiple categories.
func checkCategoryConsistency(t Taxonomy) []string {
	var errs []string
	if len(t.Categories) == 0 {
		errs = append(errs, "taxonomy must define at least one category")
	}

	// Every event listed in Categories must exist in Events map.
	for cat, catDef := range t.Categories {
		if catDef == nil {
			errs = append(errs, fmt.Sprintf("category %q has nil definition", cat))
			continue
		}
		for _, et := range catDef.Events {
			if _, ok := t.Events[et]; !ok {
				errs = append(errs, fmt.Sprintf(
					"category %q lists event type %q which is not defined in Events",
					cat, et))
			}
		}
	}
	return errs
}

// checkSeverityRanges validates that severity values are in range 0-10.
func checkSeverityRanges(t Taxonomy) []string {
	var errs []string
	for cat, catDef := range t.Categories {
		if catDef == nil {
			continue // nil categories caught by checkCategoryConsistency
		}
		if catDef.Severity != nil && (*catDef.Severity < 0 || *catDef.Severity > 10) {
			errs = append(errs, fmt.Sprintf(
				"category %q severity %d is out of range 0-10", cat, *catDef.Severity))
		}
	}
	for et, def := range t.Events {
		if def.Severity != nil && (*def.Severity < 0 || *def.Severity > 10) {
			errs = append(errs, fmt.Sprintf(
				"event %q severity %d is out of range 0-10", et, *def.Severity))
		}
	}
	return errs
}

// checkFieldOverlap validates no field appears in both Required and Optional.
// YAML-parsed taxonomies are structurally immune to this condition (a map
// key cannot appear twice), but programmatic taxonomy construction in Go
// can produce this misconfiguration.
func checkFieldOverlap(t Taxonomy) []string {
	var errs []string
	for et, def := range t.Events {
		seen := make(map[string]bool, len(def.Required))
		for _, f := range def.Required {
			seen[f] = true
		}
		for _, f := range def.Optional {
			if seen[f] {
				errs = append(errs, fmt.Sprintf(
					"event %q has field %q in both Required and Optional",
					et, f))
			}
		}
	}
	return errs
}

// checkDefaultEnabled validates that DefaultEnabled references valid categories.
func checkDefaultEnabled(t Taxonomy) []string {
	var errs []string
	for _, cat := range t.DefaultEnabled {
		if _, ok := t.Categories[cat]; !ok {
			errs = append(errs, fmt.Sprintf(
				"DefaultEnabled references category %q which does not exist",
				cat))
		}
	}
	return errs
}

// frameworkFieldNames lists field names managed by the framework that
// must not be labeled with sensitivity labels. These fields are always
// transmitted to every output regardless of exclusion filters.
var frameworkFieldNames = []string{"timestamp", "event_type", "severity", "duration_ms"}

// labelNamePattern validates sensitivity label names. Labels must start
// with a lowercase letter and contain only lowercase letters, digits,
// and underscores.
var labelNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// checkSensitivity validates the sensitivity label configuration.
func checkSensitivity(t Taxonomy) []string {
	if t.Sensitivity == nil || len(t.Sensitivity.Labels) == 0 {
		return nil
	}
	var errs []string
	errs = append(errs, checkLabelNames(t.Sensitivity)...)
	errs = append(errs, checkLabelPatterns(t.Sensitivity)...)
	errs = append(errs, checkLabelProtectedFields(t.Sensitivity)...)
	errs = append(errs, checkFieldAnnotationLabels(t)...)
	return errs
}

// checkLabelNames validates that all label names match the required pattern.
func checkLabelNames(sc *SensitivityConfig) []string {
	var errs []string
	for name := range sc.Labels {
		if name == "" {
			errs = append(errs, "sensitivity label name must not be empty")
			continue
		}
		if !labelNamePattern.MatchString(name) {
			errs = append(errs, fmt.Sprintf(
				"sensitivity label %q does not match required pattern [a-z][a-z0-9_]*", name))
		}
	}
	return errs
}

// checkLabelPatterns validates that all regex patterns compile and do
// not match framework field names.
func checkLabelPatterns(sc *SensitivityConfig) []string {
	var errs []string
	for labelName, label := range sc.Labels {
		if label == nil {
			continue
		}
		for i, pattern := range label.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				errs = append(errs, fmt.Sprintf(
					"sensitivity label %q pattern %d %q is invalid: %v",
					labelName, i, pattern, err))
				continue
			}
			for _, fw := range frameworkFieldNames {
				if re.MatchString(fw) {
					errs = append(errs, fmt.Sprintf(
						"sensitivity label %q pattern %q matches protected framework field %q",
						labelName, pattern, fw))
				}
			}
		}
	}
	return errs
}

// checkLabelProtectedFields validates that global field name mappings
// do not reference framework fields.
func checkLabelProtectedFields(sc *SensitivityConfig) []string {
	fwSet := make(map[string]struct{}, len(frameworkFieldNames))
	for _, fw := range frameworkFieldNames {
		fwSet[fw] = struct{}{}
	}
	var errs []string
	for labelName, label := range sc.Labels {
		if label == nil {
			continue
		}
		for _, field := range label.Fields {
			if _, ok := fwSet[field]; ok {
				errs = append(errs, fmt.Sprintf(
					"sensitivity label %q global field %q is a protected framework field",
					labelName, field))
			}
		}
	}
	return errs
}

// checkFieldAnnotationLabels validates that per-event field label
// annotations reference labels defined in the sensitivity config.
func checkFieldAnnotationLabels(t Taxonomy) []string {
	if t.Sensitivity == nil {
		return nil
	}
	fwSet := make(map[string]struct{}, len(frameworkFieldNames))
	for _, fw := range frameworkFieldNames {
		fwSet[fw] = struct{}{}
	}
	var errs []string
	for evtName, def := range t.Events {
		errs = append(errs, checkEventFieldAnnotations(evtName, def, t.Sensitivity, fwSet)...)
	}
	return errs
}

// checkEventFieldAnnotations validates a single event's field label
// annotations against the sensitivity config and framework fields.
func checkEventFieldAnnotations(evtName string, def *EventDef, sc *SensitivityConfig, fwSet map[string]struct{}) []string {
	if def == nil || def.fieldAnnotations == nil {
		return nil
	}
	var errs []string
	for fieldName, labels := range def.fieldAnnotations {
		if _, ok := fwSet[fieldName]; ok {
			errs = append(errs, fmt.Sprintf(
				"event %q field %q is a protected framework field and cannot be labeled",
				evtName, fieldName))
			continue
		}
		for _, label := range labels {
			if _, ok := sc.Labels[label]; !ok {
				errs = append(errs, fmt.Sprintf(
					"event %q field %q references undefined sensitivity label %q",
					evtName, fieldName, label))
			}
		}
	}
	return errs
}

// compileSensitivityPatterns compiles all regex patterns in the
// sensitivity config. This is called once at taxonomy parse time.
func compileSensitivityPatterns(sc *SensitivityConfig) error {
	for labelName, label := range sc.Labels {
		if label == nil {
			continue
		}
		label.compiled = make([]*regexp.Regexp, 0, len(label.Patterns))
		for _, pattern := range label.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("sensitivity label %q: invalid pattern %q: %w", labelName, pattern, err)
			}
			label.compiled = append(label.compiled, re)
		}
	}
	return nil
}

// precomputeSensitivity resolves sensitivity labels for all event
// fields from all three sources: explicit per-event annotation, global
// field name mapping, and regex patterns. Results are stored in
// EventDef.FieldLabels for use during field stripping at delivery time.
func precomputeSensitivity(t *Taxonomy) {
	if t.Sensitivity == nil || len(t.Sensitivity.Labels) == 0 {
		return
	}
	// Compile patterns (idempotent if already done by validation,
	// but may not be compiled for programmatic taxonomies).
	_ = compileSensitivityPatterns(t.Sensitivity)

	globalFieldLabels := buildGlobalFieldLabels(t.Sensitivity)

	for _, def := range t.Events {
		if def == nil {
			continue
		}
		resolveEventFieldLabels(def, t.Sensitivity, globalFieldLabels)
	}
}

// buildGlobalFieldLabels builds a lookup from field names to the set
// of labels they carry via global field name mappings.
func buildGlobalFieldLabels(sc *SensitivityConfig) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for labelName, label := range sc.Labels {
		if label == nil {
			continue
		}
		for _, field := range label.Fields {
			if result[field] == nil {
				result[field] = make(map[string]struct{})
			}
			result[field][labelName] = struct{}{}
		}
	}
	return result
}

// resolveEventFieldLabels resolves labels for all fields of a single
// event from all three sources and stores them in def.FieldLabels.
func resolveEventFieldLabels(def *EventDef, sc *SensitivityConfig, globalFieldLabels map[string]map[string]struct{}) {
	allFields := make([]string, 0, len(def.Required)+len(def.Optional))
	allFields = append(allFields, def.Required...)
	allFields = append(allFields, def.Optional...)
	if len(allFields) == 0 {
		return
	}
	fieldLabels := make(map[string]map[string]struct{})
	for _, fieldName := range allFields {
		labels := resolveFieldLabels(fieldName, def, sc, globalFieldLabels)
		if len(labels) > 0 {
			fieldLabels[fieldName] = labels
		}
	}
	if len(fieldLabels) > 0 {
		def.FieldLabels = fieldLabels
	}
}

// resolveFieldLabels merges labels for a single field from all three
// sources: explicit annotation, global field name mapping, and regex.
func resolveFieldLabels(fieldName string, def *EventDef, sc *SensitivityConfig, globals map[string]map[string]struct{}) map[string]struct{} {
	labels := make(map[string]struct{})

	// Source 1: explicit per-event annotation.
	if def.fieldAnnotations != nil {
		for _, l := range def.fieldAnnotations[fieldName] {
			labels[l] = struct{}{}
		}
	}

	// Source 2: global field name mapping.
	if g, ok := globals[fieldName]; ok {
		for l := range g {
			labels[l] = struct{}{}
		}
	}

	// Source 3: regex patterns.
	for labelName, label := range sc.Labels {
		if label == nil {
			continue
		}
		for _, re := range label.compiled {
			if re.MatchString(fieldName) {
				labels[labelName] = struct{}{}
				break
			}
		}
	}
	return labels
}
