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
	"strings"
)

// ValidateTaxonomy checks the taxonomy for internal consistency. It verifies
// version bounds, category-event references, severity ranges, field overlaps,
// reserved field names, and sensitivity label validity. Returns an error
// wrapping [ErrTaxonomyInvalid] containing all problems found, with
// deterministic output. Callers MUST use [errors.Is] to test for
// [ErrTaxonomyInvalid]. When any consumer-controlled identifier (category
// name, event type key, field name, or sensitivity label name) violates
// [taxonomyNamePattern] or exceeds [maxTaxonomyNameLen], the returned
// error additionally wraps [ErrInvalidTaxonomyName].
func ValidateTaxonomy(t Taxonomy) error {
	var errs []string
	var nameErrs []string

	errs = append(errs, checkTaxonomyVersion(t)...)

	catNameErrs := checkCategoryNames(t)
	nameErrs = append(nameErrs, catNameErrs...)
	errs = append(errs, catNameErrs...)
	errs = append(errs, checkCategoryConsistency(t)...)

	evtFieldNameErrs := checkEventAndFieldNames(t)
	nameErrs = append(nameErrs, evtFieldNameErrs...)
	errs = append(errs, evtFieldNameErrs...)

	errs = append(errs, checkSeverityRanges(t)...)
	errs = append(errs, checkFieldOverlap(t)...)
	errs = append(errs, checkReservedFieldNames(t)...)
	errs = append(errs, checkReservedStandardFields(t)...)

	sensErrs, sensNameErrs := checkSensitivity(t)
	nameErrs = append(nameErrs, sensNameErrs...)
	errs = append(errs, sensErrs...)

	if len(errs) > 0 {
		slices.Sort(errs)
		joined := fmt.Errorf("%w:\n- %s", ErrTaxonomyInvalid, strings.Join(errs, "\n- "))
		if len(nameErrs) > 0 {
			// Wrap ErrInvalidTaxonomyName alongside ErrTaxonomyInvalid so
			// consumers can discriminate name-shape violations from other
			// taxonomy errors (#477).
			return errors.Join(joined, ErrInvalidTaxonomyName)
		}
		return joined
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

// checkCategoryNames validates that every category map key matches
// [taxonomyNamePattern] and fits within [maxTaxonomyNameLen]. Returned
// errors are wrapped alongside [ErrInvalidTaxonomyName] by
// [ValidateTaxonomy] so consumers can discriminate name-shape
// violations from other taxonomy errors (#477).
//
// Iteration is sorted so error output is deterministic.
func checkCategoryNames(t Taxonomy) []string {
	var errs []string
	catNames := make([]string, 0, len(t.Categories))
	for cat := range t.Categories {
		catNames = append(catNames, cat)
	}
	slices.Sort(catNames)
	for _, cat := range catNames {
		if msg := invalidTaxonomyNameMsg("category name", cat); msg != "" {
			errs = append(errs, msg)
		}
	}
	return errs
}

// checkCategoryConsistency validates categories and their members.
// Events MAY appear in multiple categories. Name-shape checks are
// delegated to [checkCategoryNames] so the name-error sentinel can be
// wrapped independently.
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

// checkEventAndFieldNames validates that every event type key and every
// required/optional field name matches [taxonomyNamePattern] and fits
// within [maxTaxonomyNameLen]. Rejection protects downstream log
// consumers from bidi overrides, Unicode confusables, CEF/JSON
// metacharacters, and all C0/C1 control bytes (#477).
//
// Iteration is sorted so error output is deterministic — the caller's
// `slices.Sort(errs)` would order them anyway, but sorting here keeps
// the errors-per-event grouped in the sorted output.
func checkEventAndFieldNames(t Taxonomy) []string {
	var errs []string
	eventNames := make([]string, 0, len(t.Events))
	for name := range t.Events {
		eventNames = append(eventNames, name)
	}
	slices.Sort(eventNames)

	for _, name := range eventNames {
		if msg := invalidTaxonomyNameMsg("event type name", name); msg != "" {
			errs = append(errs, msg)
		}
		def := t.Events[name]
		// Field names from Required + Optional. Sort each slice copy so
		// the error output is stable even when the underlying slice is
		// unsorted (programmatic construction can produce any order).
		fieldNames := make([]string, 0, len(def.Required)+len(def.Optional))
		fieldNames = append(fieldNames, def.Required...)
		fieldNames = append(fieldNames, def.Optional...)
		slices.Sort(fieldNames)
		for _, fname := range fieldNames {
			if msg := invalidTaxonomyNameMsg(
				fmt.Sprintf("event %q field name", name),
				fname,
			); msg != "" {
				errs = append(errs, msg)
			}
		}
	}
	return errs
}

// invalidTaxonomyNameMsg returns an empty string when name is valid,
// or a human-readable message describing the violation otherwise.
// `position` describes what sort of name this is (e.g., "event type
// name", `event "user_create" field name`).
//
// %q is used to quote the name so control bytes and bidi characters
// appear as Go escape sequences (\x00, \u202e) in the error text
// rather than being rendered literally — prevents a malicious name
// from reordering terminal output when the error is printed.
func invalidTaxonomyNameMsg(position, name string) string {
	if len(name) > maxTaxonomyNameLen {
		return fmt.Sprintf(
			"%s %q exceeds maximum length %d bytes (got %d)",
			position, name, maxTaxonomyNameLen, len(name))
	}
	if !taxonomyNamePattern.MatchString(name) {
		return fmt.Sprintf(
			"%s %q is invalid: must match %s",
			position, name, taxonomyNamePattern.String())
	}
	return ""
}

// checkSeverityRanges validates that severity values are in the range
// [MinSeverity, MaxSeverity].
func checkSeverityRanges(t Taxonomy) []string {
	var errs []string
	for cat, catDef := range t.Categories {
		if catDef == nil {
			continue // nil categories caught by checkCategoryConsistency
		}
		if catDef.Severity != nil && (*catDef.Severity < MinSeverity || *catDef.Severity > MaxSeverity) {
			errs = append(errs, fmt.Sprintf(
				"category %q severity %d is out of range %d-%d",
				cat, *catDef.Severity, MinSeverity, MaxSeverity))
		}
	}
	for et, def := range t.Events {
		if def.Severity != nil && (*def.Severity < MinSeverity || *def.Severity > MaxSeverity) {
			errs = append(errs, fmt.Sprintf(
				"event %q severity %d is out of range %d-%d",
				et, *def.Severity, MinSeverity, MaxSeverity))
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

// reservedFieldNames returns the field names that consumers MUST NOT
// use as required or optional event fields. This is a subset of
// frameworkFieldNames — duration_ms is excluded because it can be
// legitimately set as a user field (the formatter handles the
// time.Duration vs int distinction at runtime).
func reservedFieldNames() []string {
	return []string{
		"timestamp", "event_type", "severity", "event_category",
		"app_name", "host", "timezone", "pid",
		"_hmac", "_hmac_version",
	}
}

// checkReservedFieldNames validates that no event defines a reserved
// field name as a required or optional field.
func checkReservedFieldNames(t Taxonomy) []string {
	reserved := make(map[string]struct{}, len(reservedFieldNames()))
	for _, name := range reservedFieldNames() {
		reserved[name] = struct{}{}
	}
	var errs []string
	for et, def := range t.Events {
		for _, f := range def.Required {
			if _, ok := reserved[f]; ok {
				errs = append(errs, fmt.Sprintf(
					"event %q field %q is a reserved framework field and cannot be used as a required field",
					et, f))
			}
		}
		for _, f := range def.Optional {
			if _, ok := reserved[f]; ok {
				errs = append(errs, fmt.Sprintf(
					"event %q field %q is a reserved framework field and cannot be used as an optional field",
					et, f))
			}
		}
	}
	return errs
}

// ReservedStandardFieldNames returns the well-known audit field names
// that are always available on any event without explicit taxonomy
// declaration. These fields are automatically accepted by the
// unknown-field check and have standard CEF extension key mappings.
// The returned slice is a fresh copy in deterministic alphabetical
// order; callers may modify it safely.
//
// The list is derived from the canonical type map in std_fields.go;
// see [ReservedStandardFieldType] for per-field type metadata.
func ReservedStandardFieldNames() []string {
	names := make([]string, 0, len(reservedStandardFieldTypes))
	for name := range reservedStandardFieldTypes {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// reservedStandardFieldMap is a precomputed set of reserved standard
// field names for O(1) lookup. Built once at package init from
// reservedStandardFieldNames. Read-only after init — safe for
// concurrent access without synchronisation.
var reservedStandardFieldMap = func() map[string]struct{} {
	names := ReservedStandardFieldNames()
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}()

// IsReservedStandardField reports whether name is a reserved standard
// field. Reserved standard fields are well-known audit field names
// (actor_id, source_ip, reason, etc.) that are always accepted without
// taxonomy declaration. Uses a precomputed map for O(1) lookup.
func IsReservedStandardField(name string) bool {
	_, ok := reservedStandardFieldMap[name]
	return ok
}

// checkReservedStandardFields validates that no event declares a
// reserved standard field as a bare optional (without required: true or
// sensitivity labels). Bare declarations are redundant because reserved
// standard fields are always available.
func checkReservedStandardFields(t Taxonomy) []string {
	reserved := reservedStandardFieldMap
	globalLabeled := globalLabeledFields(t)

	var errs []string
	for et, def := range t.Events {
		for _, f := range def.Optional {
			if _, ok := reserved[f]; !ok {
				continue
			}
			if isBareReservedStandardField(f, def, globalLabeled) {
				errs = append(errs, fmt.Sprintf(
					"event %q field %q is a reserved standard field -- it is always available without declaration; to reference it, set required: true or add labels",
					et, f))
			}
		}
	}
	return errs
}

// globalLabeledFields returns the set of field names that have at least
// one global sensitivity label mapping.
func globalLabeledFields(t Taxonomy) map[string]struct{} {
	labeled := make(map[string]struct{})
	if t.Sensitivity == nil {
		return labeled
	}
	for _, label := range t.Sensitivity.Labels {
		for _, f := range label.Fields {
			labeled[f] = struct{}{}
		}
	}
	return labeled
}

// isBareReservedStandardField reports whether a reserved standard field
// in Optional has no per-event annotations and no global labels.
//
// MUTATION-EQUIV(#571): the `len(annotations) > 0` boundary mutant is
// exempt because the only path that populates def.fieldAnnotations
// (taxonomy_yaml.go line 461) gates on `len(fieldDef.Labels) > 0`, so
// an entry with zero annotations cannot exist; the mutation differs
// only on the unreachable empty-slice state. See MUTATION_TESTING.md.
func isBareReservedStandardField(f string, def *EventDef, globalLabeled map[string]struct{}) bool {
	if annotations, ok := def.fieldAnnotations[f]; ok && len(annotations) > 0 {
		return false
	}
	if _, ok := globalLabeled[f]; ok {
		return false
	}
	return true
}

// frameworkFieldNames returns the field names managed by the framework.
// These names are reserved — they cannot be used as consumer-defined
// required or optional fields, cannot be tagged with sensitivity labels,
// and are always transmitted to every output regardless of exclusion
// filters.
//
// Note: The validation layer unconditionally protects duration_ms,
// while the runtime layer (isFrameworkField in format.go) only treats
// it as a framework field when the value is time.Duration. This is
// intentionally conservative — validation rejects labeling duration_ms
// to prevent accidental stripping in any context.
func frameworkFieldNames() []string {
	return []string{
		"timestamp", "event_type", "severity", "duration_ms", "event_category",
		"app_name", "host", "timezone", "pid",
	}
}

// taxonomyNamePattern validates every consumer-controlled identifier
// that surfaces in audit events and formatters — category names,
// sensitivity label names, event type keys, and field names. Names
// must start with a lowercase letter and contain only lowercase
// letters, digits, and underscores.
//
// Rationale: the pure-ASCII rule rejects bidi-override characters
// (U+202E, U+2066), zero-width chars (U+200B, U+FEFF), Unicode
// confusables (Cyrillic `а` U+0430 vs ASCII `a`), CEF metacharacters
// (|, =, \), and all C0/C1 control bytes — any of which could mislead
// SIEM operators or corrupt downstream log consumers.
var taxonomyNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// maxTaxonomyNameLen caps the length of taxonomy identifiers. A name
// of this size already wildly exceeds anything meaningful for a log
// key; the cap is a DoS safety net (downstream map keys, CEF line
// lengths, formatter buffers). Per #477 pre-coding security review.
const maxTaxonomyNameLen = 128
