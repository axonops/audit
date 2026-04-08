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
	"regexp"
	"sort"
	"strings"
)

// ValidateTaxonomy checks the taxonomy for internal consistency. It verifies
// version bounds, category-event references, severity ranges, field overlaps,
// reserved field names, and sensitivity label validity. Returns an error
// wrapping [ErrTaxonomyInvalid] containing all problems found, with
// deterministic output. Callers MUST use [errors.Is] to test for
// [ErrTaxonomyInvalid].
func ValidateTaxonomy(t Taxonomy) error {
	var errs []string
	errs = append(errs, checkTaxonomyVersion(t)...)
	errs = append(errs, checkCategoryConsistency(t)...)
	errs = append(errs, checkSeverityRanges(t)...)
	errs = append(errs, checkFieldOverlap(t)...)
	errs = append(errs, checkReservedFieldNames(t)...)
	errs = append(errs, checkReservedStandardFields(t)...)
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

	// Validate category names — must match safe identifier pattern.
	for cat := range t.Categories {
		if !labelNamePattern.MatchString(cat) {
			errs = append(errs, fmt.Sprintf(
				"category name %q is invalid: must match %s",
				cat, labelNamePattern.String()))
		}
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

// reservedFieldNames returns the field names that consumers MUST NOT
// use as required or optional event fields. This is a subset of
// frameworkFieldNames — duration_ms is excluded because it can be
// legitimately set as a user field (the formatter handles the
// time.Duration vs int distinction at runtime).
func reservedFieldNames() []string {
	return []string{
		"timestamp", "event_type", "severity", "event_category",
		"app_name", "host", "timezone", "pid",
		"_hmac", "_hmac_v",
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
// The returned slice is a fresh copy; callers may modify it safely.
func ReservedStandardFieldNames() []string {
	return reservedStandardFieldNames()
}

func reservedStandardFieldNames() []string {
	return []string{
		"action",
		"actor_id",
		"actor_uid",
		"dest_host",
		"dest_ip",
		"dest_port",
		"end_time",
		"file_hash",
		"file_name",
		"file_path",
		"file_size",
		"message",
		"method",
		"outcome",
		"path",
		"protocol",
		"reason",
		"referrer",
		"request_id",
		"role",
		"session_id",
		"source_host",
		"source_ip",
		"source_port",
		"start_time",
		"target_id",
		"target_role",
		"target_type",
		"target_uid",
		"transport",
		"user_agent",
	}
}

// reservedStandardFieldMap is a precomputed set of reserved standard
// field names for O(1) lookup. Built once at package init from
// reservedStandardFieldNames. Read-only after init — safe for
// concurrent access without synchronisation.
var reservedStandardFieldMap = func() map[string]struct{} {
	names := reservedStandardFieldNames()
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

// isReservedStandardField is the package-internal alias.
func isReservedStandardField(name string) bool {
	return IsReservedStandardField(name)
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

// labelNamePattern validates sensitivity label names. Labels must start
// with a lowercase letter and contain only lowercase letters, digits,
// and underscores.
var labelNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
