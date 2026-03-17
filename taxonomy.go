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
	"sort"
	"strings"
)

// Fields is a typed alias for audit event field maps. Consumers pass
// field values as Fields to [Logger.Audit].
type Fields = map[string]interface{}

// EventDef defines a single audit event type in the taxonomy.
type EventDef struct {
	// Category is the taxonomy category this event belongs to
	// (e.g. "write", "security"). It must match a key in
	// [Taxonomy.Categories].
	Category string

	// Required lists field names that must be present in every
	// [Logger.Audit] call for this event type. Missing required
	// fields always produce an error regardless of validation mode.
	Required []string

	// Optional lists field names that may be present. In strict
	// validation mode, any field not in Required or Optional
	// produces an error.
	Optional []string
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
	// Version is the taxonomy schema version. Must be > 0.
	Version int

	// Categories maps category names to the event type names they
	// contain. Every event type must appear in exactly one category.
	Categories map[string][]string

	// Events maps event type names to their definitions. Every event
	// type listed in Categories must have a corresponding entry here.
	Events map[string]EventDef

	// DefaultEnabled lists category names that are enabled at startup.
	// Events in categories not listed here are silently discarded
	// unless explicitly enabled at runtime.
	DefaultEnabled []string
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

// injectLifecycleEvents adds the "lifecycle" category with "startup"
// and "shutdown" events if they are not already defined. If the
// consumer has already defined these events, their definitions are
// preserved.
func injectLifecycleEvents(t *Taxonomy) {
	if t.Categories == nil {
		t.Categories = make(map[string][]string)
	}
	if t.Events == nil {
		t.Events = make(map[string]EventDef)
	}

	// Ensure lifecycle category exists.
	if _, ok := t.Categories[lifecycleCategory]; !ok {
		t.Categories[lifecycleCategory] = nil
	}

	// Inject startup if not already defined.
	if _, ok := t.Events["startup"]; !ok {
		t.Events["startup"] = EventDef{
			Category: lifecycleCategory,
			Required: []string{"app_name"},
			Optional: []string{"version", "config"},
		}
		if !sliceContains(t.Categories[lifecycleCategory], "startup") {
			t.Categories[lifecycleCategory] = append(t.Categories[lifecycleCategory], "startup")
		}
	}

	// Inject shutdown if not already defined.
	if _, ok := t.Events["shutdown"]; !ok {
		t.Events["shutdown"] = EventDef{
			Category: lifecycleCategory,
			Required: []string{"app_name"},
			Optional: []string{"reason", "uptime_ms"},
		}
		if !sliceContains(t.Categories[lifecycleCategory], "shutdown") {
			t.Categories[lifecycleCategory] = append(t.Categories[lifecycleCategory], "shutdown")
		}
	}

	// Ensure lifecycle category is in DefaultEnabled.
	if !sliceContains(t.DefaultEnabled, lifecycleCategory) {
		t.DefaultEnabled = append(t.DefaultEnabled, lifecycleCategory)
	}
}

// validateTaxonomy checks the taxonomy for internal consistency and
// returns all problems found. The returned error wraps
// [ErrTaxonomyInvalid].
func validateTaxonomy(t Taxonomy) error {
	var errs []string

	// 1. Version must be > 0.
	if t.Version == 0 {
		errs = append(errs, "taxonomy version is required — set version: 1")
	} else if t.Version > currentTaxonomyVersion {
		errs = append(errs, fmt.Sprintf(
			"taxonomy version %d is not supported by this library version (max: %d), upgrade the library",
			t.Version, currentTaxonomyVersion))
	} else if t.Version < minSupportedTaxonomyVersion {
		errs = append(errs, fmt.Sprintf(
			"taxonomy version %d is no longer supported, minimum supported is %d",
			t.Version, minSupportedTaxonomyVersion))
	}

	// 2. Categories must not be empty.
	if len(t.Categories) == 0 {
		errs = append(errs, "taxonomy must define at least one category")
	}

	// Build reverse map: event type → category it appears in within Categories.
	eventToCategory := make(map[string][]string)
	for cat, events := range t.Categories {
		for _, et := range events {
			eventToCategory[et] = append(eventToCategory[et], cat)
		}
	}

	// 3. No duplicate event types across categories.
	for et, cats := range eventToCategory {
		if len(cats) > 1 {
			sort.Strings(cats)
			errs = append(errs, fmt.Sprintf(
				"event type %q appears in multiple categories: [%s]",
				et, strings.Join(cats, ", ")))
		}
	}

	// 4. Every event in Categories must exist in Events map.
	for cat, events := range t.Categories {
		for _, et := range events {
			if _, ok := t.Events[et]; !ok {
				errs = append(errs, fmt.Sprintf(
					"category %q lists event type %q which is not defined in Events",
					cat, et))
			}
		}
	}

	// 5. Every event in Events must reference a valid category and
	//    appear in that category's list.
	for et, def := range t.Events {
		if _, ok := t.Categories[def.Category]; !ok {
			errs = append(errs, fmt.Sprintf(
				"event %q references category %q which does not exist in Categories",
				et, def.Category))
		} else if !sliceContains(t.Categories[def.Category], et) {
			errs = append(errs, fmt.Sprintf(
				"event %q has category %q but is not listed in Categories[%q]",
				et, def.Category, def.Category))
		}
	}

	// 6. No field in both Required and Optional.
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

	// 7. DefaultEnabled must reference valid categories.
	for _, cat := range t.DefaultEnabled {
		if _, ok := t.Categories[cat]; !ok {
			errs = append(errs, fmt.Sprintf(
				"DefaultEnabled references category %q which does not exist",
				cat))
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%w:\n- %s", ErrTaxonomyInvalid, strings.Join(errs, "\n- "))
	}
	return nil
}

// sliceContains reports whether s contains v.
func sliceContains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
