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
)

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
			for _, fw := range frameworkFieldNames() {
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
	fwNames := frameworkFieldNames()
	fwSet := make(map[string]struct{}, len(fwNames))
	for _, fw := range fwNames {
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
	fwNames := frameworkFieldNames()
	fwSet := make(map[string]struct{}, len(fwNames))
	for _, fw := range fwNames {
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
				return fmt.Errorf("audit: sensitivity label %q: invalid pattern %q: %w", labelName, pattern, err)
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
func precomputeSensitivity(t *Taxonomy) error {
	if t.Sensitivity == nil || len(t.Sensitivity.Labels) == 0 {
		return nil
	}
	// Compile patterns. ValidateTaxonomy already checked pattern
	// validity, so compilation errors here indicate a programming
	// error (e.g., precomputeTaxonomy called without validation).
	if err := compileSensitivityPatterns(t.Sensitivity); err != nil {
		return fmt.Errorf("audit: sensitivity pattern compilation: %w", err)
	}

	globalFieldLabels := buildGlobalFieldLabels(t.Sensitivity)

	for _, def := range t.Events {
		if def == nil {
			continue
		}
		resolveEventFieldLabels(def, t.Sensitivity, globalFieldLabels)
	}
	return nil
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
