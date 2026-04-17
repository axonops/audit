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
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/goccy/go-yaml"
)

// MaxTaxonomyInputSize is the maximum YAML input size accepted by
// [ParseTaxonomyYAML]. Inputs exceeding this limit are rejected
// with [ErrInvalidInput].
const MaxTaxonomyInputSize = 1 << 20 // 1 MiB

// yamlTaxonomy is the intermediate representation of a YAML taxonomy
// document. Field names use snake_case yaml tags matching the schema.
type yamlTaxonomy struct {
	Categories  yamlCategoriesResult    `yaml:"categories"`
	Events      map[string]yamlEventDef `yaml:"events"`
	Sensitivity *yamlSensitivity        `yaml:"sensitivity"`
	Version     int                     `yaml:"version"`
}

// yamlSensitivity is the intermediate representation of the sensitivity
// label configuration in YAML.
type yamlSensitivity struct {
	Labels map[string]*yamlSensitivityLabel `yaml:"labels"`
}

// yamlSensitivityLabel defines a single sensitivity label in YAML.
type yamlSensitivityLabel struct {
	Description string   `yaml:"description"`
	Fields      []string `yaml:"fields"`
	Patterns    []string `yaml:"patterns"`
}

// yamlCategoriesResult holds the parsed categories and the optional
// emit_event_category setting from the categories section.
type yamlCategoriesResult struct {
	categories        yamlCategories
	emitEventCategory *bool // nil = absent (default true)
}

// UnmarshalYAML parses the categories section, extracting both category
// definitions and the optional emit_event_category setting.
func (r *yamlCategoriesResult) UnmarshalYAML(data []byte) error {
	// First pass: unmarshal into a raw map to iterate keys.
	var raw yaml.MapSlice
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("categories must be a YAML mapping")
	}

	r.categories = make(yamlCategories, len(raw))

	for _, item := range raw {
		catName, ok := item.Key.(string)
		if !ok {
			return fmt.Errorf("category key must be a string")
		}
		if catName == "emit_event_category" {
			v, vOK := item.Value.(bool)
			if !vOK {
				return fmt.Errorf("emit_event_category: expected boolean")
			}
			r.emitEventCategory = &v
			continue
		}
		def, err := parseCategoryValue(catName, item.Value)
		if err != nil {
			return err
		}
		r.categories[catName] = def
	}
	return nil
}

// yamlCategories handles polymorphic YAML category parsing. Categories
// can be either a simple list of event names or a struct with severity
// and events. Both formats are supported in the same document.
type yamlCategories map[string]*yamlCategoryDef

// yamlCategoryDef represents a single category in YAML.
type yamlCategoryDef struct {
	Severity *int     `yaml:"severity"`
	Events   []string `yaml:"events"`
}

// parseCategoryValue handles polymorphic category parsing: a category
// value can be a sequence (simple list of event names) or a mapping
// (struct with severity and events).
func parseCategoryValue(catName string, value any) (*yamlCategoryDef, error) {
	switch v := value.(type) {
	case []any:
		// Simple list format: category: [event1, event2]
		events := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("category %q: event name must be a string", catName)
			}
			events = append(events, s)
		}
		return &yamlCategoryDef{Events: events}, nil

	case map[string]any:
		// Struct format: category: {severity: N, events: [...]}
		return parseCategoryMap(catName, v)

	default:
		return nil, fmt.Errorf("category %q: expected a sequence or mapping", catName)
	}
}

// parseCategoryMap decodes a struct-format category from a map and
// validates that only known fields (severity, events) are present.
func parseCategoryMap(catName string, m map[string]any) (*yamlCategoryDef, error) {
	allowed := map[string]struct{}{"severity": {}, "events": {}}
	for key := range m {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("category %q: unknown field %q", catName, key)
		}
	}
	var def yamlCategoryDef
	if sv, ok := m["severity"]; ok {
		s, err := toInt(sv)
		if err != nil {
			return nil, fmt.Errorf("category %q: severity must be an integer", catName)
		}
		def.Severity = &s
	}
	if ev, ok := m["events"]; ok {
		events, err := toStringSlice(ev)
		if err != nil {
			return nil, fmt.Errorf("category %q: %w", catName, err)
		}
		def.Events = events
	}
	return &def, nil
}

// toInt converts a YAML numeric value to int.
func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case uint64:
		return int(n), nil //nolint:gosec // severity range 0-10, no overflow risk
	case float64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

// toStringSlice converts a YAML sequence value to []string.
func toStringSlice(v any) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a sequence")
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", item)
		}
		result = append(result, s)
	}
	return result, nil
}

// yamlEventDef is the intermediate representation of a single event
// definition within the YAML taxonomy. Categories are derived from
// the categories map — there is no category field on events.
//
// Fields are declared in a unified fields: map. Each field entry
// specifies whether the field is required (default false = optional)
// and optionally carries sensitivity labels.
type yamlEventDef struct {
	Fields      map[string]*yamlFieldDef `yaml:"fields"`
	Severity    *int                     `yaml:"severity"`
	Description string                   `yaml:"description"`
}

// yamlFieldDef defines a single field within an event definition.
// A nil yamlFieldDef is treated as optional with no labels.
type yamlFieldDef struct {
	Labels   []string `yaml:"labels"`
	Required bool     `yaml:"required"`
}

// ParseTaxonomyYAML parses a YAML document into a [*Taxonomy].
// The input MUST be a single YAML document containing a valid taxonomy
// definition. Unknown keys are rejected.
//
// The returned Taxonomy is fully migrated, validated, and
// precomputed. Passing it to [WithTaxonomy] skips redundant
// re-validation.
//
// Input errors (empty, oversized, multi-document, invalid syntax) wrap
// [ErrInvalidInput]. Taxonomy validation errors wrap
// [ErrTaxonomyInvalid]. On error, nil is returned.
//
// ParseTaxonomyYAML accepts []byte only — no file paths, no readers.
// Use [embed.FS] or [os.ReadFile] in the caller to load from disk.
func ParseTaxonomyYAML(data []byte) (*Taxonomy, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: input is empty", ErrInvalidInput)
	}
	if len(data) > MaxTaxonomyInputSize {
		return nil, fmt.Errorf("%w: input size %d exceeds maximum %d bytes", ErrInvalidInput, len(data), MaxTaxonomyInputSize)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data), yaml.DisallowUnknownField())

	var yt yamlTaxonomy
	if err := dec.Decode(&yt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, WrapUnknownFieldError(err, yamlTaxonomy{})) //nolint:errorlint // intentionally not wrapping yaml.v3 error to avoid leaking third-party types into the public error chain
	}

	// Reject multi-document YAML and trailing content.
	var discard any
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: input contains multiple YAML documents", ErrInvalidInput)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content after YAML document: %v", ErrInvalidInput, err) //nolint:errorlint // intentionally not wrapping yaml.v3 error
	}

	tax := convertYAMLTaxonomy(yt)

	if err := MigrateTaxonomy(&tax); err != nil {
		return nil, err
	}

	if err := ValidateTaxonomy(tax); err != nil {
		return nil, err
	}

	if err := precomputeTaxonomy(&tax); err != nil {
		return nil, err
	}
	return &tax, nil
}

// convertYAMLTaxonomy transforms the intermediate yamlTaxonomy into a
// [Taxonomy]. All maps and slices are defensively copied. EventDef.Categories
// is derived from the categories map — events may belong to multiple
// categories or none (uncategorised).
func convertYAMLTaxonomy(yt yamlTaxonomy) Taxonomy {
	categories := make(map[string]*CategoryDef, len(yt.Categories.categories))
	for name, yamlCat := range yt.Categories.categories {
		categories[name] = &CategoryDef{
			Severity: copyIntPtr(yamlCat.Severity),
			Events:   copyStrings(yamlCat.Events),
		}
	}

	events := make(map[string]*EventDef, len(yt.Events))
	for name, def := range yt.Events {
		events[name] = convertYAMLEventDef(def)
	}

	// Derive EventDef.Categories from the categories map.
	for catName, catDef := range categories {
		for _, eventName := range catDef.Events {
			if def, ok := events[eventName]; ok {
				def.Categories = append(def.Categories, catName)
			}
		}
	}
	// Sort categories on each event for deterministic ordering.
	for _, def := range events {
		slices.Sort(def.Categories)
	}

	// Default emit_event_category to true when absent from YAML.
	// The Go struct uses SuppressEventCategory (inverted): zero value
	// (false) means "emit category", matching the YAML default.
	suppressEventCategory := false
	if yt.Categories.emitEventCategory != nil {
		suppressEventCategory = !*yt.Categories.emitEventCategory
	}

	tax := Taxonomy{
		Version:               yt.Version,
		Categories:            categories,
		Events:                events,
		SuppressEventCategory: suppressEventCategory,
	}

	if yt.Sensitivity != nil {
		tax.Sensitivity = convertYAMLSensitivity(yt.Sensitivity)
	}
	return tax
}

// convertYAMLSensitivity converts the YAML sensitivity config to a
// [SensitivityConfig].
func convertYAMLSensitivity(ys *yamlSensitivity) *SensitivityConfig {
	if ys == nil || len(ys.Labels) == 0 {
		return nil
	}
	sc := &SensitivityConfig{
		Labels: make(map[string]*SensitivityLabel, len(ys.Labels)),
	}
	for name, yl := range ys.Labels {
		label := &SensitivityLabel{
			Description: yl.Description,
			Fields:      copyStrings(yl.Fields),
			Patterns:    copyStrings(yl.Patterns),
		}
		sc.Labels[name] = label
	}
	return sc
}

// convertYAMLEventDef converts a single yamlEventDef into an [EventDef].
// Required and Optional are derived from the unified fields map. Per-field
// label annotations are stored in fieldAnnotations for later resolution
// by [precomputeSensitivity].
func convertYAMLEventDef(def yamlEventDef) *EventDef {
	ev := &EventDef{
		Description: def.Description,
		Severity:    copyIntPtr(def.Severity),
	}
	for fieldName, fieldDef := range def.Fields {
		if fieldDef == nil {
			ev.Optional = append(ev.Optional, fieldName)
			continue
		}
		if fieldDef.Required {
			ev.Required = append(ev.Required, fieldName)
		} else {
			ev.Optional = append(ev.Optional, fieldName)
		}
		if len(fieldDef.Labels) > 0 {
			if ev.fieldAnnotations == nil {
				ev.fieldAnnotations = make(map[string][]string)
			}
			ev.fieldAnnotations[fieldName] = copyStrings(fieldDef.Labels)
		}
	}
	slices.Sort(ev.Required)
	slices.Sort(ev.Optional)
	return ev
}

// copyIntPtr returns a copy of p. A nil input returns nil.
func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// copyStrings returns a shallow copy of s. A nil input returns nil.
func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}
