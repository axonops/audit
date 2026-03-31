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

	"gopkg.in/yaml.v3"
)

// ErrInvalidInput is returned when the YAML input to
// [ParseTaxonomyYAML] is structurally unsuitable (empty, oversized,
// multi-document, or syntactically invalid). Taxonomy validation
// errors wrap [ErrTaxonomyInvalid] instead.
var ErrInvalidInput = errors.New("audit: invalid input")

// MaxTaxonomyInputSize is the maximum YAML input size accepted by
// [ParseTaxonomyYAML]. Inputs exceeding this limit are rejected
// with [ErrInvalidInput].
const MaxTaxonomyInputSize = 1 << 20 // 1 MiB

// yamlTaxonomy is the intermediate representation of a YAML taxonomy
// document. Field names use snake_case yaml tags matching the schema.
type yamlTaxonomy struct {
	Categories     yamlCategories          `yaml:"categories"`
	Events         map[string]yamlEventDef `yaml:"events"`
	Sensitivity    *yamlSensitivity        `yaml:"sensitivity"`
	DefaultEnabled []string                `yaml:"default_enabled"`
	Version        int                     `yaml:"version"`
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

// yamlCategories handles polymorphic YAML category parsing. Categories
// can be either a simple list of event names or a struct with severity
// and events. Both formats are supported in the same document.
type yamlCategories map[string]*yamlCategoryDef

// yamlCategoryDef represents a single category in YAML.
type yamlCategoryDef struct {
	Severity *int     `yaml:"severity"`
	Events   []string `yaml:"events"`
}

// UnmarshalYAML handles polymorphic parsing: a category value can be
// either a sequence (list of event names) or a mapping (struct with
// severity and events fields).
func (c *yamlCategories) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("categories must be a YAML mapping")
	}

	*c = make(yamlCategories, len(value.Content)/2)

	for i := 0; i+1 < len(value.Content); i += 2 {
		catName := value.Content[i].Value
		def, err := parseCategoryNode(catName, value.Content[i+1])
		if err != nil {
			return err
		}
		(*c)[catName] = def
	}
	return nil
}

// parseCategoryNode handles polymorphic category parsing: a category
// value can be a sequence (simple list) or a mapping (struct with
// severity and events).
func parseCategoryNode(catName string, node *yaml.Node) (*yamlCategoryDef, error) {
	switch node.Kind {
	case yaml.SequenceNode:
		var events []string
		if err := node.Decode(&events); err != nil {
			return nil, fmt.Errorf("category %q: %w", catName, err)
		}
		return &yamlCategoryDef{Events: events}, nil

	case yaml.MappingNode:
		return parseCategoryMapping(catName, node)

	case yaml.ScalarNode, yaml.DocumentNode, yaml.AliasNode:
		return nil, fmt.Errorf("category %q: expected a sequence or mapping, got %v", catName, node.Kind)

	default:
		return nil, fmt.Errorf("category %q: expected a sequence or mapping", catName)
	}
}

// parseCategoryMapping decodes a struct-format category and validates
// that only known fields (severity, events) are present.
func parseCategoryMapping(catName string, node *yaml.Node) (*yamlCategoryDef, error) {
	allowed := map[string]struct{}{"severity": {}, "events": {}}
	for j := 0; j+1 < len(node.Content); j += 2 {
		if _, ok := allowed[node.Content[j].Value]; !ok {
			return nil, fmt.Errorf("category %q: unknown field %q", catName, node.Content[j].Value)
		}
	}
	var def yamlCategoryDef
	if err := node.Decode(&def); err != nil {
		return nil, fmt.Errorf("category %q: %w", catName, err)
	}
	return &def, nil
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

// ParseTaxonomyYAML parses a YAML document into a [Taxonomy].
// The input MUST be a single YAML document containing a valid taxonomy
// definition. Unknown keys are rejected.
//
// The returned Taxonomy is fully migrated, validated, and
// lifecycle-injected. Passing it to [WithTaxonomy] is safe;
// migration, injection, and validation run again inside WithTaxonomy
// but produce no additional errors for a well-formed taxonomy.
//
// Input errors (empty, oversized, multi-document, invalid syntax) wrap
// [ErrInvalidInput]. Taxonomy validation errors wrap
// [ErrTaxonomyInvalid].
//
// ParseTaxonomyYAML accepts []byte only — no file paths, no readers.
// Use [embed.FS] or [os.ReadFile] in the caller to load from disk.
func ParseTaxonomyYAML(data []byte) (Taxonomy, error) {
	if len(data) == 0 {
		return Taxonomy{}, fmt.Errorf("%w: input is empty", ErrInvalidInput)
	}
	if len(data) > MaxTaxonomyInputSize {
		return Taxonomy{}, fmt.Errorf("%w: input size %d exceeds maximum %d bytes", ErrInvalidInput, len(data), MaxTaxonomyInputSize)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var yt yamlTaxonomy
	if err := dec.Decode(&yt); err != nil {
		return Taxonomy{}, fmt.Errorf("%w: %v", ErrInvalidInput, err) //nolint:errorlint // intentionally not wrapping yaml.v3 error to avoid leaking third-party types into the public error chain
	}

	// Reject multi-document YAML and trailing content.
	var discard any
	if err := dec.Decode(&discard); err == nil {
		return Taxonomy{}, fmt.Errorf("%w: input contains multiple YAML documents", ErrInvalidInput)
	} else if !errors.Is(err, io.EOF) {
		return Taxonomy{}, fmt.Errorf("%w: trailing content after YAML document: %v", ErrInvalidInput, err) //nolint:errorlint // intentionally not wrapping yaml.v3 error
	}

	tax := convertYAMLTaxonomy(yt)
	InjectLifecycleEvents(&tax)

	if err := MigrateTaxonomy(&tax); err != nil {
		return Taxonomy{}, err
	}

	if err := ValidateTaxonomy(tax); err != nil {
		return Taxonomy{}, err
	}

	precomputeTaxonomy(&tax)
	return tax, nil
}

// convertYAMLTaxonomy transforms the intermediate yamlTaxonomy into a
// [Taxonomy]. All maps and slices are defensively copied. EventDef.Categories
// is derived from the categories map — events may belong to multiple
// categories or none (uncategorised).
func convertYAMLTaxonomy(yt yamlTaxonomy) Taxonomy {
	categories := make(map[string]*CategoryDef, len(yt.Categories))
	for name, yamlCat := range yt.Categories {
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

	defaultEnabled := make([]string, len(yt.DefaultEnabled))
	copy(defaultEnabled, yt.DefaultEnabled)

	tax := Taxonomy{
		Version:        yt.Version,
		Categories:     categories,
		Events:         events,
		DefaultEnabled: defaultEnabled,
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
