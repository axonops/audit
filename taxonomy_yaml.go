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
	Categories     map[string][]string     `yaml:"categories"`
	Events         map[string]yamlEventDef `yaml:"events"`
	DefaultEnabled []string                `yaml:"default_enabled"`
	Version        int                     `yaml:"version"`
}

// yamlEventDef is the intermediate representation of a single event
// definition within the YAML taxonomy.
type yamlEventDef struct {
	Category string   `yaml:"category"`
	Required []string `yaml:"required"`
	Optional []string `yaml:"optional"`
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

	return tax, nil
}

// convertYAMLTaxonomy transforms the intermediate yamlTaxonomy into a
// [Taxonomy]. All maps and slices are defensively copied.
func convertYAMLTaxonomy(yt yamlTaxonomy) Taxonomy {
	categories := make(map[string][]string, len(yt.Categories))
	for name, events := range yt.Categories {
		cp := make([]string, len(events))
		copy(cp, events)
		categories[name] = cp
	}

	events := make(map[string]EventDef, len(yt.Events))
	for name, def := range yt.Events {
		ed := EventDef{
			Category: def.Category,
			Required: copyStrings(def.Required),
			Optional: copyStrings(def.Optional),
		}
		events[name] = ed
	}

	defaultEnabled := make([]string, len(yt.DefaultEnabled))
	copy(defaultEnabled, yt.DefaultEnabled)

	return Taxonomy{
		Version:        yt.Version,
		Categories:     categories,
		Events:         events,
		DefaultEnabled: defaultEnabled,
	}
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
