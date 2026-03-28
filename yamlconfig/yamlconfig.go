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

package yamlconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/axonops/go-audit"
	"gopkg.in/yaml.v3"
)

// ErrInvalidInput is returned when the YAML input is structurally
// unsuitable (empty, oversized, multi-document, or syntactically
// invalid). Taxonomy validation errors wrap
// [audit.ErrTaxonomyInvalid] instead.
var ErrInvalidInput = errors.New("yamlconfig: invalid input")

// MaxInputSize is the maximum YAML input size accepted by
// [ParseTaxonomyYAML]. Inputs exceeding this limit are rejected
// with [ErrInvalidInput].
const MaxInputSize = 1 << 20 // 1 MiB

// yamlTaxonomy is the intermediate representation of a YAML taxonomy
// document. Field names use snake_case yaml tags matching the schema.
type yamlTaxonomy struct {
	Version        int                     `yaml:"version"`
	Categories     map[string][]string     `yaml:"categories"`
	Events         map[string]yamlEventDef `yaml:"events"`
	DefaultEnabled []string                `yaml:"default_enabled"`
}

// yamlEventDef is the intermediate representation of a single event
// definition within the YAML taxonomy.
type yamlEventDef struct {
	Category string   `yaml:"category"`
	Required []string `yaml:"required"`
	Optional []string `yaml:"optional"`
}

// ParseTaxonomyYAML parses a YAML document into an [audit.Taxonomy].
// The input MUST be a single YAML document containing a valid taxonomy
// definition. Unknown keys are rejected.
//
// The returned Taxonomy is fully validated and lifecycle-injected.
// Passing it to [audit.WithTaxonomy] is safe and idempotent; the
// injection and validation will run again but produce no additional
// errors.
//
// Input errors (empty, multi-document, invalid syntax) wrap
// [ErrInvalidInput]. Taxonomy validation errors wrap
// [audit.ErrTaxonomyInvalid].
//
// ParseTaxonomyYAML accepts []byte only — no file paths, no readers.
// Use [embed.FS] or [os.ReadFile] in the caller to load from disk.
func ParseTaxonomyYAML(data []byte) (audit.Taxonomy, error) {
	if len(data) == 0 {
		return audit.Taxonomy{}, fmt.Errorf("%w: input is empty", ErrInvalidInput)
	}
	if len(data) > MaxInputSize {
		return audit.Taxonomy{}, fmt.Errorf("%w: input size %d exceeds maximum %d bytes", ErrInvalidInput, len(data), MaxInputSize)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var yt yamlTaxonomy
	if err := dec.Decode(&yt); err != nil {
		return audit.Taxonomy{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	// Reject multi-document YAML.
	var discard yaml.Node
	if err := dec.Decode(&discard); !errors.Is(err, io.EOF) {
		return audit.Taxonomy{}, fmt.Errorf("%w: input contains multiple YAML documents", ErrInvalidInput)
	}

	tax := convert(yt)
	audit.InjectLifecycleEvents(&tax)

	if err := audit.ValidateTaxonomy(tax); err != nil {
		return audit.Taxonomy{}, err
	}

	return tax, nil
}

// convert transforms the intermediate yamlTaxonomy into an
// [audit.Taxonomy]. Nil slices are normalised to empty slices.
func convert(yt yamlTaxonomy) audit.Taxonomy {
	categories := make(map[string][]string, len(yt.Categories))
	for name, events := range yt.Categories {
		cp := make([]string, len(events))
		copy(cp, events)
		categories[name] = cp
	}

	events := make(map[string]audit.EventDef, len(yt.Events))
	for name, def := range yt.Events {
		ed := audit.EventDef{
			Category: def.Category,
			Required: copyStrings(def.Required),
			Optional: copyStrings(def.Optional),
		}
		events[name] = ed
	}

	defaultEnabled := make([]string, len(yt.DefaultEnabled))
	copy(defaultEnabled, yt.DefaultEnabled)

	return audit.Taxonomy{
		Version:        yt.Version,
		Categories:     categories,
		Events:         events,
		DefaultEnabled: defaultEnabled,
	}
}

// copyStrings returns a copy of s, or an empty non-nil slice if s is nil.
func copyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}
