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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	audit "github.com/axonops/go-audit"
)

// validKey matches safe taxonomy identifiers for code generation.
var validKey = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// generateOptions controls which constant groups are emitted.
type generateOptions struct {
	Package    string
	Header     string
	InputFile  string
	Types      bool
	Fields     bool
	Categories bool
	Labels     bool
}

// constantDef represents a single generated constant.
type constantDef struct {
	Name        string // Go identifier, e.g. EventSchemaRegister
	Value       string // Original string, e.g. "schema_register"
	QuotedValue string // Go string literal, e.g. `"schema_register"`
	Comment     string // Non-empty → emitted as // comment above the constant
}

// eventFieldsDef holds the field breakdown for a single event type.
type eventFieldsDef struct {
	ConstName string   // Go constant name, e.g. EventUserCreate
	Required  []string // required field constant names (sorted)
	Optional  []string // optional field constant names (sorted)
}

// fieldLabelDef pairs a field constant with its label constants.
type fieldLabelDef struct {
	ConstName   string   // Go constant name, e.g. FieldEmail
	LabelConsts []string // sorted label constant names, e.g. LabelPii
}

// categoryEventsDef pairs a category constant with event constants.
type categoryEventsDef struct {
	ConstName   string   // Go constant name, e.g. CategoryWrite
	EventConsts []string // sorted event constant names
}

// templateData is the data passed to the Go template.
type templateData struct {
	Header         string
	Package        string
	Events         []constantDef
	Categories     []constantDef
	Fields         []constantDef
	Labels         []constantDef
	FieldLabels    []fieldLabelDef     // field → labels mapping
	EventFields    []eventFieldsDef    // event → required/optional fields
	CategoryEvents []categoryEventsDef // category → events
	HasEvents      bool
	HasCategories  bool
	HasFields      bool
	HasLabels      bool
	HasMetadata    bool // true when any metadata var is emitted
}

var tmpl = template.Must(template.New("audit-gen").Parse(tmplText))

const tmplText = `{{ .Header }}

package {{ .Package }}
{{ if .HasEvents }}
// Event type constants — use these instead of raw strings
// to get compile-time safety.
const (
{{- range .Events }}
{{ if .Comment }}	// {{ .Comment }}
{{ end }}	{{ .Name }} = {{ .QuotedValue }}
{{- end }}
)
{{ end }}{{ if .HasCategories }}
// Category constants — use with Logger.EnableCategory and
// Logger.DisableCategory.
const (
{{- range .Categories }}
	{{ .Name }} = {{ .QuotedValue }}
{{- end }}
)
{{ end }}{{ if .HasFields }}
// Field name constants — use in audit.Fields maps for
// compile-time typo prevention.
const (
{{- range .Fields }}
	{{ .Name }} = {{ .QuotedValue }}
{{- end }}
)
{{ end }}{{ if .HasLabels }}
// Sensitivity label constants — use with exclude_labels
// in output configuration.
const (
{{- range .Labels }}
{{ if .Comment }}	// {{ .Comment }}
{{ end }}	{{ .Name }} = {{ .QuotedValue }}
{{- end }}
)
{{ end }}{{ if .HasMetadata }}{{ if .FieldLabels }}
// FieldLabels maps field names to the sensitivity labels they carry.
// Resolved from all three mechanisms: explicit annotation, global
// field mapping, and regex patterns.
var FieldLabels = map[string][]string{
{{- range .FieldLabels }}
	{{ .ConstName }}: { {{- range $i, $l := .LabelConsts }}{{ if $i }}, {{ end }}{{ $l }}{{ end -}} },
{{- end }}
}
{{ end }}
// EventFields maps event types to their required and optional fields.
var EventFields = map[string]struct {
	Required []string
	Optional []string
}{
{{- range .EventFields }}
	{{ .ConstName }}: {
		Required: []string{ {{- range $i, $f := .Required }}{{ if $i }}, {{ end }}{{ $f }}{{ end -}} },
		Optional: []string{ {{- range $i, $f := .Optional }}{{ if $i }}, {{ end }}{{ $f }}{{ end -}} },
	},
{{- end }}
}

// CategoryEvents maps category names to their member event types.
var CategoryEvents = map[string][]string{
{{- range .CategoryEvents }}
	{{ .ConstName }}: { {{- range $i, $e := .EventConsts }}{{ if $i }}, {{ end }}{{ $e }}{{ end -}} },
{{- end }}
}
{{ end }}`

// generate produces Go source code from a taxonomy. The output is
// gofmt-formatted and deterministic (same input → byte-identical output).
func generate(w io.Writer, tax audit.Taxonomy, opts generateOptions) error {
	data, err := buildTemplateData(tax, opts)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if execErr := tmpl.Execute(&buf, data); execErr != nil {
		return fmt.Errorf("template execution: %w", execErr)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("gofmt: %w", err)
	}

	if _, err := w.Write(formatted); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func buildTemplateData(tax audit.Taxonomy, opts generateOptions) (templateData, error) {
	header := opts.Header
	if opts.InputFile != "" {
		header = fmt.Sprintf("// Code generated by audit-gen from %s; DO NOT EDIT.", opts.InputFile)
	}

	data := templateData{
		Header:  header,
		Package: opts.Package,
	}

	if opts.Types {
		var err error
		data.Events, err = buildEventConstants(tax)
		if err != nil {
			return templateData{}, err
		}
		data.HasEvents = len(data.Events) > 0
	}

	if opts.Categories {
		var err error
		data.Categories, err = buildConstants("Category", sortedKeys(tax.Categories))
		if err != nil {
			return templateData{}, err
		}
		data.HasCategories = len(data.Categories) > 0
	}

	if opts.Fields {
		var err error
		data.Fields, err = buildConstants("Field", collectFieldNames(tax))
		if err != nil {
			return templateData{}, err
		}
		data.HasFields = len(data.Fields) > 0
	}

	if opts.Labels {
		var err error
		data.Labels, err = buildLabelConstants(tax)
		if err != nil {
			return templateData{}, err
		}
		data.HasLabels = len(data.Labels) > 0
	}

	buildMetadata(&data, tax, opts)
	return data, nil
}

// buildMetadata populates the metadata vars in the template data.
// FieldLabels is only emitted when label constants are also emitted,
// since the metadata references Label* constants.
func buildMetadata(data *templateData, tax audit.Taxonomy, opts generateOptions) {
	if opts.Labels {
		data.FieldLabels = collectFieldLabels(tax)
	}
	data.EventFields = collectEventFields(tax)
	data.CategoryEvents = collectCategoryEvents(tax)
	data.HasMetadata = len(data.FieldLabels) > 0 ||
		len(data.EventFields) > 0 ||
		len(data.CategoryEvents) > 0
}

// buildLabelConstants creates label constant entries from the taxonomy's
// sensitivity config. Only emitted when labels are defined.
func buildLabelConstants(tax audit.Taxonomy) ([]constantDef, error) {
	if tax.Sensitivity == nil || len(tax.Sensitivity.Labels) == 0 {
		return nil, nil
	}
	return buildLabelConstantsFromConfig(tax.Sensitivity)
}

// buildLabelConstantsFromConfig creates label constant entries from
// a sensitivity config. Labels with nil definitions are skipped.
func buildLabelConstantsFromConfig(sc *audit.SensitivityConfig) ([]constantDef, error) {
	keys := sortedKeys(sc.Labels)
	nameToKey := make(map[string]string, len(keys))
	defs := make([]constantDef, 0, len(keys))
	for _, k := range keys {
		label := sc.Labels[k]
		if label == nil {
			continue
		}
		if !validKey.MatchString(k) {
			return nil, fmt.Errorf("sensitivity label %q contains characters unsafe for code generation", k)
		}
		name := "Label" + toPascalCase(k)
		if prev, ok := nameToKey[name]; ok {
			return nil, fmt.Errorf("naming collision: labels %q and %q both produce constant %q", prev, k, name)
		}
		nameToKey[name] = k

		comment := sanitiseComment(label.Description)
		if comment != "" {
			comment = name + " — " + comment
		}

		defs = append(defs, constantDef{
			Name:        name,
			Value:       k,
			QuotedValue: strconv.Quote(k),
			Comment:     comment,
		})
	}
	return defs, nil
}

// buildEventConstants creates event constant entries with optional
// description comments from the taxonomy.
func buildEventConstants(tax audit.Taxonomy) ([]constantDef, error) {
	keys := sortedKeys(tax.Events)
	nameToKey := make(map[string]string, len(keys))
	defs := make([]constantDef, 0, len(keys))
	for _, k := range keys {
		if !validKey.MatchString(k) {
			return nil, fmt.Errorf("taxonomy key %q contains characters unsafe for code generation", k)
		}
		name := "Event" + toPascalCase(k)
		if prev, ok := nameToKey[name]; ok {
			return nil, fmt.Errorf("naming collision: %q and %q both produce constant %q", prev, k, name)
		}
		nameToKey[name] = k

		comment := sanitiseComment(tax.Events[k].Description)
		if comment != "" {
			comment = name + " — " + comment
		}

		defs = append(defs, constantDef{
			Name:        name,
			Value:       k,
			QuotedValue: strconv.Quote(k),
			Comment:     comment,
		})
	}
	return defs, nil
}

// sanitiseComment collapses newlines and trims whitespace from a
// description for use as a single-line Go comment.
func sanitiseComment(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSpace(s)
}

// buildConstants creates constantDef entries from sorted keys with a
// prefix. It validates keys for code-generation safety and detects
// naming collisions.
func buildConstants(prefix string, keys []string) ([]constantDef, error) {
	nameToKey := make(map[string]string, len(keys))
	defs := make([]constantDef, 0, len(keys))
	for _, k := range keys {
		if !validKey.MatchString(k) {
			return nil, fmt.Errorf("taxonomy key %q contains characters unsafe for code generation", k)
		}
		name := prefix + toPascalCase(k)
		if prev, ok := nameToKey[name]; ok {
			return nil, fmt.Errorf("naming collision: %q and %q both produce constant %q", prev, k, name)
		}
		nameToKey[name] = k
		defs = append(defs, constantDef{
			Name:        name,
			Value:       k,
			QuotedValue: strconv.Quote(k),
		})
	}
	return defs, nil
}

// collectFieldNames returns all unique field names from the taxonomy, sorted.
func collectFieldNames(tax audit.Taxonomy) []string {
	seen := make(map[string]struct{})
	for _, def := range tax.Events {
		for _, f := range def.Required {
			seen[f] = struct{}{}
		}
		for _, f := range def.Optional {
			seen[f] = struct{}{}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// collectFieldLabels returns sorted field-to-labels mappings from all
// events in the taxonomy. Labels are deduplicated across events.
// Uses constant names (e.g., FieldEmail, LabelPii) instead of raw strings.
func collectFieldLabels(tax audit.Taxonomy) []fieldLabelDef {
	merged := mergeFieldLabels(tax)
	if len(merged) == 0 {
		return nil
	}
	result := make([]fieldLabelDef, 0, len(merged))
	for _, field := range sortedKeys(merged) {
		labelKeys := sortedKeys(merged[field])
		labelConsts := make([]string, len(labelKeys))
		for i, l := range labelKeys {
			labelConsts[i] = "Label" + toPascalCase(l)
		}
		result = append(result, fieldLabelDef{
			ConstName:   "Field" + toPascalCase(field),
			LabelConsts: labelConsts,
		})
	}
	return result
}

// mergeFieldLabels collects field-to-label mappings across all events,
// deduplicating labels for fields that appear in multiple events.
func mergeFieldLabels(tax audit.Taxonomy) map[string]map[string]struct{} {
	merged := make(map[string]map[string]struct{})
	for _, def := range tax.Events {
		if def == nil || def.FieldLabels == nil {
			continue
		}
		for field, labels := range def.FieldLabels {
			if merged[field] == nil {
				merged[field] = make(map[string]struct{})
			}
			for label := range labels {
				merged[field][label] = struct{}{}
			}
		}
	}
	return merged
}

// collectEventFields returns sorted event type field definitions
// using constant names (e.g., EventUserCreate, FieldActorID).
func collectEventFields(tax audit.Taxonomy) []eventFieldsDef {
	keys := sortedKeys(tax.Events)
	result := make([]eventFieldsDef, 0, len(keys))
	for _, name := range keys {
		def := tax.Events[name]
		if def == nil {
			continue
		}
		ef := eventFieldsDef{ConstName: "Event" + toPascalCase(name)}
		ef.Required = toFieldConsts(def.Required)
		ef.Optional = toFieldConsts(def.Optional)
		result = append(result, ef)
	}
	return result
}

// collectCategoryEvents returns sorted category-to-events mappings
// using constant names (e.g., CategoryWrite, EventUserCreate).
func collectCategoryEvents(tax audit.Taxonomy) []categoryEventsDef {
	keys := sortedKeys(tax.Categories)
	result := make([]categoryEventsDef, 0, len(keys))
	for _, name := range keys {
		cat := tax.Categories[name]
		if cat == nil {
			continue
		}
		events := make([]string, len(cat.Events))
		copy(events, cat.Events)
		sort.Strings(events)
		eventConsts := make([]string, len(events))
		for i, e := range events {
			eventConsts[i] = "Event" + toPascalCase(e)
		}
		result = append(result, categoryEventsDef{
			ConstName:   "Category" + toPascalCase(name),
			EventConsts: eventConsts,
		})
	}
	return result
}

// toFieldConsts converts raw field names to sorted Field constant names.
func toFieldConsts(fields []string) []string {
	sorted := make([]string, len(fields))
	copy(sorted, fields)
	sort.Strings(sorted)
	consts := make([]string, len(sorted))
	for i, f := range sorted {
		consts[i] = "Field" + toPascalCase(f)
	}
	return consts
}
