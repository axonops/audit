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
	"unicode"

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
	Builders   bool
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

// builderDef describes a generated typed event builder.
type builderDef struct {
	StructName      string         // e.g., "UserCreateEvent"
	FieldsStruct    string         // e.g., "UserCreateFields"
	EventConst      string         // e.g., "EventUserCreate"
	Description     string         // taxonomy description
	Required        []builderField // constructor params (sorted by ParamName)
	Optional        []builderField // setter methods (sorted by SetterName)
	StandardSetters []builderField // reserved standard field setters not in Required/Optional
	Categories      []builderCat   // categories this event belongs to
}

// builderField describes a single field on a builder.
type builderField struct {
	GoName     string         // Go exported name, e.g., "ActorID" (for struct fields)
	ParamName  string         // Go param name, e.g., "actorID" (for constructor)
	SetterName string         // Go method name, e.g., "SetActorID"
	FieldConst string         // e.g., "FieldActorID"
	FieldName  string         // raw field name, e.g., "actor_id"
	GoType     string         // Go type for setter parameter, e.g., "string" or "int"
	Labels     []builderLabel // labels on this field
}

// standardFieldGoTypes maps reserved standard field names to their Go
// types. Fields not in this map default to "string".
var standardFieldGoTypes = map[string]string{
	"source_port": "int",
	"dest_port":   "int",
	"file_size":   "int",
}

func standardFieldGoType(name string) string {
	if t, ok := standardFieldGoTypes[name]; ok {
		return t
	}
	return "string"
}

// builderLabel is a label reference for generated godoc.
type builderLabel struct {
	ConstName   string // e.g., "LabelPii"
	Description string // e.g., "Personally identifiable information"
}

// builderCat is a category reference for generated Categories() method.
type builderCat struct {
	ConstName   string // e.g., "CategoryWrite"
	HasSeverity bool
	Severity    int
}

// templateData is the data passed to the Go template.
type templateData struct {
	Header                string
	Package               string
	Events                []constantDef
	Categories            []constantDef
	Fields                []constantDef
	Labels                []constantDef
	Builders              []builderDef
	FieldLabels           []fieldLabelDef     // field → labels mapping
	EventFields           []eventFieldsDef    // event → required/optional fields
	CategoryEvents        []categoryEventsDef // category → events
	HasEvents             bool
	HasCategories         bool
	HasFields             bool
	HasLabels             bool
	HasBuilders           bool
	HasSeverityInBuilders bool
	HasMetadata           bool // true when any metadata var is emitted
}

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

// buildMetadata populates the metadata vars and builders in the
// template data.
func buildMetadata(data *templateData, tax audit.Taxonomy, opts generateOptions) {
	if opts.Labels {
		data.FieldLabels = collectFieldLabels(tax)
	}
	data.EventFields = collectEventFields(tax)
	data.CategoryEvents = collectCategoryEvents(tax)
	data.HasMetadata = len(data.FieldLabels) > 0 ||
		len(data.EventFields) > 0 ||
		len(data.CategoryEvents) > 0

	if opts.Builders {
		data.Builders = collectBuilders(tax)
		data.HasBuilders = len(data.Builders) > 0
		for i := range data.Builders {
			for _, c := range data.Builders[i].Categories {
				if c.HasSeverity {
					data.HasSeverityInBuilders = true
					break
				}
			}
			if data.HasSeverityInBuilders {
				break
			}
		}
	}
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
	// Always include reserved standard fields so their constants
	// are generated even when not declared in the taxonomy.
	for _, f := range audit.ReservedStandardFieldNames() {
		seen[f] = struct{}{}
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

// collectBuilders creates typed builder definitions for each event type.
func collectBuilders(tax audit.Taxonomy) []builderDef {
	keys := sortedKeys(tax.Events)
	builders := make([]builderDef, 0, len(keys))
	for _, name := range keys {
		def := tax.Events[name]
		if def == nil {
			continue
		}
		b := buildOneBuilder(name, def, tax)
		builders = append(builders, b)
	}
	return builders
}

func buildOneBuilder(name string, def *audit.EventDef, tax audit.Taxonomy) builderDef {
	pascal := toPascalCase(name)
	b := builderDef{
		StructName:   pascal + "Event",
		FieldsStruct: pascal + "Fields",
		EventConst:   "Event" + pascal,
		Description:  sanitiseComment(def.Description),
	}

	// Required fields → constructor params.
	req := sortedCopyStr(def.Required)
	for _, f := range req {
		b.Required = append(b.Required, makeBuilderField(f, def, tax))
	}

	// Optional fields → setter methods.
	opt := sortedCopyStr(def.Optional)
	for _, f := range opt {
		b.Optional = append(b.Optional, makeBuilderField(f, def, tax))
	}

	// Reserved standard field setters — for fields not already in
	// Required or Optional.
	handled := make(map[string]struct{}, len(req)+len(opt))
	for _, f := range req {
		handled[f] = struct{}{}
	}
	for _, f := range opt {
		handled[f] = struct{}{}
	}
	for _, f := range audit.ReservedStandardFieldNames() {
		if _, ok := handled[f]; ok {
			continue
		}
		b.StandardSetters = append(b.StandardSetters, makeBuilderField(f, def, tax))
	}

	// Categories.
	for _, catName := range def.Categories {
		bc := builderCat{ConstName: "Category" + toPascalCase(catName)}
		if catDef, ok := tax.Categories[catName]; ok && catDef.Severity != nil {
			bc.HasSeverity = true
			bc.Severity = *catDef.Severity
		}
		b.Categories = append(b.Categories, bc)
	}

	return b
}

func makeBuilderField(fieldName string, def *audit.EventDef, tax audit.Taxonomy) builderField {
	pascal := toPascalCase(fieldName)
	goType := "any"
	if audit.IsReservedStandardField(fieldName) {
		goType = standardFieldGoType(fieldName)
	}
	bf := builderField{
		GoName:     pascal,
		ParamName:  toParamName(fieldName),
		SetterName: "Set" + pascal,
		FieldConst: "Field" + pascal,
		FieldName:  fieldName,
		GoType:     goType,
	}
	bf.Labels = resolveFieldLabels(fieldName, def, tax)
	return bf
}

// resolveFieldLabels extracts sensitivity label metadata for a field.
func resolveFieldLabels(fieldName string, def *audit.EventDef, tax audit.Taxonomy) []builderLabel {
	if def.FieldLabels == nil {
		return nil
	}
	labels, ok := def.FieldLabels[fieldName]
	if !ok {
		return nil
	}
	sorted := sortedKeys(labels)
	result := make([]builderLabel, 0, len(sorted))
	for _, labelName := range sorted {
		bl := builderLabel{ConstName: "Label" + toPascalCase(labelName)}
		if tax.Sensitivity != nil {
			if sl, ok := tax.Sensitivity.Labels[labelName]; ok {
				bl.Description = sanitiseComment(sl.Description)
			}
		}
		result = append(result, bl)
	}
	return result
}

// toParamName converts a snake_case field name to a Go parameter name
// (camelCase). Handles acronyms: "actor_id" → "actorID", "id" → "id".
func toParamName(s string) string {
	pascal := toPascalCase(s)
	if pascal == "" {
		return s
	}
	runes := []rune(pascal)
	// Find length of leading uppercase run (acronym detection).
	upper := 0
	for upper < len(runes) && runes[upper] >= 'A' && runes[upper] <= 'Z' {
		upper++
	}
	if upper == 0 {
		return pascal
	}
	// Entire name is uppercase (bare acronym like "ID") → all lowercase.
	if upper == len(runes) {
		return strings.ToLower(pascal)
	}
	// Acronym at start ("HTTPServer" → "httpServer"): lowercase all but
	// last uppercase letter which starts the next word.
	if upper > 1 {
		for i := range upper - 1 {
			runes[i] = unicode.ToLower(runes[i])
		}
	} else {
		runes[0] = unicode.ToLower(runes[0])
	}
	return string(runes)
}

func sortedCopyStr(s []string) []string {
	cp := make([]string, len(s))
	copy(cp, s)
	sort.Strings(cp)
	return cp
}
