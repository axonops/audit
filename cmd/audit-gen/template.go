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

import "text/template"

var tmpl = template.Must(template.New("audit-gen").Parse(tmplText))

const tmplText = `{{ .Header }}

//nolint:all // generated code — do not lint
package {{ .Package }}
{{ if .HasBuilders }}
import "github.com/axonops/audit"
{{ end }}
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
// Category constants — use with Auditor.EnableCategory and
// Auditor.DisableCategory.
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
{{ end }}{{ if .HasBuilders }}{{ range $b := .Builders }}
// {{ $b.FieldsStruct }} describes every field on [{{ $b.EventConst }}] events.
type {{ $b.FieldsStruct }} struct {
{{- range $b.Required }}
	{{ .GoName }} audit.FieldInfo // required
{{- end }}
{{- range $b.Optional }}
	{{ .GoName }} audit.FieldInfo // optional
{{- end }}
{{- range $b.StandardSetters }}
	{{ .GoName }} audit.FieldInfo // reserved standard
{{- end }}
}

{{ if $b.Description }}// {{ $b.StructName }} builds a type-safe audit event: {{ $b.Description }}.
{{ else }}// {{ $b.StructName }} builds a type-safe audit event.
{{ end }}// A builder is not safe for concurrent use. Calling a setter
// multiple times overwrites the previous value.
type {{ $b.StructName }} struct {
	fields audit.Fields
}

// New{{ $b.StructName }} creates a {{ $b.EventConst }} event with required fields.
func New{{ $b.StructName }}({{ range $i, $f := $b.Required }}{{ if $i }}, {{ end }}{{ $f.ParamName }} {{ $f.GoType }}{{ end }}) *{{ $b.StructName }} {
	return &{{ $b.StructName }}{fields: audit.Fields{
{{- range $b.Required }}
		{{ .FieldConst }}: {{ .ParamName }},
{{- end }}
	}}
}
{{ range $b.Optional }}
// {{ .SetterName }} sets the {{ .FieldConst }} field.{{ range .Labels }}
// Sensitivity label: {{ .ConstName }} — {{ .Description }}{{ end }}
func (e *{{ $b.StructName }}) {{ .SetterName }}(v {{ .GoType }}) *{{ $b.StructName }} {
	e.fields[{{ .FieldConst }}] = v
	return e
}
{{ end }}{{ range $b.StandardSetters }}
// {{ .SetterName }} sets the reserved standard field "{{ .FieldName }}".
func (e *{{ $b.StructName }}) {{ .SetterName }}(v {{ .GoType }}) *{{ $b.StructName }} {
	e.fields[{{ .FieldConst }}] = v
	return e
}
{{ end }}
// EventType returns the event type name.
func (e *{{ $b.StructName }}) EventType() string { return {{ $b.EventConst }} }

// Fields returns the event fields for [audit.Auditor.AuditEvent].
func (e *{{ $b.StructName }}) Fields() audit.Fields { return e.fields }

// Description returns the taxonomy description.
func (e *{{ $b.StructName }}) Description() string { return {{ printf "%q" $b.Description }} }

// FieldInfo returns typed descriptors for every field on this event.
func (e *{{ $b.StructName }}) FieldInfo() {{ $b.FieldsStruct }} {
	return {{ $b.FieldsStruct }}{
{{- range $b.Required }}
		{{ .GoName }}: audit.FieldInfo{Name: {{ .FieldConst }}, Required: true{{ if .Labels }}, Labels: []audit.LabelInfo{ {{- range $i, $l := .Labels }}{{ if $i }}, {{ end }}{ Name: {{ $l.ConstName }}, Description: {{ printf "%q" $l.Description }}}{{ end -}} }{{ end }}},
{{- end }}
{{- range $b.Optional }}
		{{ .GoName }}: audit.FieldInfo{Name: {{ .FieldConst }}{{ if .Labels }}, Labels: []audit.LabelInfo{ {{- range $i, $l := .Labels }}{{ if $i }}, {{ end }}{ Name: {{ $l.ConstName }}, Description: {{ printf "%q" $l.Description }}}{{ end -}} }{{ end }}},
{{- end }}
{{- range $b.StandardSetters }}
		{{ .GoName }}: audit.FieldInfo{Name: {{ .FieldConst }}},
{{- end }}
	}
}

// Categories returns the categories this event belongs to.
func (e *{{ $b.StructName }}) Categories() []audit.CategoryInfo {
	return []audit.CategoryInfo{
{{- range $b.Categories }}
		{Name: {{ .ConstName }}{{ if .HasSeverity }}, Severity: intPtr({{ .Severity }}){{ end }}},
{{- end }}
	}
}
{{ end }}{{ if .HasSeverityInBuilders }}
func intPtr(n int) *int { return &n }
{{ end }}{{ end }}`
