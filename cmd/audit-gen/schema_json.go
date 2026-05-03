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
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/axonops/audit"
)

// generateJSONSchema writes a JSON Schema (Draft 2020-12) document
// describing the JSON shape of a single audit event produced by
// [audit.JSONFormatter] for the supplied taxonomy.
//
// Shape:
//
//   - Always-present framework fields (timestamp, event_type,
//     severity, app_name, host, timezone, pid) are required.
//   - Reserved standard fields (the names returned by
//     [audit.ReservedStandardFieldNames]) are listed as optional
//     properties with their declared types.
//   - Per-taxonomy events are encoded as a top-level `oneOf`
//     branch keyed on `event_type`. Each branch lists the event's
//     required + optional custom fields with types inferred from
//     [audit.EventDef.FieldTypes].
//   - `unevaluatedProperties: false` at the root rejects unknown
//     fields. Branch-level `unevaluatedProperties` would not see
//     root properties and would over-reject.
//
// The generated schema is stable and self-contained — no external
// `$ref` lookups are required. It validates a single event document;
// consumers ingesting NDJSON streams validate one line at a time.
func generateJSONSchema(w io.Writer, tax audit.Taxonomy) error {
	schema := buildEventSchema(tax)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(schema); err != nil {
		return fmt.Errorf("encode json schema: %w", err)
	}
	return nil
}

// buildEventSchema constructs the full JSON Schema document for the
// supplied taxonomy as a Go map. Pure function for unit testing.
func buildEventSchema(tax audit.Taxonomy) map[string]any {
	root := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://github.com/axonops/audit/schema/audit-event.schema.json",
		"title":       "Audit event",
		"description": "Single audit event emitted by github.com/axonops/audit (JSONFormatter wire format).",
		"type":        "object",
	}

	// Required framework fields. event_category, duration_ms, and the
	// reserved standard fields are optional — present only when set.
	root["required"] = []string{
		"timestamp", "event_type", "severity",
		"app_name", "host", "timezone", "pid",
	}

	// Always-present property union: framework + reserved standard.
	props := frameworkFieldProperties()
	for k, v := range reservedStandardFieldProperties() {
		props[k] = v
	}
	root["properties"] = props

	// Per-event branches via oneOf — one branch per event type with
	// the event's required + optional custom field types pinned.
	if len(tax.Events) > 0 {
		root["oneOf"] = buildEventBranches(tax)
		// Strict unknown-property rejection at the ROOT.
		// unevaluatedProperties counts properties evaluated by
		// adjacent applicators on the same instance — including the
		// matched oneOf branch's properties — so framework + reserved
		// (root properties) and custom fields (branch properties) are
		// all considered "evaluated" and only truly unknown properties
		// are rejected.
		root["unevaluatedProperties"] = false
	} else {
		// Framework-only fallback (no taxonomy events): allow any
		// additional properties so callers can attach custom data
		// when they have not yet declared a taxonomy.
		root["additionalProperties"] = true
		root["description"] = "Framework-only audit event schema. Permissive: additionalProperties is true so consumer custom fields validate without re-derivation. For strict validation that pins per-event custom-field types, generate a taxonomy-aware schema with `audit-gen -format json-schema -input <your-taxonomy.yaml>`."
	}

	return root
}

// frameworkFieldProperties is the JSON Schema property block for the
// always-present framework fields. Mirrors the order in
// [audit.JSONFormatter] (timestamp, event_type, severity, ...).
func frameworkFieldProperties() map[string]any {
	return map[string]any{
		"timestamp": map[string]any{
			"type":        "string",
			"format":      "date-time",
			"description": "RFC 3339 timestamp at which the event was emitted.",
		},
		"event_type": map[string]any{
			"type":        "string",
			"description": "Taxonomy-defined event type name (e.g. 'user_create').",
		},
		"severity": map[string]any{
			"type":        "integer",
			"minimum":     0,
			"maximum":     10,
			"description": "Resolved severity (0=emerg, 7=debug, library cap 10).",
		},
		"event_category": map[string]any{
			"type":        "string",
			"description": "Taxonomy category for this delivery pass; absent for uncategorised events.",
		},
		"app_name": map[string]any{
			"type":        "string",
			"description": "Application name supplied via WithAppName.",
		},
		"host": map[string]any{
			"type":        "string",
			"description": "Host identifier supplied via WithHost.",
		},
		"timezone": map[string]any{
			"type":        "string",
			"description": "Timezone label supplied via WithTimezone (defaults to time.Local).",
		},
		"pid": map[string]any{
			"type":        "integer",
			"description": "Process ID at auditor construction time.",
		},
		"duration_ms": map[string]any{
			"type":        "integer",
			"description": "Optional event duration in milliseconds.",
		},
	}
}

// reservedStandardFieldProperties returns the JSON Schema property
// block for every reserved standard field, with types inferred from
// [audit.ReservedStandardFieldType].
func reservedStandardFieldProperties() map[string]any {
	out := make(map[string]any, len(audit.ReservedStandardFieldNames()))
	for _, name := range audit.ReservedStandardFieldNames() {
		t, _ := audit.ReservedStandardFieldType(name)
		out[name] = jsonSchemaTypeForReserved(t)
	}
	return out
}

// jsonSchemaTypeForReserved maps an [audit.ReservedFieldType] to its
// JSON Schema property block.
func jsonSchemaTypeForReserved(t audit.ReservedFieldType) map[string]any {
	switch t {
	case audit.ReservedFieldString:
		return map[string]any{"type": "string"}
	case audit.ReservedFieldInt, audit.ReservedFieldInt64:
		return map[string]any{"type": "integer"}
	case audit.ReservedFieldFloat64:
		return map[string]any{"type": "number"}
	case audit.ReservedFieldBool:
		return map[string]any{"type": "boolean"}
	case audit.ReservedFieldTime:
		return map[string]any{"type": "string", "format": "date-time"}
	case audit.ReservedFieldDuration:
		return map[string]any{"type": "string"}
	}
	return map[string]any{}
}

// jsonSchemaTypeForCustom maps a custom field's YAML-declared Go type
// to its JSON Schema property block. Unknown types fall back to
// `{"type": "string"}` — the same default the library applies when a
// `type:` annotation is omitted.
func jsonSchemaTypeForCustom(goType string) map[string]any {
	switch goType {
	case "", "string":
		return map[string]any{"type": "string"}
	case "int", "int64":
		return map[string]any{"type": "integer"}
	case "float64":
		return map[string]any{"type": "number"}
	case "bool":
		return map[string]any{"type": "boolean"}
	case "time.Time":
		return map[string]any{"type": "string", "format": "date-time"}
	case "time.Duration":
		return map[string]any{"type": "string"}
	}
	return map[string]any{"type": "string"}
}

// buildEventBranches builds one oneOf branch per event type. Each
// branch constrains event_type to the specific name and pins the
// branch's required + optional custom field types.
func buildEventBranches(tax audit.Taxonomy) []any {
	names := make([]string, 0, len(tax.Events))
	for n := range tax.Events {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]any, 0, len(names))
	for _, name := range names {
		def := tax.Events[name]
		out = append(out, buildEventBranch(name, def, tax))
	}
	return out
}

// buildEventBranch constructs the oneOf branch for one event type.
func buildEventBranch(name string, def *audit.EventDef, tax audit.Taxonomy) map[string]any {
	branchProps := map[string]any{
		"event_type": map[string]any{
			"type":  "string",
			"const": name,
		},
	}

	// Per-branch property type pinning for the custom fields named
	// in the event's Required + Optional lists. Reserved standard
	// fields are typed at the root; we don't need to repeat them.
	for _, field := range def.Required {
		addCustomFieldType(branchProps, field, def)
	}
	for _, field := range def.Optional {
		addCustomFieldType(branchProps, field, def)
	}

	// event_category is allowed on every branch (set per delivery
	// pass when the event matches a category).
	if catEnum := categoryEnumForEvent(name, tax); len(catEnum) > 0 {
		branchProps["event_category"] = map[string]any{
			"type": "string",
			"enum": catEnum,
		}
	}

	// Required: event_type plus any reserved/custom field listed in
	// def.Required. The framework-required fields (timestamp,
	// severity, ...) are pinned at the root and don't need repeating.
	required := append([]string{"event_type"}, def.Required...)
	tail := required[1:]
	sort.Strings(tail)

	return map[string]any{
		"properties": branchProps,
		"required":   required,
	}
}

// addCustomFieldType attaches a JSON Schema type entry for a custom
// (non-reserved) field. Reserved fields are typed at the schema root
// and omitted here.
func addCustomFieldType(props map[string]any, field string, def *audit.EventDef) {
	if _, isReserved := audit.ReservedStandardFieldType(field); isReserved {
		return
	}
	goType := def.FieldTypes[field]
	props[field] = jsonSchemaTypeForCustom(goType)
}

// categoryEnumForEvent returns the sorted list of category names this
// event type belongs to (for the event_category enum). Returns nil
// for uncategorised events; callers omit the property in that case.
func categoryEnumForEvent(eventType string, tax audit.Taxonomy) []string {
	def, ok := tax.Events[eventType]
	if !ok || len(def.Categories) == 0 {
		return nil
	}
	out := make([]string, len(def.Categories))
	copy(out, def.Categories)
	sort.Strings(out)
	return out
}
