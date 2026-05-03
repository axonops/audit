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
	"fmt"
	"io"
	"sort"

	"github.com/axonops/audit"
)

// generateCEFTemplate writes a documentation artifact describing the
// CEF mapping the library applies via [audit.CEFFormatter] for the
// supplied taxonomy. It is a TEMPLATE, not an executable encoding —
// SIEM rule authors read it to align field-extraction rules with the
// library's CEF output. Production CEF generation is still done by
// [audit.CEFFormatter].
func generateCEFTemplate(w io.Writer, tax audit.Taxonomy) error {
	mapping := audit.DefaultCEFFieldMapping()

	if _, err := fmt.Fprint(w, cefTemplateHeader); err != nil {
		return fmt.Errorf("write cef template: %w", err)
	}
	if err := writeFrameworkMapping(w); err != nil {
		return err
	}
	if err := writeReservedFieldMapping(w, mapping); err != nil {
		return err
	}
	if err := writeCustomFieldsForTaxonomy(w, tax); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, cefTemplateFooter); err != nil {
		return fmt.Errorf("write cef template footer: %w", err)
	}
	return nil
}

// cefTemplateHeader is the static prefix listing the CEF v0 header
// shape and the per-event placeholders.
const cefTemplateHeader = `# CEF mapping — github.com/axonops/audit
#
# This file documents the Common Event Format (CEF) v0 wire format
# emitted by audit.CEFFormatter for events produced from the
# taxonomy used to generate this artifact. SIEM rule authors and
# integrators reference it to align field extraction with the
# library's output.
#
# This is documentation — not an executable template. CEF generation
# in production is performed by audit.CEFFormatter; consumers do not
# render this template themselves.
#
# CEF v0 header (one line per event):
#
#   CEF:0|<vendor>|<product>|<version>|<event_type>|<event_type_label>|<cef_severity>|<extension>
#
# Where:
#
#   vendor / product / version  — supplied via CEFFormatter config.
#   event_type                  — taxonomy event name (e.g. user_create).
#   event_type_label            — same as event_type by default; may
#                                 be overridden via DescriptionFunc.
#   cef_severity                — audit severity (0-10) translated
#                                 to CEF severity (0-10) via
#                                 DefaultCEFSeverity:
#                                   audit 0-3  → CEF 0-3
#                                   audit 4-6  → CEF 4-6
#                                   audit 7-10 → CEF 7-10
#                                 (identity for the reserved 0-7
#                                 syslog range; clamped at 10).
#   extension                   — space-separated key=value pairs
#                                 (see field mappings below).
#
# Escape rules in the extension section:
#   backslash      \\
#   equals sign    \=
#   pipe           \|
#   newline        \n
#   carriage return \r
#
`

// cefTemplateFooter closes out the documentation with consumer notes.
const cefTemplateFooter = `
# Notes for SIEM rule authors:
#
#   - Custom string slots cs1..cs6 are the CEF idiom for non-standard
#     fields. Each cs<N> is paired with cs<N>Label so the receiving
#     SIEM can render the field name without out-of-band knowledge.
#     The library assigns slots in the order custom fields appear in
#     the Required + Optional lists for each event.
#
#   - Reserved standard field mappings are stable across the library
#     v1.0 line. New reserved fields land in minor releases; CEF
#     mappings for them are added at the same time.
#
#   - Framework fields are always present. Reserved standard and
#     custom fields are present only when the consumer supplies them.
#
#   - For events with multiple categories, the library emits one CEF
#     line per (event, category) tuple. The category appears in the
#     extension section under the cs<N>Label slot reserved for
#     event_category by the library (see custom-field allocation
#     above).
`

// writeFrameworkMapping emits the framework field → CEF key block.
func writeFrameworkMapping(w io.Writer) error {
	_, err := fmt.Fprint(w, `# Framework fields (always emitted):
#
#   timestamp        → rt                  (millis since Unix epoch)
#   event_type       → header field 5      (event class id)
#   severity         → header field 7      (cef_severity, see translation above)
#   app_name         → deviceProcessName
#   host             → dvchost
#   timezone         → dtz
#   pid              → dvcpid

`)
	if err != nil {
		return fmt.Errorf("write framework mapping: %w", err)
	}
	return nil
}

// writeReservedFieldMapping emits the sorted reserved standard field
// → CEF key block.
func writeReservedFieldMapping(w io.Writer, mapping map[string]string) error {
	if _, err := fmt.Fprint(w, "# Reserved standard fields (emitted when present on the event):\n#\n"); err != nil {
		return fmt.Errorf("write reserved header: %w", err)
	}
	keys := make([]string, 0, len(mapping))
	for k := range mapping {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	maxKey := 0
	for _, k := range keys {
		if len(k) > maxKey {
			maxKey = len(k)
		}
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(w, "#   %-*s → %s\n", maxKey, k, mapping[k]); err != nil {
			return fmt.Errorf("write reserved entry: %w", err)
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("write blank line: %w", err)
	}
	return nil
}

// writeCustomFieldsForTaxonomy emits the per-event custom-field slot
// allocation. Custom fields are mapped to cs1..cs6 (with cs<N>Label
// twin) in declaration order. Events with no custom fields are
// skipped to keep the output focused.
func writeCustomFieldsForTaxonomy(w io.Writer, tax audit.Taxonomy) error {
	if len(tax.Events) == 0 {
		return writeFrameworkOnlyCustomFooter(w)
	}
	if _, err := fmt.Fprint(w, "# Custom fields (per-event, in cs1..cs6 allocation order):\n#\n"); err != nil {
		return fmt.Errorf("write custom header: %w", err)
	}
	for _, eventType := range sortedEventNames(tax) {
		if err := writeCustomFieldsForEvent(w, eventType, tax.Events[eventType]); err != nil {
			return err
		}
	}
	return nil
}

// sortedEventNames returns the event-type names from a taxonomy in
// alphabetical order.
func sortedEventNames(tax audit.Taxonomy) []string {
	names := make([]string, 0, len(tax.Events))
	for n := range tax.Events {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// writeFrameworkOnlyCustomFooter emits the per-event placeholder
// block when the taxonomy has no events declared.
func writeFrameworkOnlyCustomFooter(w io.Writer) error {
	if _, err := fmt.Fprint(w, `# Custom fields (per-event):
#
#   No taxonomy events declared. Custom fields are allocated to
#   cs1..cs6 (with paired cs<N>Label) in the order they appear in
#   the event's Required + Optional lists.
#
`); err != nil {
		return fmt.Errorf("write framework-only custom: %w", err)
	}
	return nil
}

// writeCustomFieldsForEvent emits the cs1..cs6 slot allocation for
// one event's custom fields. Events without any custom fields are
// silently skipped.
func writeCustomFieldsForEvent(w io.Writer, eventType string, def *audit.EventDef) error {
	custom := customFieldsFor(def)
	if len(custom) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "#   %s\n", eventType); err != nil {
		return fmt.Errorf("write event header: %w", err)
	}
	for i, field := range custom {
		if err := writeCustomSlot(w, i+1, field); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("write blank line: %w", err)
	}
	return nil
}

// writeCustomSlot emits one cs<N> slot line, or an overflow notice
// when the slot index exceeds the cs1..cs6 capacity.
func writeCustomSlot(w io.Writer, slot int, field string) error {
	const maxSlot = 6
	if slot > maxSlot {
		if _, err := fmt.Fprintf(w, "#     %s → (overflow — slots cs1..cs6 exhausted)\n", field); err != nil {
			return fmt.Errorf("write overflow: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(w, "#     %-32s → cs%d (cs%dLabel=%q)\n", field, slot, slot, field); err != nil {
		return fmt.Errorf("write slot: %w", err)
	}
	return nil
}

// customFieldsFor returns the deduplicated list of non-reserved
// custom fields declared on an event.
func customFieldsFor(def *audit.EventDef) []string {
	out := make([]string, 0, len(def.Required)+len(def.Optional))
	seen := make(map[string]struct{}, cap(out))
	add := func(field string) {
		if _, dup := seen[field]; dup {
			return
		}
		if _, isReserved := audit.ReservedStandardFieldType(field); isReserved {
			return
		}
		seen[field] = struct{}{}
		out = append(out, field)
	}
	for _, f := range def.Required {
		add(f)
	}
	for _, f := range def.Optional {
		add(f)
	}
	return out
}
