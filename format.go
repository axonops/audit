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
	"slices"
	"time"
)

// Formatter serialises an audit event into a wire-format byte slice.
// Implementations MUST append a newline terminator. The library
// provides [JSONFormatter] and [CEFFormatter].
//
// Format is called from a single goroutine (the drain loop);
// implementations do not need to be safe for concurrent use.
type Formatter interface {
	// Format serialises a single audit event into a wire-format byte
	// slice. Implementations MUST append a newline terminator; the
	// library passes the result directly to [Output.Write].
	//
	// ts is the wall-clock time recorded at drain time (not
	// submission). eventType is the registered event type name.
	// fields contains the caller-supplied key-value pairs. def is the
	// [EventDef] for eventType; it is never nil when called by the
	// library.
	//
	// A non-nil error causes the event to be dropped and
	// [Metrics.RecordSerializationError] to be called.
	Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error)
}

// TimestampFormat controls how timestamps are rendered in serialised
// output. Unrecognised values default to [TimestampRFC3339Nano].
type TimestampFormat string

const (
	// TimestampRFC3339Nano renders timestamps as RFC 3339 with
	// nanosecond precision (e.g. "2006-01-02T15:04:05.999999999Z07:00").
	// This is the default.
	TimestampRFC3339Nano TimestampFormat = "rfc3339nano"

	// TimestampUnixMillis renders timestamps as Unix epoch
	// milliseconds (e.g. 1709222400000).
	TimestampUnixMillis TimestampFormat = "unix_ms"
)

// sortedFieldKeys returns field keys filtered by framework field
// exclusion and optionally by zero-value omission. When a pre-sorted
// slice is available (non-nil), it is used directly. Otherwise the
// fallback slice is sorted on the fly. When omitEmpty is false and no
// framework fields are present, the pre-sorted slice is returned
// directly (zero allocation).
func sortedFieldKeys(sorted, fallback []string, fields Fields, omitEmpty bool) []string {
	src := sorted
	if src == nil {
		src = sortedCopy(fallback)
	}
	if len(src) == 0 {
		return nil
	}
	// Fast path: when omitEmpty is false and no framework fields
	// appear in the list, return it directly (zero allocation).
	if !omitEmpty && !containsFrameworkField(src, fields) {
		return src
	}
	keys := make([]string, 0, len(src))
	for _, k := range src {
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && shouldOmit(k, fields) {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// containsFrameworkField reports whether any key in sorted is a
// framework-managed field for the given fields map.
func containsFrameworkField(sorted []string, fields Fields) bool {
	for _, k := range sorted {
		if isFrameworkField(k, fields) {
			return true
		}
	}
	return false
}

// isFrameworkField reports whether k is a framework-managed field that
// should be skipped during user-field iteration.
func isFrameworkField(k string, fields Fields) bool {
	if k == "timestamp" || k == "event_type" || k == "severity" {
		return true
	}
	if k == "duration_ms" {
		_, isDuration := fields[k].(time.Duration)
		return isDuration
	}
	return false
}

// shouldOmit reports whether a field should be omitted when OmitEmpty
// is true: the field either does not exist or has a zero value.
func shouldOmit(k string, fields Fields) bool {
	v, exists := fields[k]
	return !exists || isZeroValue(v)
}

// extraFieldKeys returns field keys that are not in the EventDef's
// Required or Optional lists (i.e. extra fields from permissive mode),
// sorted alphabetically. Uses the pre-computed knownFields set to
// avoid per-call map allocation.
func extraFieldKeys(def *EventDef, fields Fields, omitEmpty bool) []string {
	known := effectiveKnownFields(def)
	capHint := len(fields) - len(known)
	if capHint < 0 {
		capHint = 0
	}
	extra := make([]string, 0, capHint)
	for k, v := range fields {
		if _, ok := known[k]; ok {
			continue
		}
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && isZeroValue(v) {
			continue
		}
		extra = append(extra, k)
	}
	if len(extra) == 0 {
		return nil
	}
	slices.Sort(extra)
	return extra
}

// effectiveKnownFields returns the pre-computed knownFields set or
// builds one from Required + Optional if pre-computed fields are nil.
func effectiveKnownFields(def *EventDef) map[string]struct{} {
	if def.knownFields != nil {
		return def.knownFields
	}
	known := make(map[string]struct{}, len(def.Required)+len(def.Optional))
	for _, k := range def.Required {
		known[k] = struct{}{}
	}
	for _, k := range def.Optional {
		known[k] = struct{}{}
	}
	return known
}

// allFieldKeysSorted returns all field keys from the EventDef
// (required + optional) plus any extra fields, sorted alphabetically.
// When pre-computed fields are available and no extra fields are
// present (the common case), sortedAllKeys is returned directly
// (zero allocation). Falls back to building the list from scratch
// when pre-computed fields are nil.
func allFieldKeysSorted(def *EventDef, fields Fields) []string {
	// Fall back to building from scratch if pre-computed fields
	// are not available (e.g. EventDef constructed outside taxonomy
	// registration).
	if def.knownFields == nil {
		return allFieldKeysSortedSlow(def, fields)
	}

	// Check if all field keys are known (common case).
	hasExtra := false
	for k := range fields {
		if _, ok := def.knownFields[k]; !ok && !isFrameworkField(k, fields) {
			hasExtra = true
			break
		}
	}
	if !hasExtra {
		return def.sortedAllKeys
	}

	// Slow path: extra fields present, build a combined sorted list.
	keys := make([]string, len(def.sortedAllKeys))
	copy(keys, def.sortedAllKeys)
	for k := range fields {
		if _, ok := def.knownFields[k]; ok {
			continue
		}
		if isFrameworkField(k, fields) {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// allFieldKeysSortedSlow builds the sorted key list from scratch when
// pre-computed fields are not available.
func allFieldKeysSortedSlow(def *EventDef, fields Fields) []string {
	seen := make(map[string]bool, len(def.Required)+len(def.Optional))
	keys := make([]string, 0, len(def.Required)+len(def.Optional)+len(fields))
	for _, k := range def.Required {
		seen[k] = true
		keys = append(keys, k)
	}
	for _, k := range def.Optional {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range fields {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
