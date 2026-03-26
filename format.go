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

// sortedFieldKeys returns the keys from fieldNames that exist in
// fields, sorted alphabetically. If omitEmpty is true, zero-value
// fields are excluded. Framework fields (timestamp, event_type) are
// always skipped. duration_ms is only skipped if the value is a
// [time.Duration] (already handled as a framework field); non-Duration
// values pass through as regular fields.
func sortedFieldKeys(fieldNames []string, fields Fields, omitEmpty bool) []string {
	if len(fieldNames) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fieldNames))
	for _, k := range fieldNames {
		if isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && shouldOmit(k, fields) {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// isFrameworkField reports whether k is a framework-managed field that
// should be skipped during user-field iteration.
func isFrameworkField(k string, fields Fields) bool {
	if k == "timestamp" || k == "event_type" {
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
// sorted alphabetically.
func extraFieldKeys(def *EventDef, fields Fields, omitEmpty bool) []string {
	known := make(map[string]bool, len(def.Required)+len(def.Optional)+2)
	for _, k := range def.Required {
		known[k] = true
	}
	for _, k := range def.Optional {
		known[k] = true
	}
	known["timestamp"] = true
	known["event_type"] = true

	extra := make([]string, 0, len(fields))
	for k, v := range fields {
		if known[k] || isFrameworkField(k, fields) {
			continue
		}
		if omitEmpty && isZeroValue(v) {
			continue
		}
		extra = append(extra, k)
	}
	slices.Sort(extra)
	return extra
}

// allFieldKeysSorted returns all field keys from the EventDef
// (required + optional) plus any extra fields, sorted alphabetically.
func allFieldKeysSorted(def *EventDef, fields Fields) []string {
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
