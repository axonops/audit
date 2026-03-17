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
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Formatter serialises an audit event into a wire-format byte slice.
// Implementations MUST append a newline terminator. The library
// provides [JSONFormatter] and [CEFFormatter].
//
// Format is called from a single goroutine (the drain loop);
// implementations do not need to be safe for concurrent use.
type Formatter interface {
	Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error)
}

// TimestampFormat controls how timestamps are rendered in serialised
// output.
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

// JSONFormatter serialises audit events as line-delimited JSON.
//
// Fields are emitted in deterministic order: framework fields first
// (timestamp, event_type, duration_ms if present), then required
// fields (sorted), then optional fields (sorted), then any extra
// fields (sorted). Each event is terminated by a newline.
//
// [time.Duration] values are converted to int64 milliseconds.
// Timestamps are rendered according to [JSONFormatter.Timestamp]
// (default [TimestampRFC3339Nano]).
type JSONFormatter struct {
	// OmitEmpty controls whether zero-value fields are omitted.
	// When true, fields where [isZeroValue] returns true are skipped.
	OmitEmpty bool

	// Timestamp controls the timestamp format. Empty defaults to
	// [TimestampRFC3339Nano].
	Timestamp TimestampFormat
}

// Format serialises a single audit event as a JSON line.
func (f *JSONFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	enc := &jsonEncoder{buf: &buf, omitEmpty: f.OmitEmpty}

	// Framework fields first.
	enc.writeTimestamp(ts, f.tsFormat())
	enc.writeStringField("event_type", eventType)
	f.writeDuration(enc, fields)

	// Required fields (sorted).
	required := sortedFieldKeys(def.Required, fields, f.OmitEmpty)
	for _, k := range required {
		enc.writeField(k, fields[k])
	}

	// Optional fields (sorted).
	optional := sortedFieldKeys(def.Optional, fields, f.OmitEmpty)
	for _, k := range optional {
		enc.writeField(k, fields[k])
	}

	// Extra fields not in required or optional (sorted).
	extra := extraFieldKeys(def, fields, f.OmitEmpty)
	for _, k := range extra {
		enc.writeField(k, fields[k])
	}

	buf.WriteByte('}')
	buf.WriteByte('\n')

	if enc.err != nil {
		return nil, fmt.Errorf("audit: json format: %w", enc.err)
	}
	return buf.Bytes(), nil
}

func (f *JSONFormatter) tsFormat() TimestampFormat {
	if f.Timestamp == "" {
		return TimestampRFC3339Nano
	}
	return f.Timestamp
}

// writeDuration checks for a duration_ms field with a time.Duration
// value and writes it as int64 milliseconds.
func (f *JSONFormatter) writeDuration(enc *jsonEncoder, fields Fields) {
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			enc.writeInt64Field("duration_ms", d.Milliseconds())
			return
		}
		// Not a time.Duration — will be written as a regular field.
	}
}

// jsonEncoder writes JSON key-value pairs to a buffer with comma
// separation. It tracks the first error encountered.
type jsonEncoder struct {
	buf       *bytes.Buffer
	omitEmpty bool
	written   bool // true after the first field is written
	err       error
}

func (e *jsonEncoder) writeComma() {
	if e.written {
		e.buf.WriteByte(',')
	}
	e.written = true
}

func (e *jsonEncoder) writeTimestamp(ts time.Time, format TimestampFormat) {
	e.writeComma()
	e.buf.WriteString(`"timestamp":`)
	switch format {
	case TimestampUnixMillis:
		fmt.Fprintf(e.buf, "%d", ts.UnixMilli())
	default:
		data, _ := json.Marshal(ts.Format(time.RFC3339Nano))
		e.buf.Write(data)
	}
}

func (e *jsonEncoder) writeStringField(key, value string) {
	e.writeComma()
	fmt.Fprintf(e.buf, "%q:", key)
	data, err := json.Marshal(value)
	if err != nil && e.err == nil {
		e.err = err
	}
	e.buf.Write(data)
}

func (e *jsonEncoder) writeInt64Field(key string, value int64) {
	e.writeComma()
	fmt.Fprintf(e.buf, "%q:%d", key, value)
}

func (e *jsonEncoder) writeField(key string, value any) {
	if e.omitEmpty && isZeroValue(value) {
		return
	}

	// Convert time.Duration to int64 milliseconds.
	if d, ok := value.(time.Duration); ok {
		e.writeInt64Field(key, d.Milliseconds())
		return
	}

	e.writeComma()
	fmt.Fprintf(e.buf, "%q:", key)
	data, err := json.Marshal(value)
	if err != nil && e.err == nil {
		e.err = err
	}
	e.buf.Write(data)
}

// sortedFieldKeys returns the keys from fieldNames that exist in
// fields, sorted alphabetically. If omitEmpty is true, zero-value
// fields are excluded.
func sortedFieldKeys(fieldNames []string, fields Fields, omitEmpty bool) []string {
	if len(fieldNames) == 0 {
		return nil
	}
	keys := make([]string, 0, len(fieldNames))
	for _, k := range fieldNames {
		// Skip framework fields handled separately.
		if k == "timestamp" || k == "event_type" || k == "duration_ms" {
			continue
		}
		v, exists := fields[k]
		if !exists && omitEmpty {
			continue
		}
		if omitEmpty && isZeroValue(v) {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// extraFieldKeys returns field keys that are not in the EventDef's
// Required or Optional lists (i.e. extra fields from permissive mode),
// sorted alphabetically.
func extraFieldKeys(def *EventDef, fields Fields, omitEmpty bool) []string {
	known := make(map[string]bool, len(def.Required)+len(def.Optional)+3)
	for _, k := range def.Required {
		known[k] = true
	}
	for _, k := range def.Optional {
		known[k] = true
	}
	// Framework fields are handled separately.
	known["timestamp"] = true
	known["event_type"] = true
	known["duration_ms"] = true

	var extra []string
	for k, v := range fields {
		if known[k] {
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

// ---------------------------------------------------------------------------
// CEF Formatter
// ---------------------------------------------------------------------------

// DefaultCEFFieldMapping maps common audit field names to standard CEF
// extension keys. Consumers can override individual mappings via
// [CEFFormatter.FieldMapping].
var DefaultCEFFieldMapping = map[string]string{
	"actor_id":   "suser",
	"source_ip":  "src",
	"request_id": "externalId",
	"user_agent": "requestClientApplication",
	"method":     "requestMethod",
	"path":       "request",
	"outcome":    "outcome",
}

// CEFFormatter serialises audit events in Common Event Format (CEF).
//
// The output format is:
//
//	CEF:0|{Vendor}|{Product}|{Version}|{eventType}|{description}|{severity}|{extensions}
//
// Header fields use pipe (|) as a delimiter. Extension values use
// key=value pairs separated by spaces.
//
// # Escaping
//
// Header fields escape backslash and pipe: \ → \\, | → \|.
// Extension values escape backslash, equals, newline, and CR:
// \ → \\, = → \=, newline → \n (literal), CR → \r (literal).
// See the CEF specification for details.
//
// # Severity
//
// Severity is determined by [CEFFormatter.SeverityFunc]. If nil, all
// events default to severity 5 (medium). The consumer is responsible
// for defining severity for their event types.
type CEFFormatter struct {
	// Vendor is the CEF header vendor field (e.g. "AxonOps").
	Vendor string

	// Product is the CEF header product field (e.g. "SchemaRegistry").
	Product string

	// Version is the CEF header product version field (e.g. "1.0").
	Version string

	// SeverityFunc maps event types to CEF severity (0-10). If nil,
	// all events default to severity 5.
	SeverityFunc func(eventType string) int

	// DescriptionFunc maps event types to human-readable CEF
	// descriptions. If nil, the event type name is used.
	DescriptionFunc func(eventType string) string

	// FieldMapping maps audit field names to CEF extension keys.
	// If nil, [DefaultCEFFieldMapping] is used. Entries in this map
	// override the defaults; unmapped fields use their original name.
	FieldMapping map[string]string

	// OmitEmpty controls whether zero-value fields are omitted from
	// extensions.
	OmitEmpty bool
}

// Format serialises a single audit event as a CEF line.
func (f *CEFFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error) {
	severity := f.severity(eventType)
	description := f.description(eventType)
	mapping := f.fieldMapping()

	var ext strings.Builder

	// Timestamp as receipt time (epoch ms).
	writeExtField(&ext, "rt", fmt.Sprintf("%d", ts.UnixMilli()))

	// Event type as device action.
	writeExtField(&ext, "act", cefEscapeExtValue(eventType))

	// Duration if present.
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			writeExtField(&ext, "cn1", fmt.Sprintf("%d", d.Milliseconds()))
			writeExtField(&ext, "cn1Label", "durationMs")
		}
	}

	// All fields via mapping.
	allKeys := allFieldKeysSorted(def, fields, f.OmitEmpty)
	for _, k := range allKeys {
		if k == "duration_ms" || k == "timestamp" || k == "event_type" {
			continue
		}
		v := fields[k]
		if f.OmitEmpty && isZeroValue(v) {
			continue
		}
		extKey := mapFieldKey(k, mapping)
		if err := validateExtKey(extKey); err != nil {
			return nil, fmt.Errorf("audit: cef: field %q maps to invalid extension key %q: %w", k, extKey, err)
		}
		writeExtField(&ext, extKey, formatFieldValue(v))
	}

	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s\n",
		cefEscapeHeader(f.Vendor),
		cefEscapeHeader(f.Product),
		cefEscapeHeader(f.Version),
		cefEscapeHeader(eventType),
		cefEscapeHeader(description),
		severity,
		ext.String(),
	)
	return []byte(header), nil
}

func (f *CEFFormatter) severity(eventType string) int {
	if f.SeverityFunc != nil {
		return f.SeverityFunc(eventType)
	}
	return 5
}

func (f *CEFFormatter) description(eventType string) string {
	if f.DescriptionFunc != nil {
		return f.DescriptionFunc(eventType)
	}
	return eventType
}

func (f *CEFFormatter) fieldMapping() map[string]string {
	if f.FieldMapping != nil {
		return f.FieldMapping
	}
	return DefaultCEFFieldMapping
}

// cefEscapeHeader escapes characters in CEF header fields.
// Header fields use pipe (|) as delimiter -- pipes and backslashes
// MUST be escaped. Backslash is escaped first to avoid double-escaping.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// cefEscapeExtValue escapes characters in CEF extension values.
// Backslash is escaped first to avoid double-escaping.
func cefEscapeExtValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

// validExtKeyRe matches valid CEF extension key names.
var validExtKeyRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// validateExtKey returns an error if the key is not a valid CEF
// extension key name (must match [a-zA-Z0-9_]+).
func validateExtKey(key string) error {
	if !validExtKeyRe.MatchString(key) {
		return fmt.Errorf("audit: cef: invalid extension key %q, must match [a-zA-Z0-9_]+", key)
	}
	return nil
}

// writeExtField writes a key=value pair to the extension string.
func writeExtField(b *strings.Builder, key, value string) {
	if b.Len() > 0 {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(cefEscapeExtValue(value))
}

// mapFieldKey maps an audit field name to a CEF extension key using
// the provided mapping. If no mapping exists, the field name is used
// as-is.
func mapFieldKey(fieldName string, mapping map[string]string) string {
	if ext, ok := mapping[fieldName]; ok {
		return ext
	}
	return fieldName
}

// formatFieldValue converts a field value to a string for CEF
// extension values.
func formatFieldValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%g", val)
	case time.Duration:
		return fmt.Sprintf("%d", val.Milliseconds())
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// allFieldKeysSorted returns all field keys from the EventDef
// (required + optional) plus any extra fields, sorted alphabetically.
func allFieldKeysSorted(def *EventDef, fields Fields, omitEmpty bool) []string {
	seen := make(map[string]bool, len(def.Required)+len(def.Optional))
	var keys []string
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
