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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultCEFFieldMappingEntries returns a new map containing the
// built-in audit-field-to-CEF-extension-key mapping. Each call returns
// a distinct map instance; callers may mutate the result without
// affecting other callers. No package-level mutable state is held.
func defaultCEFFieldMappingEntries() map[string]string {
	return map[string]string{
		"actor_id":   "suser",
		"source_ip":  "src",
		"request_id": "externalId",
		"user_agent": "requestClientApplication",
		"method":     "requestMethod",
		"path":       "request",
		"outcome":    "outcome",
	}
}

// DefaultCEFFieldMapping returns a new map containing the built-in
// field mapping from audit field names to standard CEF extension keys.
// Each call returns a distinct map instance; callers may freely mutate
// the result. Consumers can use this as a base, add or override
// entries, and pass the result to [CEFFormatter.FieldMapping].
func DefaultCEFFieldMapping() map[string]string {
	return defaultCEFFieldMappingEntries()
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
// Header fields escape backslash and pipe: \ -> \\, | -> \|.
// Newlines and carriage returns in headers are replaced with spaces.
// Extension values escape backslash, equals, newline, and CR:
// \ -> \\, = -> \=, newline -> \n (literal), CR -> \r (literal).
// All remaining C0 control characters (0x00-0x1F) are stripped.
//
// # Severity
//
// Severity is determined by [CEFFormatter.SeverityFunc]. If nil, all
// events default to severity 5 (medium). Values are clamped to the
// valid CEF range 0-10.
type CEFFormatter struct {
	// SeverityFunc maps event types to CEF severity (0-10). If nil,
	// all events default to severity 5. Values are clamped to 0-10.
	SeverityFunc func(eventType string) int

	// DescriptionFunc maps event types to human-readable CEF
	// descriptions. If nil, the event type name is used.
	DescriptionFunc func(eventType string) string

	// FieldMapping maps audit field names to CEF extension keys. If nil,
	// [DefaultCEFFieldMapping] is used. If non-nil, entries are merged
	// with [DefaultCEFFieldMapping]: consumer entries override matching
	// defaults, and defaults not present in FieldMapping remain active.
	// To suppress all defaults, call [DefaultCEFFieldMapping], delete
	// unwanted entries, and pass the result. Unmapped fields use their
	// original audit field name as the extension key.
	FieldMapping    map[string]string
	resolvedMapping map[string]string

	// Vendor is the CEF header vendor field (e.g. "AxonOps"). If empty,
	// the vendor position in the header is blank but the pipe
	// delimiters are preserved. SHOULD be non-empty for
	// standard-compliant CEF output.
	Vendor string

	// Product is the CEF header product field (e.g. "SchemaRegistry").
	// If empty, the product position is blank. SHOULD be non-empty.
	Product string

	// Version is the CEF header product version field (e.g. "1.0").
	// If empty, the version position is blank. SHOULD be non-empty.
	Version string

	// noCopy prevents go vet from missing struct copies after first use.
	// CEFFormatter embeds sync.Once which must not be copied.
	noCopy      noCopy
	resolveOnce sync.Once

	// OmitEmpty controls whether zero-value fields are omitted from
	// extensions.
	OmitEmpty bool
}

// noCopy is a go vet guard that prevents copying of structs containing
// sync primitives. See https://pkg.go.dev/sync#Locker.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// Format serialises a single audit event as a CEF line using a single
// buffer for both header and extensions.
func (cf *CEFFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error) {
	severity := cf.severity(eventType)
	description := cf.description(eventType)
	mapping := cf.fieldMapping()

	var buf bytes.Buffer
	buf.Grow(256)

	// Write header: CEF:0|vendor|product|version|eventType|description|severity|
	buf.WriteString("CEF:0|")
	buf.WriteString(cefEscapeHeader(cf.Vendor))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(cf.Product))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(cf.Version))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(eventType))
	buf.WriteByte('|')
	buf.WriteString(cefEscapeHeader(description))
	buf.WriteByte('|')
	buf.WriteString(strconv.Itoa(severity))
	buf.WriteByte('|')

	// Write extensions directly into the same buffer.
	extStart := buf.Len()

	// Timestamp as receipt time (epoch ms).
	writeExtField(&buf, extStart, "rt", strconv.FormatInt(ts.UnixMilli(), 10))

	// Event type as device action.
	writeExtField(&buf, extStart, "act", eventType)

	// Build reserved key set from framework-emitted extension keys.
	reserved := map[string]struct{}{
		"rt":  {},
		"act": {},
	}

	// Duration if present as time.Duration.
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			writeExtField(&buf, extStart, "cn1", strconv.FormatInt(d.Milliseconds(), 10))
			writeExtField(&buf, extStart, "cn1Label", "durationMs")
			reserved["cn1"] = struct{}{}
			reserved["cn1Label"] = struct{}{}
		}
	}

	// All fields via mapping.
	if err := cf.writeFieldExtensions(&buf, extStart, fields, def, mapping, reserved); err != nil {
		return nil, err
	}

	buf.WriteByte('\n')
	// Safe: buf is local and not reused; Bytes() is the sole reference.
	return buf.Bytes(), nil
}

// writeFieldExtensions writes all user-defined fields as CEF
// extensions into buf, starting at extStart. Fields whose mapped
// extension key collides with a reserved framework key are silently
// skipped.
func (cf *CEFFormatter) writeFieldExtensions(buf *bytes.Buffer, extStart int, fields Fields, def *EventDef, mapping map[string]string, reserved map[string]struct{}) error {
	allKeys := allFieldKeysSorted(def, fields)
	for _, k := range allKeys {
		if isFrameworkField(k, fields) {
			continue
		}
		v := fields[k]
		if cf.OmitEmpty && isZeroValue(v) {
			continue
		}
		extKey := mapFieldKey(k, mapping)
		// Skip fields whose mapped key collides with a framework-
		// emitted extension key (rt, act, cn1, cn1Label). Collision
		// is a consumer mapping misconfiguration; it is silently
		// skipped to avoid per-event log flooding.
		if _, dup := reserved[extKey]; dup {
			continue
		}
		if err := validateExtKey(extKey); err != nil {
			return fmt.Errorf("audit: cef: field %q maps to invalid extension key %q: %w", k, extKey, err)
		}
		writeExtField(buf, extStart, extKey, formatFieldValue(v))
	}
	return nil
}

func (cf *CEFFormatter) severity(eventType string) int {
	s := 5
	if cf.SeverityFunc != nil {
		s = cf.SeverityFunc(eventType)
	}
	// Clamp to valid CEF range.
	if s < 0 {
		s = 0
	}
	if s > 10 {
		s = 10
	}
	return s
}

func (cf *CEFFormatter) description(eventType string) string {
	if cf.DescriptionFunc != nil {
		return cf.DescriptionFunc(eventType)
	}
	return eventType
}

// fieldMapping returns the resolved field mapping, merging consumer
// overrides with defaults. The result is computed once and cached.
func (cf *CEFFormatter) fieldMapping() map[string]string {
	cf.resolveOnce.Do(func() {
		defaults := defaultCEFFieldMappingEntries()
		if cf.FieldMapping == nil {
			cf.resolvedMapping = defaults
			return
		}
		merged := make(map[string]string, len(defaults)+len(cf.FieldMapping))
		for k, v := range defaults {
			merged[k] = v
		}
		for k, v := range cf.FieldMapping {
			merged[k] = v
		}
		cf.resolvedMapping = merged
	})
	return cf.resolvedMapping
}

// cefEscapeHeader escapes characters in CEF header fields.
// Header fields use pipe (|) as delimiter -- pipes and backslashes
// MUST be escaped. Backslash is escaped first to avoid double-escaping.
// Newlines and carriage returns are replaced with spaces.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// cefEscapeExtValue escapes characters in CEF extension values.
// Backslash is escaped first to avoid double-escaping. All C0 control
// characters (0x00-0x1F) are stripped after newline/CR escaping.
func cefEscapeExtValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	// Strip remaining C0 control characters (0x00-0x1F).
	s = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	return s
}

// validateExtKey returns an error if the key is not a valid CEF
// extension key name (must match [a-zA-Z0-9_]+).
func validateExtKey(key string) error {
	if key == "" {
		return fmt.Errorf("must match [a-zA-Z0-9_]+")
	}
	for _, c := range key {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("must match [a-zA-Z0-9_]+")
		}
	}
	return nil
}

// writeExtField writes a key=value pair to the buffer. extStart is the
// buffer position where extensions begin (after the header); a space
// separator is added before each field except the first extension.
func writeExtField(b *bytes.Buffer, extStart int, key, value string) {
	if b.Len() > extStart {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(cefEscapeExtValue(value))
}

// mapFieldKey maps an audit field name to a CEF extension key using
// the provided mapping. If no mapping exists, the field name is used.
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
		return strconv.FormatBool(val)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'g', -1, 64)
	case time.Duration:
		return strconv.FormatInt(val.Milliseconds(), 10)
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", val)
	}
}
