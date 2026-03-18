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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultCEFFieldMapping is the built-in mapping from audit field names
// to CEF extension keys. Do not mutate -- treat as read-only.
var defaultCEFFieldMapping = map[string]string{
	"actor_id":   "suser",
	"source_ip":  "src",
	"request_id": "externalId",
	"user_agent": "requestClientApplication",
	"method":     "requestMethod",
	"path":       "request",
	"outcome":    "outcome",
}

// DefaultCEFFieldMapping returns a copy of the built-in field mapping
// from audit field names to standard CEF extension keys. Consumers can
// use this as a base, add or override entries, and pass the result to
// [CEFFormatter.FieldMapping].
func DefaultCEFFieldMapping() map[string]string {
	cp := make(map[string]string, len(defaultCEFFieldMapping))
	for k, v := range defaultCEFFieldMapping {
		cp[k] = v
	}
	return cp
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
	// Vendor is the CEF header vendor field (e.g. "AxonOps").
	Vendor string

	// Product is the CEF header product field (e.g. "SchemaRegistry").
	Product string

	// Version is the CEF header product version field (e.g. "1.0").
	Version string

	// SeverityFunc maps event types to CEF severity (0-10). If nil,
	// all events default to severity 5. Values are clamped to 0-10.
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

	resolveOnce     sync.Once
	resolvedMapping map[string]string
}

// Format serialises a single audit event as a CEF line.
func (cf *CEFFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error) {
	severity := cf.severity(eventType)
	description := cf.description(eventType)
	mapping := cf.fieldMapping()

	var ext strings.Builder

	// Timestamp as receipt time (epoch ms).
	writeExtField(&ext, "rt", strconv.FormatInt(ts.UnixMilli(), 10))

	// Event type as device action (writeExtField handles escaping).
	writeExtField(&ext, "act", eventType)

	// Duration if present as time.Duration.
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			writeExtField(&ext, "cn1", strconv.FormatInt(d.Milliseconds(), 10))
			writeExtField(&ext, "cn1Label", "durationMs")
		}
	}

	// All fields via mapping.
	allKeys := allFieldKeysSorted(def, fields)
	for _, k := range allKeys {
		if k == "timestamp" || k == "event_type" {
			continue
		}
		// Skip duration_ms only if it's a time.Duration (handled above).
		if k == "duration_ms" {
			if _, isDuration := fields[k].(time.Duration); isDuration {
				continue
			}
		}
		v := fields[k]
		if cf.OmitEmpty && isZeroValue(v) {
			continue
		}
		extKey := mapFieldKey(k, mapping)
		if err := validateExtKey(extKey); err != nil {
			return nil, fmt.Errorf("audit: cef: field %q maps to invalid extension key %q: %w", k, extKey, err)
		}
		writeExtField(&ext, extKey, formatFieldValue(v))
	}

	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s\n",
		cefEscapeHeader(cf.Vendor),
		cefEscapeHeader(cf.Product),
		cefEscapeHeader(cf.Version),
		cefEscapeHeader(eventType),
		cefEscapeHeader(description),
		severity,
		ext.String(),
	)
	return []byte(header), nil
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
		if cf.FieldMapping == nil {
			cf.resolvedMapping = defaultCEFFieldMapping
			return
		}
		merged := make(map[string]string, len(defaultCEFFieldMapping)+len(cf.FieldMapping))
		for k, v := range defaultCEFFieldMapping {
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
	if len(key) == 0 {
		return fmt.Errorf("must match [a-zA-Z0-9_]+")
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return fmt.Errorf("must match [a-zA-Z0-9_]+")
		}
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
