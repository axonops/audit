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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cefBufPool caches bytes.Buffer instances for CEFFormatter.Format.
// The New function pre-grows to 256 bytes as a starting hint; the
// buffer grows on first use and retains capacity, so after warm-up
// the pool holds buffers large enough for the typical ~400-byte output.
//
// Outlier buffers (cap > maxPooledBufCap) are dropped on Put rather
// than re-pooled. On Put the backing array is zeroed across [0:cap]
// to defend against future read-past-len bugs.
var cefBufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(256)
		return b
	},
}

// putCEFBuf returns buf to [cefBufPool] with defensive zeroing and
// outlier rejection.
func putCEFBuf(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledBufCap {
		return
	}
	buf.Reset()
	b := buf.Bytes()
	clear(b[:cap(b)])
	cefBufPool.Put(buf)
}

// defaultCEFFieldMappingEntries returns a new map containing the
// built-in audit-field-to-CEF-extension-key mapping. Each call returns
// a distinct map instance; callers may mutate the result without
// affecting other callers. No package-level mutable state is held.
func defaultCEFFieldMappingEntries() map[string]string {
	return map[string]string{
		// Identity and access
		"actor_id":    "suser",
		"actor_uid":   "suid",
		"role":        "spriv",
		"target_id":   "duser",
		"target_uid":  "duid",
		"target_role": "dpriv",

		// Event context
		"outcome": "outcome",
		"reason":  "reason",
		"message": "msg",

		// Network
		"source_ip":   "src",
		"source_host": "shost",
		"source_port": "spt",
		"dest_ip":     "dst",
		"dest_host":   "dhost",
		"dest_port":   "dpt",
		"protocol":    "app",
		"transport":   "proto",

		// HTTP / request
		"request_id": "externalId",
		"user_agent": "requestClientApplication",
		"referrer":   "requestContext",
		"method":     "requestMethod",
		"path":       "request",

		// Temporal
		"start_time": "start",
		"end_time":   "end",

		// File
		"file_name": "fname",
		"file_path": "filePath",
		"file_hash": "fileHash",
		"file_size": "fsize",
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
// Severity is determined by [CEFFormatter.SeverityFunc] if set. If nil,
// the taxonomy-defined severity is used via [EventDef.ResolvedSeverity]:
// event Severity (if non-nil) → first category Severity in alphabetical
// order (if non-nil) → 5. Values are clamped to the valid CEF range 0-10.
type CEFFormatter struct {
	// SeverityFunc maps event types to CEF severity (0-10). If nil,
	// taxonomy-defined severity is used via [EventDef.ResolvedSeverity].
	// Values are clamped to 0-10. Set SeverityFunc only to override
	// the taxonomy.
	SeverityFunc func(eventType string) int

	// DescriptionFunc maps event types to human-readable CEF
	// descriptions. If nil, [EventDef.Description] is used when
	// non-empty, falling back to the event type name.
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

	// resolveErr captures any error produced by [fieldMapping]'s
	// construction-time validation (e.g. an unsafe CEF extension key
	// in consumer-supplied FieldMapping). Surfaced from every call to
	// Format so the problem fails fast rather than silently emitting
	// corrupt CEF lines. See #477.
	resolveErr error

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

	// Framework fields set once via SetFrameworkFields.
	appName  string
	host     string
	timezone string
	pidStr   string // pre-formatted PID; empty when pid == 0
	pid      int

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

// maxCEFHeaderField is the maximum length for Vendor, Product, and
// Version header fields. Prevents unbounded header growth.
const maxCEFHeaderField = 255

// cefSeverityStrings avoids per-event strconv.Itoa for severity (0-10).
var cefSeverityStrings = [11]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}

// Format serialises a single audit event as a CEF line. The returned
// slice is owned by the caller (defensive copy from the pooled buffer).
//
// Internal callers in the drain pipeline use [CEFFormatter.formatBuf]
// to obtain the leased buffer directly and skip the copy.
func (cf *CEFFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) {
	buf, err := cf.formatBuf(ts, eventType, fields, def, opts)
	if err != nil {
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	cf.releaseFormatBuf(buf)
	return out, nil
}

// releaseFormatBuf returns buf to [cefBufPool], applying the same
// outlier-rejection and zeroing rules as [putCEFBuf].
func (*CEFFormatter) releaseFormatBuf(buf *bytes.Buffer) { putCEFBuf(buf) }

// formatBuf serialises an event into a pool-leased *bytes.Buffer.
// See [JSONFormatter.formatBuf] for the contract.
func (cf *CEFFormatter) formatBuf(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) (*bytes.Buffer, error) {
	if len(cf.Vendor) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef vendor exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Vendor))
	}
	if len(cf.Product) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef product exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Product))
	}
	if len(cf.Version) > maxCEFHeaderField {
		return nil, fmt.Errorf("audit: cef version exceeds %d bytes (%d)", maxCEFHeaderField, len(cf.Version))
	}
	severity := cf.severity(eventType, def)
	description := cf.description(eventType, def)
	mapping := cf.fieldMapping()
	// Construction-time validation failure (e.g. unsafe extension
	// key in FieldMapping) is surfaced here so every Format call
	// fails fast rather than emitting corrupt CEF that downstream
	// SIEMs mis-parse as spoofed events (#477).
	if cf.resolveErr != nil {
		return nil, cf.resolveErr
	}

	buf, ok := cefBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()

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
	buf.WriteString(cefSeverityStrings[severity])
	buf.WriteByte('|')

	// Write extensions directly into the same buffer.
	extStart := buf.Len()

	// Timestamp as receipt time (epoch ms) — write directly to buffer
	// to avoid strconv.FormatInt string allocation.
	if extStart < buf.Len() {
		buf.WriteByte(' ')
	}
	buf.WriteString("rt=")
	buf.Write(strconv.AppendInt(buf.AvailableBuffer(), ts.UnixMilli(), 10))

	// Event type as device action.
	writeExtField(buf, extStart, "act", eventType)

	// Build reserved key set from framework-emitted extension keys.
	reserved := map[string]struct{}{
		"rt":  {},
		"act": {},
	}

	// Duration if present as time.Duration.
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			writeExtField(buf, extStart, "cn1", strconv.FormatInt(d.Milliseconds(), 10))
			writeExtField(buf, extStart, "cn1Label", "durationMs")
			reserved["cn1"] = struct{}{}
			reserved["cn1Label"] = struct{}{}
		}
	}

	// Framework fields (app_name, host, timezone, pid).
	cf.writeFrameworkExtensions(buf, extStart, reserved)

	// All fields via mapping.
	if err := cf.writeFieldExtensions(buf, extStart, fields, def, mapping, reserved, opts); err != nil {
		putCEFBuf(buf)
		return nil, err
	}

	buf.WriteByte('\n')
	return buf, nil
}

// writeFieldExtensions writes all user-defined fields as CEF
// extensions into buf, starting at extStart. Fields whose mapped
// extension key collides with a reserved framework key are silently
// skipped.
func (cf *CEFFormatter) writeFieldExtensions(buf *bytes.Buffer, extStart int, fields Fields, def *EventDef, mapping map[string]string, reserved map[string]struct{}, opts *FormatOptions) error {
	// Per-event extension-key validation was removed as part of #477.
	// The taxonomy validator (ValidateTaxonomy) already rejects any
	// event-type key or field name that does not match the safe
	// identifier pattern at load time, so consumer-controlled names
	// reaching this point are known-safe. Custom FieldMapping entries
	// are consumer code and are trusted.
	allKeys, owned := allFieldKeysSorted(def, fields)
	for _, k := range allKeys {
		if isFrameworkField(k, fields) {
			continue
		}
		if opts.IsExcluded(k) {
			continue
		}
		v := fields[k]
		if cf.OmitEmpty && isZeroValue(v) {
			continue
		}
		extKey := mapFieldKey(k, mapping)
		// Skip fields whose mapped key collides with a framework-
		// emitted extension key. Collision is a consumer mapping
		// misconfiguration; it is silently skipped to avoid
		// per-event log flooding.
		if _, dup := reserved[extKey]; dup {
			continue
		}
		writeExtField(buf, extStart, extKey, formatFieldValue(v))
	}
	putSortedKeysSlice(owned)
	return nil
}

func (cf *CEFFormatter) severity(eventType string, def *EventDef) int {
	// SeverityFunc takes precedence (backwards compatibility).
	if cf.SeverityFunc != nil {
		return clampSeverity(cf.SeverityFunc(eventType))
	}
	// Use taxonomy-defined severity.
	return def.ResolvedSeverity()
}

func (cf *CEFFormatter) description(eventType string, def *EventDef) string {
	// DescriptionFunc takes precedence (backwards compatibility).
	if cf.DescriptionFunc != nil {
		return cf.DescriptionFunc(eventType)
	}
	// Use taxonomy-defined description.
	if def.Description != "" {
		return def.Description
	}
	return eventType
}

// fieldMapping returns the resolved field mapping, merging consumer
// overrides with defaults. The result is computed once and cached.
//
// Every resolved extension key is validated once here (O(1) startup
// cost) against the CEF key character class `[a-zA-Z0-9_]+`. Keys
// containing space, `=`, `|`, newline, or other characters would be
// written verbatim into the CEF extension section by [writeExtField]
// and could be mis-parsed by downstream SIEMs as spoofed extension
// pairs, a new event delimiter, or a truncated event. Catching the
// misconfiguration at construction time keeps the per-event hot path
// validation-free while preventing the log-injection class (#477).
//
// The first validation failure is captured in [cf.resolveErr] and
// surfaced from every [Format] call.
func (cf *CEFFormatter) fieldMapping() map[string]string {
	cf.resolveOnce.Do(func() {
		defaults := defaultCEFFieldMappingEntries()
		var merged map[string]string
		if cf.FieldMapping == nil {
			merged = defaults
		} else {
			merged = make(map[string]string, len(defaults)+len(cf.FieldMapping))
			for k, v := range defaults {
				merged[k] = v
			}
			for k, v := range cf.FieldMapping {
				merged[k] = v
			}
		}
		// Validate every resolved extension key. Sort the audit keys
		// so the first error reported is deterministic.
		auditKeys := make([]string, 0, len(merged))
		for k := range merged {
			auditKeys = append(auditKeys, k)
		}
		slices.Sort(auditKeys)
		for _, auditKey := range auditKeys {
			extKey := merged[auditKey]
			if err := validateExtKey(extKey); err != nil {
				cf.resolveErr = fmt.Errorf(
					"audit: cef: field %q maps to invalid extension key %q: %w",
					auditKey, extKey, err)
				return
			}
		}
		cf.resolvedMapping = merged
	})
	return cf.resolvedMapping
}

// SetFrameworkFields stores auditor-wide framework metadata for
// emission in every CEF event. Called once at construction time.
func (cf *CEFFormatter) SetFrameworkFields(appName, host, timezone string, pid int) {
	cf.appName = appName
	cf.host = host
	cf.timezone = timezone
	cf.pid = pid
	if pid > 0 {
		cf.pidStr = strconv.Itoa(pid)
	}
}

// writeFrameworkExtensions writes app_name, host, timezone, and pid as
// standard CEF extension keys.
func (cf *CEFFormatter) writeFrameworkExtensions(buf *bytes.Buffer, extStart int, reserved map[string]struct{}) {
	if cf.appName != "" {
		writeExtField(buf, extStart, "deviceProcessName", cf.appName)
		reserved["deviceProcessName"] = struct{}{}
	}
	if cf.host != "" {
		writeExtField(buf, extStart, "dvchost", cf.host)
		reserved["dvchost"] = struct{}{}
	}
	if cf.timezone != "" {
		writeExtField(buf, extStart, "dtz", cf.timezone)
		reserved["dtz"] = struct{}{}
	}
	if cf.pidStr != "" {
		writeExtField(buf, extStart, "dvcpid", cf.pidStr)
		reserved["dvcpid"] = struct{}{}
	}
}

// cefEscapeHeader escapes characters in CEF header fields using a
// single-pass byte scanner. Escapes: \ -> \\, | -> \|, \n -> space,
// \r -> space. Returns the original string unchanged when no escaping
// is needed, avoiding allocation on the common path.
func cefEscapeHeader(s string) string {
	var buf strings.Builder
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			buf.WriteString(s[start:i])
			buf.WriteString(`\\`)
			start = i + 1
		case '|':
			buf.WriteString(s[start:i])
			buf.WriteString(`\|`)
			start = i + 1
		case '\n', '\r':
			buf.WriteString(s[start:i])
			buf.WriteByte(' ')
			start = i + 1
		}
	}
	if start == 0 {
		return s // no escaping needed; return original string (0 allocs)
	}
	buf.WriteString(s[start:])
	return buf.String()
}

// cefEscapeExtValue escapes characters in CEF extension values using a
// single-pass byte scanner. Escapes: \ -> \\, = -> \=, \n -> \n
// (literal backslash-n), \r -> \r (literal backslash-r). Remaining C0
// control characters (0x00-0x1F) are stripped.
func cefEscapeExtValue(s string) string {
	var buf strings.Builder
	start := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x20 {
			switch b {
			case '\\':
				buf.WriteString(s[start:i])
				buf.WriteString(`\\`)
				start = i + 1
			case '=':
				buf.WriteString(s[start:i])
				buf.WriteString(`\=`)
				start = i + 1
			}
			continue
		}
		// C0 control character.
		buf.WriteString(s[start:i])
		switch b {
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			// Strip other control characters.
		}
		start = i + 1
	}
	if start == 0 {
		return s // no escaping needed; return original string (0 allocs)
	}
	buf.WriteString(s[start:])
	return buf.String()
}

// validateExtKey returns an error if the key is not a valid CEF
// extension key name (must match `[a-zA-Z0-9_]+`). Called once per
// CEFFormatter from [fieldMapping]'s resolveOnce — never on the
// per-event hot path (#477).
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
func formatFieldValue(v any) string { //nolint:gocyclo,cyclop // type switch; complexity is inherent
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
	case float32:
		return strconv.FormatFloat(float64(val), 'g', -1, 32)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case time.Duration:
		return strconv.FormatInt(val.Milliseconds(), 10)
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", val)
	}
}
