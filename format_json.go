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
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// jsonBufPool caches bytes.Buffer instances for JSONFormatter.Format
// to avoid per-call heap allocation of the output buffer. Buffers are
// Reset on retrieval from the pool (before each Format call) to ensure
// a clean slate. The pooled buffer's internal byte slice grows to the
// typical output size and is reused across calls, eliminating repeated
// growth allocations.
var jsonBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// JSONFormatter serialises audit events as line-delimited JSON.
//
// Fields are emitted in deterministic order: framework fields first
// (timestamp, event_type, severity, duration_ms if present as
// [time.Duration]), then required fields (sorted), then optional fields
// (sorted), then any extra fields (sorted). Each event is terminated
// by a newline.
//
// [time.Duration] values are converted to int64 milliseconds.
// Timestamps are rendered according to [JSONFormatter.Timestamp]
// (default [TimestampRFC3339Nano]).
type JSONFormatter struct {
	// Timestamp controls the timestamp format. Empty defaults to
	// [TimestampRFC3339Nano].
	Timestamp TimestampFormat

	// OmitEmpty controls whether zero-value fields are omitted.
	OmitEmpty bool
}

// Format serialises a single audit event as a JSON line.
func (jf *JSONFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef, opts *FormatOptions) ([]byte, error) {
	buf, ok := jsonBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	buf.WriteByte('{')

	enc := &jsonEncoder{buf: buf, omitEmpty: jf.OmitEmpty}

	// Framework fields first.
	enc.writeTimestamp(ts, jf.tsFormat())
	enc.writeStringField("event_type", eventType)
	enc.writeInt64Field("severity", int64(def.ResolvedSeverity()))
	jf.writeDuration(enc, fields)

	// Required fields (sorted). Uses pre-sorted slice when available.
	for _, k := range sortedFieldKeys(def.sortedRequired, def.Required, fields, jf.OmitEmpty) {
		if opts.isExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}

	// Optional fields (sorted). Uses pre-sorted slice when available.
	for _, k := range sortedFieldKeys(def.sortedOptional, def.Optional, fields, jf.OmitEmpty) {
		if opts.isExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}

	// Extra fields not in required or optional (sorted).
	for _, k := range extraFieldKeys(def, fields, jf.OmitEmpty) {
		if opts.isExcluded(k) {
			continue
		}
		enc.writeField(k, fields[k])
	}

	buf.WriteByte('}')
	buf.WriteByte('\n')

	if enc.err != nil {
		jsonBufPool.Put(buf)
		return nil, fmt.Errorf("audit: json format: %w", enc.err)
	}

	// Copy before returning the buffer to the pool. formatCached in
	// audit.go stores Format() results in a cache spanning multiple
	// output Write() calls — returning a slice backed by the pooled
	// buffer would cause corruption when the buffer is reused.
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	jsonBufPool.Put(buf)
	return out, nil
}

func (jf *JSONFormatter) tsFormat() TimestampFormat {
	if jf.Timestamp == "" {
		return TimestampRFC3339Nano
	}
	return jf.Timestamp
}

// writeDuration writes duration_ms as an int64 if the value is a
// [time.Duration]. Non-Duration values for duration_ms are handled as
// regular fields through the normal field path.
func (jf *JSONFormatter) writeDuration(enc *jsonEncoder, fields Fields) {
	if v, ok := fields["duration_ms"]; ok {
		if d, ok := v.(time.Duration); ok {
			enc.writeInt64Field("duration_ms", d.Milliseconds())
		}
	}
}

// jsonEncoder writes JSON key-value pairs to a buffer with comma
// separation. It tracks the first error encountered.
type jsonEncoder struct {
	buf       *bytes.Buffer
	err       error
	omitEmpty bool
	hasFields bool // true after the first field is written
}

func (e *jsonEncoder) writeComma() {
	if e.hasFields {
		e.buf.WriteByte(',')
	}
	e.hasFields = true
}

func (e *jsonEncoder) writeTimestamp(ts time.Time, format TimestampFormat) {
	e.writeComma()
	e.buf.WriteString(`"timestamp":`)
	//nolint:exhaustive // unrecognised TimestampFormat values fall back to RFC3339Nano
	switch format {
	case TimestampUnixMillis:
		e.buf.WriteString(strconv.FormatInt(ts.UnixMilli(), 10))
	default:
		// RFC3339Nano timestamps contain only ASCII characters safe in
		// JSON (digits, colons, dashes, T, Z, dot, plus). Write between
		// quotes without escaping, using AvailableBuffer to avoid a
		// string allocation from ts.Format().
		e.buf.WriteByte('"')
		b := ts.AppendFormat(e.buf.AvailableBuffer(), time.RFC3339Nano)
		_, _ = e.buf.Write(b)
		e.buf.WriteByte('"')
	}
}

func (e *jsonEncoder) writeStringField(key, value string) {
	e.writeComma()
	e.writeKey(key)
	writeJSONString(e.buf, value)
}

func (e *jsonEncoder) writeInt64Field(key string, value int64) {
	e.writeComma()
	e.writeKey(key)
	b := strconv.AppendInt(e.buf.AvailableBuffer(), value, 10)
	_, _ = e.buf.Write(b)
}

func (e *jsonEncoder) writeKey(key string) {
	writeJSONString(e.buf, key)
	e.buf.WriteByte(':')
}

//nolint:cyclop,gocyclo // flat type switch over common field types; linear, not true complexity
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
	e.writeKey(key)
	switch v := value.(type) {
	case string:
		writeJSONString(e.buf, v)
	case int:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), int64(v), 10)
		_, _ = e.buf.Write(b)
	case int64:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), v, 10)
		_, _ = e.buf.Write(b)
	case int32:
		b := strconv.AppendInt(e.buf.AvailableBuffer(), int64(v), 10)
		_, _ = e.buf.Write(b)
	case float64:
		// Fallback to json.Marshal for exact format matching.
		data, err := json.Marshal(v)
		if err != nil && e.err == nil {
			e.err = err
		}
		e.buf.Write(data)
	case bool:
		e.buf.WriteString(strconv.FormatBool(v))
	case nil:
		e.buf.WriteString("null")
	default:
		// Fallback: json.Marshal for unknown types.
		data, err := json.Marshal(v)
		if err != nil && e.err == nil {
			e.err = err
		}
		e.buf.Write(data)
	}
}

// writeJSONString writes the JSON-encoded form of s directly to buf,
// producing byte-for-byte identical output to [encoding/json.Marshal]
// for string values. This includes HTML-safe escaping of <, >, and &,
// and JavaScript-safe escaping of U+2028/U+2029 line/paragraph
// separators. Invalid UTF-8 is replaced with \ufffd.
//
// Writing directly to the buffer eliminates the per-call allocation
// that json.Marshal incurs for its return value.
//
//nolint:gocyclo,cyclop // single-pass byte scanner; complexity is inherent in JSON escaping rules
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b >= utf8.RuneSelf {
			var size int
			start, size = writeJSONMultibyte(buf, s, i, start)
			i += size
			continue
		}
		if jsonSafeASCII[b] {
			i++
			continue
		}
		buf.WriteString(s[start:i])
		switch b {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			// Remaining control chars (0x00-0x1F) and HTML-special (<, >, &).
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[b>>4])
			buf.WriteByte(hexDigits[b&0xf])
		}
		i++
		start = i
	}
	buf.WriteString(s[start:])
	buf.WriteByte('"')
}

// writeJSONMultibyte handles multi-byte UTF-8 sequences in
// writeJSONString. Returns the updated start position and the rune
// size in bytes (avoiding a redundant DecodeRuneInString in the caller).
func writeJSONMultibyte(buf *bytes.Buffer, s string, i, start int) (newStart, size int) {
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		buf.WriteString(s[start:i])
		buf.WriteString(`\ufffd`)
		return i + size, size
	case r == '\u2028':
		buf.WriteString(s[start:i])
		buf.WriteString(`\u2028`)
		return i + size, size
	case r == '\u2029':
		buf.WriteString(s[start:i])
		buf.WriteString(`\u2029`)
		return i + size, size
	default:
		return start, size // no escape needed; continue accumulating
	}
}

const hexDigits = "0123456789abcdef"

// jsonSafeASCII marks ASCII bytes safe to pass through writeJSONString
// without escaping. Bytes with false entries need escaping.
var jsonSafeASCII = func() [256]bool {
	var t [256]bool
	for i := 0x20; i < utf8.RuneSelf; i++ {
		t[i] = true
	}
	t['"'] = false
	t['\\'] = false
	t['<'] = false // HTML-safe escaping (matches json.Marshal)
	t['>'] = false
	t['&'] = false
	return t
}()
