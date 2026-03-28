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
)

// jsonBufPool caches bytes.Buffer instances for JSONFormatter.Format
// to avoid per-call heap allocation of the output buffer. Buffers are
// Reset before return to the pool. The pooled buffer's internal byte
// slice grows to the typical output size and is reused across calls,
// eliminating repeated growth allocations.
var jsonBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// JSONFormatter serialises audit events as line-delimited JSON.
//
// Fields are emitted in deterministic order: framework fields first
// (timestamp, event_type, duration_ms if present as [time.Duration]),
// then required fields (sorted), then optional fields (sorted), then
// any extra fields (sorted). Each event is terminated by a newline.
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
func (jf *JSONFormatter) Format(ts time.Time, eventType string, fields Fields, def *EventDef) ([]byte, error) {
	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteByte('{')

	enc := &jsonEncoder{buf: buf, omitEmpty: jf.OmitEmpty}

	// Framework fields first.
	enc.writeTimestamp(ts, jf.tsFormat())
	enc.writeStringField("event_type", eventType)
	jf.writeDuration(enc, fields)

	// Required fields (sorted). Uses pre-sorted slice when available.
	for _, k := range sortedFieldKeys(def.sortedRequired, def.Required, fields, jf.OmitEmpty) {
		enc.writeField(k, fields[k])
	}

	// Optional fields (sorted). Uses pre-sorted slice when available.
	for _, k := range sortedFieldKeys(def.sortedOptional, def.Optional, fields, jf.OmitEmpty) {
		enc.writeField(k, fields[k])
	}

	// Extra fields not in required or optional (sorted).
	for _, k := range extraFieldKeys(def, fields, jf.OmitEmpty) {
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
		data, err := json.Marshal(ts.Format(time.RFC3339Nano))
		if err != nil && e.err == nil {
			e.err = err
		}
		e.buf.Write(data)
	}
}

func (e *jsonEncoder) writeStringField(key, value string) {
	e.writeComma()
	e.writeKey(key)
	data, err := json.Marshal(value)
	if err != nil && e.err == nil {
		e.err = err
	}
	e.buf.Write(data)
}

func (e *jsonEncoder) writeInt64Field(key string, value int64) {
	e.writeComma()
	e.writeKey(key)
	e.buf.WriteString(strconv.FormatInt(value, 10))
}

func (e *jsonEncoder) writeKey(key string) {
	data, err := json.Marshal(key)
	if err != nil && e.err == nil {
		e.err = err
	}
	e.buf.Write(data)
	e.buf.WriteByte(':')
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
	e.writeKey(key)
	data, err := json.Marshal(value)
	if err != nil && e.err == nil {
		e.err = err
	}
	e.buf.Write(data)
}
