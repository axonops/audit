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

import "bytes"

// PostField represents a field appended to serialised bytes after
// format caching. This is an advanced/internal API used by the drain
// goroutine for delivery-specific context (event_category, HMAC).
// Custom formatter implementors may use [AppendPostFields]; regular
// consumers do not need this type.
type PostField struct {
	// JSONKey is the JSON object key used when appending to JSON output.
	JSONKey string
	// CEFKey is the extension key used when appending to CEF output.
	CEFKey string
	// Value is the string value to emit for this field. Values are
	// escaped automatically (JSON via [WriteJSONString], CEF via cefEscapeExtValue).
	Value string
}

// AppendPostField appends a single post-serialisation field to cached
// bytes. This is the zero-allocation fast path for the common case of
// appending one field (event_category, HMAC). For multiple fields, use
// [AppendPostFields].
func AppendPostField(data []byte, formatter Formatter, field PostField) []byte {
	if len(data) < 2 {
		return data
	}

	switch formatter.(type) {
	case *JSONFormatter:
		return appendPostFieldJSON(data, field)
	case *CEFFormatter:
		return appendPostFieldCEF(data, field)
	default:
		return data
	}
}

// AppendPostFields appends one or more post-serialisation fields to
// cached bytes. The formatter type determines the syntax:
// JSON: ,"key":"val" inserted before }\n
// CEF: key=val inserted before the newline.
func AppendPostFields(data []byte, formatter Formatter, fields []PostField) []byte {
	if len(fields) == 0 || len(data) < 2 {
		return data
	}

	switch formatter.(type) {
	case *JSONFormatter:
		return appendPostFieldsJSON(data, fields)
	case *CEFFormatter:
		return appendPostFieldsCEF(data, fields)
	default:
		return data // unknown formatter — skip silently
	}
}

func appendPostFieldJSON(data []byte, f PostField) []byte {
	braceIdx := len(data) - 2
	if braceIdx < 0 || data[braceIdx] != '}' {
		return data
	}
	buf, ok := jsonBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	buf.Write(data[:braceIdx])
	buf.WriteByte(',')
	WriteJSONString(buf, f.JSONKey)
	buf.WriteByte(':')
	WriteJSONString(buf, f.Value)
	buf.Write(data[braceIdx:])
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	jsonBufPool.Put(buf)
	return result
}

func appendPostFieldCEF(data []byte, f PostField) []byte {
	nlIdx := len(data) - 1
	if nlIdx < 0 || data[nlIdx] != '\n' {
		return data
	}
	result := make([]byte, 0, len(data)+2+len(f.CEFKey)+len(f.Value))
	result = append(result, data[:nlIdx]...)
	result = append(result, ' ')
	result = append(result, f.CEFKey...)
	result = append(result, '=')
	result = append(result, cefEscapeExtValue(f.Value)...)
	result = append(result, '\n')
	return result
}

func appendPostFieldsJSON(data []byte, fields []PostField) []byte {
	// JSON ends with }\n — insert before the closing brace.
	braceIdx := len(data) - 2 // data[len-1] is \n, data[len-2] is }
	if braceIdx < 0 || data[braceIdx] != '}' {
		return data // unexpected format — return unchanged
	}

	// Build the complete output in a pooled buffer using WriteJSONString
	// instead of json.Marshal to avoid per-field allocations.
	buf, ok := jsonBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	buf.Write(data[:braceIdx])
	for _, f := range fields {
		buf.WriteByte(',')
		WriteJSONString(buf, f.JSONKey)
		buf.WriteByte(':')
		WriteJSONString(buf, f.Value)
	}
	buf.Write(data[braceIdx:]) // }\n

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	jsonBufPool.Put(buf)
	return result
}

// appendPostFieldInto appends a single post-serialisation field by
// mutating buf in place. This is the zero-allocation drain-pipeline
// counterpart to [AppendPostField]. The buffer must already contain
// the base serialised bytes (e.g. via buf.Write(base)).
func appendPostFieldInto(buf *bytes.Buffer, formatter Formatter, f PostField) []byte {
	switch formatter.(type) {
	case *JSONFormatter:
		return appendPostFieldJSONInto(buf, f)
	case *CEFFormatter:
		return appendPostFieldCEFInto(buf, f)
	default:
		return buf.Bytes()
	}
}

// appendPostFieldJSONInto rewinds the trailing }\n, appends
// ,"key":"value", and restores the }\n. Returns buf.Bytes().
func appendPostFieldJSONInto(buf *bytes.Buffer, f PostField) []byte {
	b := buf.Bytes()
	if len(b) < 2 || b[len(b)-1] != '\n' || b[len(b)-2] != '}' {
		return b
	}
	buf.Truncate(buf.Len() - 2)
	buf.WriteByte(',')
	WriteJSONString(buf, f.JSONKey)
	buf.WriteByte(':')
	WriteJSONString(buf, f.Value)
	buf.WriteByte('}')
	buf.WriteByte('\n')
	return buf.Bytes()
}

// appendPostFieldCEFInto rewinds the trailing \n, appends
// " key=value", and restores the \n. Returns buf.Bytes().
func appendPostFieldCEFInto(buf *bytes.Buffer, f PostField) []byte {
	b := buf.Bytes()
	if len(b) < 1 || b[len(b)-1] != '\n' {
		return b
	}
	buf.Truncate(buf.Len() - 1)
	buf.WriteByte(' ')
	buf.WriteString(f.CEFKey)
	buf.WriteByte('=')
	buf.WriteString(cefEscapeExtValue(f.Value))
	buf.WriteByte('\n')
	return buf.Bytes()
}

// appendPostFieldsInto is the batch in-place counterpart to
// [appendPostFieldInto]. It rewinds the buffer terminator once,
// appends every field in fields, and restores the terminator once —
// saving one rewind / restore cycle per additional field over
// N sequential [appendPostFieldInto] calls. Used by the drain
// pipeline to emit the pre-HMAC batch (event_category + _hmac_v)
// in a single buffer mutation; see [Auditor.assemblePostFields]
// in drain.go.
//
// Contract mirrors [appendPostFieldInto]:
//
//   - Returns buf.Bytes() unchanged if fields is empty or the buffer
//     lacks the expected terminator (}\n for JSON, \n for CEF). The
//     format cache always produces well-terminated input, so the
//     guard is defensive against future invariant violations.
//   - All-or-none: if the terminator guard fails the function returns
//     without appending any field. It never leaves the buffer in a
//     partially-appended state.
//   - Silent on unknown formatter (matches the single-field variant).
//
// The returned slice aliases buf.Bytes() and is valid until the next
// mutation of buf.
func appendPostFieldsInto(buf *bytes.Buffer, formatter Formatter, fields []PostField) []byte {
	if len(fields) == 0 {
		return buf.Bytes()
	}
	switch formatter.(type) {
	case *JSONFormatter:
		return appendPostFieldsJSONInto(buf, fields)
	case *CEFFormatter:
		return appendPostFieldsCEFInto(buf, fields)
	default:
		return buf.Bytes()
	}
}

// appendPostFieldsJSONInto rewinds the trailing }\n, appends
// ,"k1":"v1",...,"kN":"vN", and restores the }\n. Returns
// buf.Bytes(). See [appendPostFieldsInto] for the contract.
func appendPostFieldsJSONInto(buf *bytes.Buffer, fields []PostField) []byte {
	b := buf.Bytes()
	if len(b) < 2 || b[len(b)-1] != '\n' || b[len(b)-2] != '}' {
		return b
	}
	buf.Truncate(buf.Len() - 2)
	for i := range fields {
		buf.WriteByte(',')
		WriteJSONString(buf, fields[i].JSONKey)
		buf.WriteByte(':')
		WriteJSONString(buf, fields[i].Value)
	}
	buf.WriteByte('}')
	buf.WriteByte('\n')
	return buf.Bytes()
}

// appendPostFieldsCEFInto rewinds the trailing \n, appends
// " k1=v1 k2=v2 ... kN=vN", and restores the \n. Returns
// buf.Bytes(). See [appendPostFieldsInto] for the contract.
func appendPostFieldsCEFInto(buf *bytes.Buffer, fields []PostField) []byte {
	b := buf.Bytes()
	if len(b) < 1 || b[len(b)-1] != '\n' {
		return b
	}
	buf.Truncate(buf.Len() - 1)
	for i := range fields {
		buf.WriteByte(' ')
		buf.WriteString(fields[i].CEFKey)
		buf.WriteByte('=')
		buf.WriteString(cefEscapeExtValue(fields[i].Value))
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

func appendPostFieldsCEF(data []byte, fields []PostField) []byte {
	// CEF ends with \n — insert before the newline.
	nlIdx := len(data) - 1
	if nlIdx < 0 || data[nlIdx] != '\n' {
		return data // unexpected format — return unchanged
	}

	// Build suffix with proper CEF escaping for values.
	// Use the shared CEF buffer pool (same pool as CEFFormatter.Format).
	buf, ok := cefBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	for _, f := range fields {
		buf.WriteByte(' ')
		buf.WriteString(f.CEFKey)
		buf.WriteByte('=')
		buf.WriteString(cefEscapeExtValue(f.Value))
	}

	result := make([]byte, 0, len(data)+buf.Len())
	result = append(result, data[:nlIdx]...)
	result = append(result, buf.Bytes()...)
	result = append(result, '\n')
	cefBufPool.Put(buf)
	return result
}
