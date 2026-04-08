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

package loki

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"sort"
	"strconv"

	audit "github.com/axonops/go-audit"
)

// lokiStream holds events grouped by a common set of stream labels.
type lokiStream struct {
	labels  map[string]string
	entries []lokiStreamEntry
}

// lokiStreamEntry is a single event within a Loki stream.
type lokiStreamEntry struct { //nolint:govet // fieldalignment: readability preferred
	tsNano int64  // nanosecond Unix timestamp
	line   []byte // pre-serialised event JSON
}

// groupByStream partitions a batch of events into Loki streams based on
// their label values (static + dynamic + framework). The streams map is
// stored on Output and reused across flushes (single goroutine).
func (o *Output) groupByStream(batch []lokiEntry) {
	clear(o.streams)

	fw := o.fw.Load()

	for i := range batch {
		entry := &batch[i]
		key := o.streamKey(entry.metadata, fw)
		s, ok := o.streams[key]
		if !ok {
			s = &lokiStream{
				labels:  o.streamLabels(entry.metadata, fw),
				entries: make([]lokiStreamEntry, 0, 8),
			}
			o.streams[key] = s
		}

		tsNano := entry.metadata.Timestamp.UnixNano()
		// Ensure monotonically increasing timestamps within a stream.
		// Loki may reject out-of-order entries in the same stream.
		if n := len(s.entries); n > 0 && tsNano <= s.entries[n-1].tsNano {
			tsNano = s.entries[n-1].tsNano + 1
		}

		s.entries = append(s.entries, lokiStreamEntry{
			tsNano: tsNano,
			line:   entry.data,
		})
	}
}

// dynamicField describes a single dynamic label extracted from event
// metadata and framework fields. Used by streamKey and streamLabels
// to avoid repetitive conditional logic.
type dynamicField struct { //nolint:govet // fieldalignment: readability preferred
	key     string // short key for fingerprint (e.g. "et")
	label   string // Loki label name (e.g. "event_type")
	exclude bool   // from DynamicLabels config
	value   string // resolved value for this event
}

// resolveDynamicFields builds the list of active dynamic label values
// for a single event.
func (o *Output) resolveDynamicFields(meta audit.EventMetadata, fw *frameworkFields) []dynamicField {
	dl := &o.cfg.Labels.Dynamic
	fields := o.dynFields[:0] // reuse backing array

	if fw != nil {
		fields = append(fields,
			dynamicField{"an", "app_name", dl.ExcludeAppName, fw.appName},
			dynamicField{"h", "host", dl.ExcludeHost, fw.host},
			dynamicField{"tz", "timezone", dl.ExcludeTimezone, fw.timezone},
			dynamicField{"p", "pid", dl.ExcludePID, strconv.Itoa(fw.pid)},
		)
		// pid=0 means unset.
		if fw.pid == 0 {
			fields[len(fields)-1].value = ""
		}
	}

	fields = append(fields,
		dynamicField{"et", "event_type", dl.ExcludeEventType, meta.EventType},
		dynamicField{"ec", "event_category", dl.ExcludeEventCategory, meta.Category},
		dynamicField{"s", "severity", dl.ExcludeSeverity, strconv.Itoa(meta.Severity)},
	)

	o.dynFields = fields
	return fields
}

// streamKey builds a deterministic fingerprint from the label values.
// Delimiter characters (| and =) in values are escaped to prevent
// collisions between logically distinct label sets.
func (o *Output) streamKey(meta audit.EventMetadata, fw *frameworkFields) string {
	o.keyBuf.Reset()
	for _, f := range o.resolveDynamicFields(meta, fw) {
		if f.exclude || f.value == "" {
			continue
		}
		o.keyBuf.WriteString(f.key)
		o.keyBuf.WriteByte('=')
		escapeKeyValue(&o.keyBuf, f.value)
		o.keyBuf.WriteByte('|')
	}
	return o.keyBuf.String()
}

// escapeKeyValue writes s to buf, escaping the | and = delimiters used
// in stream key fingerprints. This prevents collisions when label
// values contain these characters.
func escapeKeyValue(buf *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '|':
			buf.WriteString(`\|`)
		case '=':
			buf.WriteString(`\=`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			buf.WriteByte(s[i])
		}
	}
}

// streamLabels builds the label map for a Loki stream.
func (o *Output) streamLabels(meta audit.EventMetadata, fw *frameworkFields) map[string]string {
	labels := make(map[string]string, len(o.cfg.Labels.Static)+6)
	for k, v := range o.cfg.Labels.Static {
		labels[k] = v
	}
	for _, f := range o.resolveDynamicFields(meta, fw) {
		if f.exclude || f.value == "" {
			continue
		}
		labels[f.label] = f.value
	}
	return labels
}

// buildPayload writes the Loki push API JSON payload into o.payloadBuf.
// The payload follows the Loki push API format:
//
//	{"streams":[{"stream":{...},"values":[["ts","line"],...]},...]
func (o *Output) buildPayload() {
	o.payloadBuf.Reset()
	buf := &o.payloadBuf

	buf.WriteString(`{"streams":[`)

	first := true
	for _, s := range o.sortedStreams() {
		if !first {
			buf.WriteByte(',')
		}
		first = false

		// Stream labels object.
		buf.WriteString(`{"stream":{`)
		writeLabelsJSON(buf, s.labels)
		buf.WriteString(`},"values":[`)

		// Values array: [["timestamp_ns", "log_line"], ...]
		for j, e := range s.entries {
			if j > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`["`)
			buf.Write(strconv.AppendInt(buf.AvailableBuffer(), e.tsNano, 10))
			buf.WriteString(`",`)
			audit.WriteJSONString(buf, bytesToString(e.line))
			buf.WriteByte(']')
		}

		buf.WriteString(`]}`)
	}

	buf.WriteString(`]}`)
}

// sortedStreams returns the streams in deterministic label key order.
func (o *Output) sortedStreams() []*lokiStream {
	keys := make([]string, 0, len(o.streams))
	for k := range o.streams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]*lokiStream, 0, len(keys))
	for _, k := range keys {
		result = append(result, o.streams[k])
	}
	return result
}

// writeLabelsJSON writes a sorted set of label key-value pairs as JSON
// object fields (without the enclosing braces).
func writeLabelsJSON(buf *bytes.Buffer, labels map[string]string) {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		audit.WriteJSONString(buf, k)
		buf.WriteByte(':')
		audit.WriteJSONString(buf, labels[k])
	}
}

// maybeCompress applies gzip compression if cfg.Compress is true.
// Returns the payload bytes, whether they are compressed, and any
// compression error. On error the caller should fall back to the
// uncompressed payload in payloadBuf.
//
// In practice, gzip.Writer writing to a bytes.Buffer will not fail
// (bytes.Buffer.Write always returns nil error). The error handling
// is defensive — a safety net for correctness.
func (o *Output) maybeCompress() (body []byte, compressed bool, err error) {
	if !o.cfg.Compress {
		return o.payloadBuf.Bytes(), false, nil
	}
	o.compressBuf.Reset()
	if o.gzWriter == nil {
		o.gzWriter = gzip.NewWriter(o.compressDest)
	} else {
		o.gzWriter.Reset(o.compressDest)
	}
	if _, wErr := o.gzWriter.Write(o.payloadBuf.Bytes()); wErr != nil {
		return nil, false, fmt.Errorf("audit: loki: gzip write: %w", wErr)
	}
	if cErr := o.gzWriter.Close(); cErr != nil {
		return nil, false, fmt.Errorf("audit: loki: gzip close: %w", cErr)
	}
	return o.compressBuf.Bytes(), true, nil
}

// bytesToString converts a byte slice to a string. This is a simple
// type conversion; Go 1.22+ optimises this to avoid copying in many
// cases when the result is only used temporarily.
func bytesToString(b []byte) string {
	return string(b)
}
