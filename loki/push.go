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

	"github.com/axonops/audit"
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
//
// # Per-event allocation accounting (#494)
//
// The per-event hot path is lock-free and allocation-free in the
// steady state:
//
//   - streamKey writes into the reused keyBuf and does not allocate;
//     the map lookup `o.streams[string(keyBytes)]` uses the Go
//     compiler's `m[string(b)]` optimisation to avoid materialising
//     a string on every lookup.
//   - A string is materialised only on cache miss (first event for a
//     given stream in this flush). A typical batch of 100 events
//     across 5 streams therefore allocates 5 keys rather than 100.
//   - resolveDynamicFields reuses the dynFields backing array, so no
//     per-event slice allocation.
//
// The per-stream-creation cost is one map allocation (streamLabels)
// and one entries-slice allocation — unavoidable without a slab
// allocator, and bounded by the number of distinct streams in the
// batch, not the number of events.
func (o *Output) groupByStream(batch []lokiEntry) {
	clear(o.streams)

	fw := o.fw.Load()

	for i := range batch {
		entry := &batch[i]
		o.writeStreamKey(entry.metadata, fw)
		// Go optimises `m[string(b)]` to avoid allocating the lookup
		// key — the string is materialised only on cache miss below.
		keyBytes := o.keyBuf.Bytes()
		s, ok := o.streams[string(keyBytes)]
		if !ok {
			s = &lokiStream{
				labels:  o.streamLabels(entry.metadata, fw),
				entries: make([]lokiStreamEntry, 0, 8),
			}
			// One string allocation per distinct stream in this batch.
			o.streams[string(keyBytes)] = s
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
//
// Per-event allocations: none. `fw.pidStr` is pre-computed at
// [Output.SetFrameworkFields] time (one-shot; framework fields are
// auditor-wide constants). `strconv.Itoa(meta.Severity)` falls into
// Go's small-integer intern table (values 0..99) which covers every
// [audit.Severity] constant, so no heap allocation per event (#494).
func (o *Output) resolveDynamicFields(meta audit.EventMetadata, fw *frameworkFields) []dynamicField {
	dl := &o.cfg.Labels.Dynamic
	fields := o.dynFields[:0] // reuse backing array

	if fw != nil {
		fields = append(fields,
			dynamicField{"an", "app_name", dl.ExcludeAppName, fw.appName},
			dynamicField{"h", "host", dl.ExcludeHost, fw.host},
			dynamicField{"tz", "timezone", dl.ExcludeTimezone, fw.timezone},
			dynamicField{"p", "pid", dl.ExcludePID, fw.pidStr},
		)
	}

	fields = append(fields,
		dynamicField{"et", "event_type", dl.ExcludeEventType, meta.EventType},
		dynamicField{"ec", "event_category", dl.ExcludeEventCategory, meta.Category},
		dynamicField{"s", "severity", dl.ExcludeSeverity, strconv.Itoa(meta.Severity)},
	)

	o.dynFields = fields
	return fields
}

// writeStreamKey builds a deterministic fingerprint from the label
// values into o.keyBuf. Delimiter characters (| and =) in values are
// escaped to prevent collisions between logically distinct label sets.
// Callers read the result via o.keyBuf.Bytes() — materialising a
// string only when actually needed (on map insert). The previous API
// that returned a string allocated once per event; this one never
// allocates (#494).
func (o *Output) writeStreamKey(meta audit.EventMetadata, fw *frameworkFields) {
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
		o.writeLabelsJSON(buf, s.labels)
		buf.WriteString(`},"values":[`)

		// Values array: [["timestamp_ns", "log_line"], ...]
		for j, e := range s.entries {
			if j > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`["`)
			// strconv.AppendInt into a fixed-size Output scratch array
			// instead of buf.AvailableBuffer(): AvailableBuffer may
			// return a 0-cap slice when the buffer is full, forcing
			// append() to allocate a fresh backing array every event
			// (#494).
			buf.Write(strconv.AppendInt(o.intScratch[:0], e.tsNano, 10))
			buf.WriteString(`",`)
			// WriteJSONBytes avoids the `string(e.line)` copy at
			// 100 events-per-batch scale (#494/#495).
			audit.WriteJSONBytes(buf, e.line)
			buf.WriteByte(']')
		}

		buf.WriteString(`]}`)
	}

	buf.WriteString(`]}`)
}

// sortedStreams returns the streams in deterministic stream-key order.
// The `keys` and `result` backing slices are pooled on the Output
// struct and reused across flushes — no per-flush allocation once the
// slices have grown to the working-set size (#494).
//
// Trailing positions in sortStreamsBuf are nil'd before returning so
// that a flush whose stream count shrinks does not retain pointers to
// the previous flush's *lokiStream values (and through them, their
// labels map and entries slices) past their useful life. The
// sortKeysBuf and labelKeysBuf pools hold strings — no nil-tail
// concern there.
func (o *Output) sortedStreams() []*lokiStream {
	keys := o.sortKeysBuf[:0]
	for k := range o.streams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o.sortKeysBuf = keys

	result := o.sortStreamsBuf[:0]
	for _, k := range keys {
		result = append(result, o.streams[k])
	}
	// Nil the tail of the backing array so previously-returned (now
	// out-of-scope) *lokiStream pointers can be GC'd if this flush's
	// stream count is smaller than the previous (#494).
	for i := len(result); i < cap(result); i++ {
		result[:cap(result)][i] = nil
	}
	o.sortStreamsBuf = result
	return result
}

// writeLabelsJSON writes a sorted set of label key-value pairs as JSON
// object fields (without the enclosing braces). The `keys` backing
// slice is pooled on the Output struct via keysBuf and reused across
// streams within a flush and across flushes — no per-stream slice
// allocation once grown to the working-set size (#494).
func (o *Output) writeLabelsJSON(buf *bytes.Buffer, labels map[string]string) {
	keys := o.labelKeysBuf[:0]
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	o.labelKeysBuf = keys

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
