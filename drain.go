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
	"context"
	"runtime"
	"time"
)

func (l *Logger) drainLoop(ctx context.Context) {
	defer close(l.drainDone)
	defer l.logger.Debug("audit: drain loop exiting")
	l.logger.Debug("audit: drain loop started")
	for {
		select {
		case entry := <-l.ch:
			if entry != nil {
				l.processEntry(entry)
			}
		case <-ctx.Done():
			l.drainRemaining()
			return
		}
	}
}

// drainRemaining flushes any events left in the channel after the
// context is cancelled.
func (l *Logger) drainRemaining() {
	for {
		select {
		case entry := <-l.ch:
			if entry != nil {
				l.processEntry(entry)
			}
		default:
			return
		}
	}
}

// processEntry fans out an audit entry to all matching outputs. Events
// are serialised once per unique Formatter; per-output routes are
// checked before delivery. Output failures are isolated.
func (l *Logger) processEntry(entry *auditEntry) {
	// Defers execute LIFO. The pool return must happen after the
	// panic recovery, so it is declared first (executes last).
	defer func() {
		returnFieldsToPool(entry.fields)
		entry.eventType = ""
		entry.fields = nil
		auditEntryPool.Put(entry)
	}()
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error("audit: panic in processEntry",
				"event_type", entry.eventType,
				"panic", r)
			if l.metrics != nil {
				l.metrics.RecordSerializationError(entry.eventType)
			}
		}
	}()

	ts := time.Now()
	def := l.taxonomy.Events[entry.eventType]

	if len(def.Categories) == 0 {
		// Uncategorised event: single pass, no category context.
		var fc formatCache
		l.deliverToOutputs(entry, "", ts, def, &fc)
		return
	}

	// Categorised event: deliver once per enabled category.
	// If EnableEvent was called, iterate ALL categories.
	// The atomic flag guards the sync.Map lookup on the hot path.
	eventForceEnabled := false
	if l.filter.hasEventOverrides.Load() {
		if override, ok := l.filter.eventOverrides.Load(entry.eventType); ok && override {
			eventForceEnabled = true
		}
	}

	// Format cache shared across category passes — the formatted
	// output is identical because ResolvedSeverity is a single
	// value per event, not per category.
	var fc formatCache

	for _, category := range def.Categories {
		if !eventForceEnabled && !l.filter.isCategoryEnabled(category) {
			continue
		}
		l.deliverToOutputs(entry, category, ts, def, &fc)
	}
}

// deliverToOutputs fans out a single event to all matching outputs
// for a given category. An empty category means the event is
// uncategorised.
func (l *Logger) deliverToOutputs(entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache) {
	severity := def.ResolvedSeverity()
	meta := EventMetadata{
		EventType: entry.eventType,
		Severity:  severity,
		Category:  category,
		Timestamp: ts,
	}

	for _, oe := range l.entries {
		l.deliverToOutput(oe, entry, category, ts, def, fc, meta)
	}
}

// deliverToOutput handles delivery to a single output with per-output
// panic recovery. A panic in one output's Write (or format/HMAC path)
// does not prevent delivery to subsequent outputs. This is critical
// for the fan-out guarantee: a buggy output must not take down the
// entire delivery pipeline.
func (l *Logger) deliverToOutput(oe *outputEntry, entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache, meta EventMetadata) { //nolint:gocyclo,gocognit,cyclop // per-output delivery with panic recovery
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			l.logger.Error("audit: panic in output write",
				"output", oe.output.Name(),
				"event_type", entry.eventType,
				"panic", r,
				"stack", string(buf[:n]))
			// Always record the panic in core metrics, even for
			// DeliveryReporter outputs — the output clearly did not
			// self-report if it panicked.
			if l.metrics != nil {
				l.metrics.RecordOutputError(oe.output.Name())
			}
		}
	}()

	if !oe.matchesEvent(entry.eventType, category, meta.Severity) {
		if l.metrics != nil {
			l.metrics.RecordOutputFiltered(oe.output.Name())
		}
		return
	}

	var data []byte
	if oe.formatOpts != nil && def.FieldLabels != nil {
		data = l.formatWithExclusion(oe, entry, ts, def)
	} else {
		data = l.formatCached(oe, entry, ts, def, fc)
	}
	if data == nil {
		return
	}

	// Append event_category if enabled and the event has a category.
	if category != "" && !l.taxonomy.SuppressEventCategory {
		data = appendEventCategory(data, oe.effectiveFormatter(l.formatter), category)
	}

	// Compute and append HMAC if configured for this output.
	// HMAC is computed over the complete payload at this point
	// (after field stripping + event_category).
	if oe.hmac != nil {
		hmacHex := oe.hmac.computeHMACFast(data)
		fmtr := oe.effectiveFormatter(l.formatter)
		data = AppendPostField(data, fmtr, PostField{
			JSONKey: "_hmac", CEFKey: "_hmac", Value: string(hmacHex),
		})
		data = AppendPostField(data, fmtr, PostField{
			JSONKey: "_hmac_v", CEFKey: "_hmacVersion", Value: oe.hmacConfig.SaltVersion,
		})
	}

	var writeErr error
	if oe.metadataWriter != nil {
		writeErr = oe.metadataWriter.WriteWithMetadata(data, meta)
	} else {
		writeErr = oe.output.Write(data)
	}
	l.recordWrite(oe.output.Name(), entry.eventType, oe.selfReports, writeErr)
}

// prepareOutputEntries caches interface assertions and pre-constructs
// per-output state (MetadataWriter, DeliveryReporter, FormatOptions,
// HMAC). Called once at construction time after all options are applied.
func (l *Logger) prepareOutputEntries() {
	for _, oe := range l.entries {
		if mw, ok := oe.output.(MetadataWriter); ok {
			oe.metadataWriter = mw
		}
		if dr, ok := oe.output.(DeliveryReporter); ok {
			oe.selfReports = dr.ReportsDelivery()
		}
		if oe.excludedLabels != nil {
			oe.formatOpts = &FormatOptions{
				ExcludedLabels: oe.excludedLabels,
			}
		}
		if oe.hmacConfig != nil && oe.hmacConfig.Enabled {
			oe.hmac = newHMACState(oe.hmacConfig)
		}
	}
}

// propagateFrameworkFields propagates logger-wide framework
// metadata to all formatters that implement [FrameworkFieldSetter]
// and all outputs that implement [FrameworkFieldReceiver].
func (l *Logger) propagateFrameworkFields() {
	set := func(f Formatter) {
		if setter, ok := f.(FrameworkFieldSetter); ok {
			setter.SetFrameworkFields(l.appName, l.host, l.timezone, l.pid)
		}
	}
	set(l.formatter)
	for _, oe := range l.entries {
		if oe.formatter != nil {
			set(oe.formatter)
		}
		if recv, ok := oe.output.(FrameworkFieldReceiver); ok {
			recv.SetFrameworkFields(l.appName, l.host, l.timezone, l.pid)
		}
	}
}

// formatWithExclusion serialises an event with sensitivity-labelled
// fields excluded. It bypasses the format cache because different
// outputs may exclude different label sets.
func (l *Logger) formatWithExclusion(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef) []byte {
	// Safe: drain loop is single-goroutine. FieldLabels is read-only
	// after taxonomy registration; we assign the pointer per-event
	// to avoid allocating a new FormatOptions on every call.
	oe.formatOpts.FieldLabels = def.FieldLabels
	f := oe.effectiveFormatter(l.formatter)
	data, err := f.Format(ts, entry.eventType, entry.fields, def, oe.formatOpts)
	if err != nil {
		l.logger.Error("audit: format error (filtered)", "event", entry.eventType, "output", oe.output.Name(), "error", err)
		if l.metrics != nil {
			l.metrics.RecordSerializationError(entry.eventType)
		}
		return nil
	}
	return data
}

// formatCacheSize is the number of unique formatters cached on the
// stack before falling back to a heap-allocated map.
const formatCacheSize = 4

// formatCacheEntry pairs a formatter with its serialised output.
type formatCacheEntry struct {
	f    Formatter
	data []byte
}

// formatCache caches serialised output per unique formatter. For
// deployments with <= 4 unique formatters (the vast majority), the
// array is stack-allocated. Falls back to a heap map for larger counts.
type formatCache struct {
	m   map[Formatter][]byte // overflow; nil until needed
	arr [formatCacheSize]formatCacheEntry
	n   int
}

func (c *formatCache) get(f Formatter) ([]byte, bool) {
	for i := range c.n {
		if c.arr[i].f == f {
			return c.arr[i].data, true
		}
	}
	if c.m != nil {
		data, ok := c.m[f]
		return data, ok
	}
	return nil, false
}

func (c *formatCache) put(f Formatter, data []byte) {
	if c.n < formatCacheSize {
		c.arr[c.n] = formatCacheEntry{f: f, data: data}
		c.n++
		return
	}
	if c.m == nil {
		c.m = make(map[Formatter][]byte)
	}
	c.m[f] = data
}

// formatCached returns the serialised bytes for the output's formatter,
// using the cache to avoid redundant serialisation. Returns nil if
// serialisation failed.
func (l *Logger) formatCached(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef, cache *formatCache) []byte {
	f := oe.effectiveFormatter(l.formatter)
	if data, ok := cache.get(f); ok {
		return data // may be nil if serialisation failed
	}
	data, err := f.Format(ts, entry.eventType, entry.fields, def, nil)
	if err != nil {
		l.logger.Error("audit: serialisation failed",
			"event_type", entry.eventType,
			"error", err)
		if l.metrics != nil {
			l.metrics.RecordSerializationError(entry.eventType)
		}
		cache.put(f, nil) // mark as failed
		return nil
	}
	cache.put(f, data)
	return data
}

// recordWrite handles post-write metrics and error logging for both
// the plain Write and MetadataWriter paths. Called once per output per
// event with the result of the write call. No closures, no interface
// dispatch — all parameters are concrete values.
func (l *Logger) recordWrite(outputName, eventType string, selfReports bool, writeErr error) {
	if writeErr != nil {
		l.logger.Error("audit: output write failed",
			"output", outputName,
			"event_type", eventType,
			"error", writeErr)
		if l.metrics != nil && !selfReports {
			l.metrics.RecordOutputError(outputName)
			l.metrics.RecordEvent(outputName, "error")
		}
		return
	}
	if l.metrics != nil && !selfReports {
		l.metrics.RecordEvent(outputName, "success")
	}
}
