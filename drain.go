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

func (a *Auditor) drainLoop(ctx context.Context) {
	defer close(a.drainDone)
	defer a.logger.Debug("audit: drain loop exiting")
	a.logger.Debug("audit: drain loop started")
	for {
		select {
		case entry := <-a.ch:
			if entry != nil {
				a.processEntry(entry)
			}
		case <-ctx.Done():
			a.drainRemaining()
			return
		}
	}
}

// drainRemaining flushes any events left in the channel after the
// context is cancelled.
func (a *Auditor) drainRemaining() {
	for {
		select {
		case entry := <-a.ch:
			if entry != nil {
				a.processEntry(entry)
			}
		default:
			return
		}
	}
}

// processEntry fans out an audit entry to all matching outputs. Events
// are serialised once per unique Formatter; per-output routes are
// checked before delivery. Output failures are isolated.
func (a *Auditor) processEntry(entry *auditEntry) { //nolint:gocognit,gocyclo,cyclop // queue depth sampling adds 1 to baseline complexity
	// Sample queue depth every 64 events for metrics gauges.
	a.drainCount++
	if a.metrics != nil && a.drainCount%64 == 0 {
		a.metrics.RecordQueueDepth(len(a.ch), cap(a.ch))
	}

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
			a.logger.Error("audit: panic in processEntry",
				"event_type", entry.eventType,
				"panic", r)
			if a.metrics != nil {
				a.metrics.RecordSerializationError(entry.eventType)
			}
		}
	}()

	ts := time.Now()
	def := a.taxonomy.Events[entry.eventType]

	if len(def.Categories) == 0 {
		// Uncategorised event: single pass, no category context.
		var fc formatCache
		a.deliverToOutputs(entry, "", ts, def, &fc)
		return
	}

	// Categorised event: deliver once per enabled category.
	// If EnableEvent was called, iterate ALL categories.
	// The atomic flag guards the sync.Map lookup on the hot path.
	eventForceEnabled := false
	if a.filter.hasEventOverrides.Load() {
		if override, ok := a.filter.eventOverrides.Load(entry.eventType); ok && override {
			eventForceEnabled = true
		}
	}

	// Format cache shared across category passes — the formatted
	// output is identical because ResolvedSeverity is a single
	// value per event, not per category.
	var fc formatCache

	for _, category := range def.Categories {
		if !eventForceEnabled && !a.filter.isCategoryEnabled(category) {
			continue
		}
		a.deliverToOutputs(entry, category, ts, def, &fc)
	}
}

// deliverToOutputs fans out a single event to all matching outputs
// for a given category. An empty category means the event is
// uncategorised.
func (a *Auditor) deliverToOutputs(entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache) {
	severity := def.ResolvedSeverity()
	meta := EventMetadata{
		EventType: entry.eventType,
		Severity:  severity,
		Category:  category,
		Timestamp: ts,
	}

	for _, oe := range a.entries {
		a.deliverToOutput(oe, entry, category, ts, def, fc, meta)
	}
}

// deliverToOutput handles delivery to a single output with per-output
// panic recovery. A panic in one output's Write (or format/HMAC path)
// does not prevent delivery to subsequent outputs. This is critical
// for the fan-out guarantee: a buggy output must not take down the
// entire delivery pipeline.
func (a *Auditor) deliverToOutput(oe *outputEntry, entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache, meta EventMetadata) { //nolint:gocyclo,gocognit,cyclop // per-output delivery with panic recovery
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			a.logger.Error("audit: panic in output write",
				"output", oe.output.Name(),
				"event_type", entry.eventType,
				"panic", r,
				"stack", string(buf[:n]))
			// Always record the panic in core metrics, even for
			// DeliveryReporter outputs — the output clearly did not
			// self-report if it panicked.
			if a.metrics != nil {
				a.metrics.RecordOutputError(oe.output.Name())
			}
		}
	}()

	if !oe.matchesEvent(entry.eventType, category, meta.Severity) {
		if a.metrics != nil {
			a.metrics.RecordOutputFiltered(oe.output.Name())
		}
		return
	}

	var data []byte
	if oe.formatOpts != nil && def.FieldLabels != nil {
		data = a.formatWithExclusion(oe, entry, ts, def)
	} else {
		data = a.formatCached(oe, entry, ts, def, fc)
	}
	if data == nil {
		return
	}

	// Append event_category if enabled and the event has a category.
	if category != "" && !a.taxonomy.SuppressEventCategory {
		data = appendEventCategory(data, oe.effectiveFormatter(a.formatter), category)
	}

	// Compute and append HMAC if configured for this output.
	//
	// Invariant: _hmac is the LAST field on the wire. Every field
	// authenticated by HMAC is appended BEFORE computeHMACFast. Any
	// future post-field added to the drain pipeline MUST land before
	// this block. Appending after _hmac leaves the new field outside
	// the authenticated region — same class of bug as issue #473.
	if oe.hmac != nil {
		fmtr := oe.effectiveFormatter(a.formatter)
		// _hmac_v (salt version identifier) is appended FIRST so it is
		// part of the bytes the HMAC authenticates. A MITM flipping
		// v1 → v2 would otherwise redirect the verifier to a different
		// salt without detection (issue #473).
		data = AppendPostField(data, fmtr, PostField{
			JSONKey: "_hmac_v", CEFKey: "_hmacVersion", Value: oe.hmacConfig.SaltVersion,
		})
		// HMAC covers payload + event_category + _hmac_v.
		hmacHex := oe.hmac.computeHMACFast(data)
		// _hmac is the tag; it is appended last and never covers itself.
		data = AppendPostField(data, fmtr, PostField{
			JSONKey: "_hmac", CEFKey: "_hmac", Value: string(hmacHex),
		})
	}

	var writeErr error
	if oe.metadataWriter != nil {
		writeErr = oe.metadataWriter.WriteWithMetadata(data, meta)
	} else {
		writeErr = oe.output.Write(data)
	}
	a.recordWrite(oe.output.Name(), entry.eventType, oe.selfReports, writeErr)
}

// prepareOutputEntries caches interface assertions and pre-constructs
// per-output state (MetadataWriter, DeliveryReporter, FormatOptions,
// HMAC). Called once at construction time after all options are applied.
func (a *Auditor) prepareOutputEntries() {
	for _, oe := range a.entries {
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

// propagateFrameworkFields propagates auditor-wide framework
// metadata to all formatters that implement [FrameworkFieldSetter]
// and all outputs that implement [FrameworkFieldReceiver].
func (a *Auditor) propagateFrameworkFields() {
	set := func(f Formatter) {
		if setter, ok := f.(FrameworkFieldSetter); ok {
			setter.SetFrameworkFields(a.appName, a.host, a.timezone, a.pid)
		}
	}
	set(a.formatter)
	for _, oe := range a.entries {
		if oe.formatter != nil {
			set(oe.formatter)
		}
		if recv, ok := oe.output.(FrameworkFieldReceiver); ok {
			recv.SetFrameworkFields(a.appName, a.host, a.timezone, a.pid)
		}
	}
}

// formatWithExclusion serialises an event with sensitivity-labelled
// fields excluded. It bypasses the format cache because different
// outputs may exclude different label sets.
func (a *Auditor) formatWithExclusion(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef) []byte {
	// Safe: drain loop is single-goroutine. FieldLabels is read-only
	// after taxonomy registration; we assign the pointer per-event
	// to avoid allocating a new FormatOptions on every call.
	oe.formatOpts.FieldLabels = def.FieldLabels
	f := oe.effectiveFormatter(a.formatter)
	data, err := f.Format(ts, entry.eventType, entry.fields, def, oe.formatOpts)
	if err != nil {
		a.logger.Error("audit: format error (filtered)", "event", entry.eventType, "output", oe.output.Name(), "error", err)
		if a.metrics != nil {
			a.metrics.RecordSerializationError(entry.eventType)
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
func (a *Auditor) formatCached(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef, cache *formatCache) []byte {
	f := oe.effectiveFormatter(a.formatter)
	if data, ok := cache.get(f); ok {
		return data // may be nil if serialisation failed
	}
	data, err := f.Format(ts, entry.eventType, entry.fields, def, nil)
	if err != nil {
		a.logger.Error("audit: serialisation failed",
			"event_type", entry.eventType,
			"error", err)
		if a.metrics != nil {
			a.metrics.RecordSerializationError(entry.eventType)
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
func (a *Auditor) recordWrite(outputName, eventType string, selfReports bool, writeErr error) {
	if writeErr != nil {
		a.logger.Error("audit: output write failed",
			"output", outputName,
			"event_type", eventType,
			"error", writeErr)
		if a.metrics != nil && !selfReports {
			a.metrics.RecordOutputError(outputName)
			a.metrics.RecordEvent(outputName, "error")
		}
		return
	}
	if a.metrics != nil && !selfReports {
		a.metrics.RecordEvent(outputName, "success")
	}
}
