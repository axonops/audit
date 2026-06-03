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

import "time"

// Metrics is an optional instrumentation interface that consumers implement
// to collect audit pipeline telemetry. Pass an implementation via
// [WithMetrics]; pass nil to disable metrics collection.
//
// The library never imports a concrete metrics library (Prometheus,
// OpenTelemetry, etc.). Consumers wire their own. The
// [examples/20-capstone] Prometheus adapter shows a complete
// implementation in under 50 lines using a table-driven registration
// pattern; copy it as a starting point.
//
// Consumers SHOULD embed [NoOpMetrics] in their implementation to
// absorb new methods added in future versions without breaking builds.
//
// # Ownership: Metrics vs OutputMetrics
//
// [Metrics] records pipeline-level counters that span the entire auditor:
//
//   - RecordSubmitted — total events entering the pipeline
//   - RecordBufferDrop — core intake queue overflow
//   - RecordQueueDepth — core intake queue pressure gauge
//
// [OutputMetrics] records per-output buffer and delivery operations
// inside each async output:
//
//   - RecordDrop(count) — per-output buffer overflow
//   - RecordFlush(batchSize, dur) — per-output batch delivery
//   - RecordError(count) — per-output non-retryable delivery failure
//   - RecordRetry — per-output retry attempt
//   - RecordQueueDepth — per-output buffer pressure gauge
//
// Consumers derive event-level delivery counts from the sum of
// RecordFlush batchSize values; per-output error counts come from
// RecordError(count). The pipeline does NOT carry an auditor-wide
// per-event delivery counter — RecordFlush sums are the canonical
// "delivered events" signal.
//
// # Cardinality guidance
//
// Each method notes the Prometheus / OpenTelemetry label-vector
// dimensionality implied by its arguments. "High cardinality" flags
// methods whose label space scales with caller-supplied identifiers
// (event types, output names) — consumers with many event types
// should budget accordingly when wiring label vectors.
//
// # Forward compatibility
//
// Adding a method to [Metrics] in a v1.x release is a breaking
// interface change. The library adds new metrics via separate
// optional interfaces detected by type assertion on the passed
// [Metrics] value, mirroring the pattern used by
// [file.RotationRecorder] / [syslog.ReconnectRecorder] on
// [OutputMetrics]. Consumers who embed [NoOpMetrics] retain
// no-op implementations for every base-interface method; extensions
// are additive. See ADR 0005 (docs/adr/0005-metrics-interface-shape.md)
// for the full policy.
type Metrics interface {
	// RecordSubmitted records that an event was submitted to the
	// pipeline via [Auditor.AuditEvent]. Called once per AuditEvent
	// call, before any filtering or buffering. This is the "total
	// events in" counter.
	//
	// Cardinality: single counter (no labels).
	RecordSubmitted()

	// RecordOutputError records a write error on the named output.
	//
	// Cardinality: 1-dimensional vector (output). Bounded by the
	// number of configured outputs.
	RecordOutputError(output string)

	// RecordOutputFiltered records that a per-output event route filter
	// prevented an event from being delivered to the named output.
	// This is distinct from [Metrics.RecordFiltered], which records
	// global category/event filter drops before any output is reached.
	//
	// Cardinality: 1-dimensional vector (output).
	RecordOutputFiltered(output string)

	// RecordValidationError records that [Auditor.AuditEvent] rejected an
	// event due to a validation failure: unknown event type, missing
	// required fields, or unknown fields in strict mode. The
	// eventType parameter is the event type string that was passed to
	// AuditEvent.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// if the taxonomy grows large or if unknown event types are
	// common. Consumers may aggregate into a single counter without
	// the event_type label to cap the vector size.
	RecordValidationError(eventType string)

	// RecordFiltered records that an event was silently discarded by
	// the global category/event filter. This is distinct from
	// [Metrics.RecordOutputFiltered] which tracks per-output route
	// filtering.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// — see [Metrics.RecordValidationError].
	RecordFiltered(eventType string)

	// RecordSerializationError records that the configured [Formatter]
	// returned an error (or panicked) when serialising an event. The
	// event is dropped when this occurs.
	//
	// Cardinality: 1-dimensional vector (event_type). HIGH cardinality
	// — see [Metrics.RecordValidationError].
	RecordSerializationError(eventType string)

	// RecordBufferDrop records that an event was dropped because the
	// main async queue was full.
	//
	// Cardinality: single counter (no labels).
	RecordBufferDrop()

	// RecordQueueDepth records the current depth and capacity of the
	// core intake queue. Called from the drain loop, sampled every 64
	// events processed. depth is len(channel), capacity is
	// cap(channel).
	//
	// Cardinality: gauge (depth) and an associated gauge or constant
	// (capacity). No per-call labels. Consumers may record the
	// capacity once at startup and emit depth per call.
	RecordQueueDepth(depth, capacity int)
}

// NoOpMetrics is a [Metrics] implementation where every method is a
// no-op. Embed it in your own struct to override only the methods you
// care about:
//
//	type MyMetrics struct {
//	    audit.NoOpMetrics
//	    drops atomic.Int64
//	}
//	func (m *MyMetrics) RecordBufferDrop() { m.drops.Add(1) }
type NoOpMetrics struct{}

// Compile-time interface check.
var _ Metrics = NoOpMetrics{}

// RecordSubmitted is a no-op.
func (NoOpMetrics) RecordSubmitted() {}

// RecordOutputError is a no-op.
func (NoOpMetrics) RecordOutputError(string) {}

// RecordOutputFiltered is a no-op.
func (NoOpMetrics) RecordOutputFiltered(string) {}

// RecordValidationError is a no-op.
func (NoOpMetrics) RecordValidationError(string) {}

// RecordFiltered is a no-op.
func (NoOpMetrics) RecordFiltered(string) {}

// RecordSerializationError is a no-op.
func (NoOpMetrics) RecordSerializationError(string) {}

// RecordBufferDrop is a no-op.
func (NoOpMetrics) RecordBufferDrop() {}

// RecordQueueDepth is a no-op.
func (NoOpMetrics) RecordQueueDepth(int, int) {}

// OutputMetrics is an optional per-output instrumentation interface
// for async buffer telemetry. Each output receives its own instance
// at construction via [FrameworkContext.OutputMetrics] (typically
// produced per-output by an [OutputMetricsFactory] supplied to
// outputconfig.WithOutputMetricsFactory), scoped to that output's
// identity.
//
// Unlike [Metrics] (which tracks pipeline-level events), OutputMetrics
// tracks per-output buffer operations: drops, flushes, retries, errors,
// and queue depth. See the [Metrics] godoc for the ownership table.
//
// Output-specific extensions (e.g. file rotation, syslog reconnection)
// are detected via type assertion on the OutputMetrics value. The
// returned OutputMetrics MAY optionally implement output-specific
// extension interfaces (e.g. [file.RotationRecorder],
// [syslog.ReconnectRecorder]). If detected, the output uses the
// extended methods automatically.
//
// Consumers SHOULD embed [NoOpOutputMetrics] for forward compatibility.
type OutputMetrics interface {
	// RecordDrop records that count events were dropped because the
	// output's internal async buffer was full. count MUST be >= 1.
	// Outputs that drop one event at a time SHOULD call
	// RecordDrop(1); batch-aware drop paths SHOULD pass the precise
	// event count.
	RecordDrop(count int)

	// RecordFlush records a successful batch flush to the output
	// destination. batchSize is the number of events in the batch.
	// dur is the wall-clock time of the flush operation.
	//
	// Consumers derive the auditor-wide "events delivered" counter
	// by summing batchSize across all RecordFlush calls.
	RecordFlush(batchSize int, dur time.Duration)

	// RecordError records count events that failed delivery with a
	// non-retryable error. count MUST be >= 1. Outputs that report
	// per-batch errors SHOULD pass len(batch); outputs that report
	// per-event errors SHOULD call RecordError(1).
	RecordError(count int)

	// RecordRetry records a retry attempt. attempt is 1-indexed:
	// 1 means first retry (second delivery attempt), 2 means second
	// retry, etc.
	RecordRetry(attempt int)

	// RecordQueueDepth records the current depth and capacity of the
	// output's internal async buffer. depth is the number of events
	// waiting to be flushed, capacity is the buffer size.
	RecordQueueDepth(depth, capacity int)
}

// OutputMetricsFactory creates a scoped [OutputMetrics] for a named
// output. outputType is the output type name (e.g. "file", "syslog",
// "webhook", "loki"). outputName is the consumer-chosen YAML key name
// (e.g. "compliance_archive", "security_feed"). The factory is called
// once per output at construction time.
//
// Example Prometheus implementation:
//
//	func(outputType, outputName string) audit.OutputMetrics {
//	    return &outputMetrics{
//	        drops: dropsVec.WithLabelValues(outputType, outputName),
//	    }
//	}
type OutputMetricsFactory func(outputType, outputName string) OutputMetrics

// NoOpOutputMetrics is an [OutputMetrics] implementation where every
// method is a no-op. Embed it in your own struct to override only
// the methods you care about.
type NoOpOutputMetrics struct{}

// Compile-time interface check.
var _ OutputMetrics = NoOpOutputMetrics{}

// RecordDrop is a no-op.
func (NoOpOutputMetrics) RecordDrop(int) {}

// RecordFlush is a no-op.
func (NoOpOutputMetrics) RecordFlush(int, time.Duration) {}

// RecordError is a no-op.
func (NoOpOutputMetrics) RecordError(int) {}

// RecordRetry is a no-op.
func (NoOpOutputMetrics) RecordRetry(int) {}

// RecordQueueDepth is a no-op.
func (NoOpOutputMetrics) RecordQueueDepth(int, int) {}
