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

// Metrics is an optional instrumentation interface that consumers implement
// to collect audit pipeline telemetry. Pass an implementation via
// [WithMetrics]; pass nil to disable metrics collection.
//
// The library never imports a concrete metrics library (Prometheus,
// OpenTelemetry, etc.). Consumers wire their own.
type Metrics interface {
	// RecordEvent records an event delivery attempt to the named output.
	// status is always one of the string literals "success" or "error";
	// implementers MAY assume no other value is passed.
	RecordEvent(output, status string)

	// RecordOutputError records a write error on the named output.
	RecordOutputError(output string)

	// RecordOutputFiltered records that a per-output event route filter
	// prevented an event from being delivered to the named output.
	// This is distinct from [Metrics.RecordFiltered], which records
	// global category/event filter drops before any output is reached.
	RecordOutputFiltered(output string)

	// RecordValidationError records that [Logger.Audit] rejected an
	// event due to a validation failure: unknown event type, missing
	// required fields, or unknown fields in strict mode. The
	// eventType parameter is the event type string that was passed to
	// Audit.
	RecordValidationError(eventType string)

	// RecordFiltered records that an event was silently discarded by
	// the global category/event filter. This is distinct from
	// [Metrics.RecordOutputFiltered] which tracks per-output route
	// filtering.
	RecordFiltered(eventType string)

	// RecordSerializationError records that the configured [Formatter]
	// returned an error (or panicked) when serialising an event. The
	// event is dropped when this occurs.
	RecordSerializationError(eventType string)

	// RecordBufferDrop records that an event was dropped because the
	// main async buffer was full.
	RecordBufferDrop()
}
