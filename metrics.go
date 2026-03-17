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
// OpenTelemetry, etc.). Consumers wire their own.
type Metrics interface {
	// RecordEvent records an event delivery attempt to the named output.
	// status is always one of the string literals "success" or "error";
	// implementers MAY assume no other value is passed.
	RecordEvent(output, status string)

	// RecordOutputError records a write error on the named output.
	RecordOutputError(output string)

	// RecordOutputFiltered records that an event was skipped by a
	// per-output event route filter (see issue #6 for the fan-out
	// engine that uses this).
	RecordOutputFiltered(output string)

	// RecordBufferDrop records that an event was dropped because the
	// main async buffer was full.
	RecordBufferDrop()

	// RecordWebhookDrop records that an event was dropped because the
	// webhook output's internal buffer was full.
	RecordWebhookDrop()

	// RecordWebhookFlush records a webhook batch flush with the number
	// of events in the batch and the flush duration.
	RecordWebhookFlush(batchSize int, dur time.Duration)
}
