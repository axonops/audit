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

import "errors"

// ErrOutputClosed is returned by [Output.Write] when the output has
// already been closed.
var ErrOutputClosed = errors.New("audit: output is closed")

// Output is the interface that audit event destinations MUST implement.
// All outputs receive pre-serialised bytes (JSON, CEF, or a custom
// format chosen via [WithFormatter]). The library will provide built-in
// implementations for stdout, file, syslog, and webhook.
type Output interface {
	// Write sends a single serialised audit event to the output.
	// data is a complete, newline-terminated byte slice. Write is
	// called from a single goroutine; concurrent calls from the
	// library will not occur. Implementers MAY assume single-caller
	// access.
	Write(data []byte) error

	// Close flushes any buffered data and releases resources. The
	// library guarantees Write will not be called after Close. Close
	// is called exactly once by [Logger.Close].
	Close() error

	// Name returns a human-readable identifier for the output,
	// used in log messages and metrics labels.
	Name() string
}

// DeliveryReporter is an optional interface that [Output] implementations
// may satisfy to indicate they handle their own delivery metrics
// reporting. When satisfied and [DeliveryReporter.ReportsDelivery]
// returns true, the core logger skips its default per-event
// [Metrics.RecordEvent] calls for that output — the output is
// responsible for calling them after actual delivery.
type DeliveryReporter interface {
	ReportsDelivery() bool
}
