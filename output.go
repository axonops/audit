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
	"fmt"
	"log/slog"
	"time"
)

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
	// is called exactly once by [Auditor.Close].
	Close() error

	// Name returns a human-readable identifier for the output,
	// used in log messages and metrics labels.
	Name() string
}

// DestinationKeyer is an optional interface that [Output] implementations
// MAY satisfy to enable duplicate destination detection at construction
// time. When two outputs return the same key from DestinationKey,
// [WithOutputs] and [WithNamedOutput] return an error.
//
// Returning an empty string from DestinationKey opts out of duplicate
// detection for that output.
//
// Key format conventions by output type:
//   - File: absolute filesystem path
//   - Syslog: network address (host:port)
//   - Webhook: full URL
//
// Outputs that do not implement this interface (e.g. [StdoutOutput])
// are silently skipped during destination dedup.
type DestinationKeyer interface {
	DestinationKey() string
}

// DeliveryReporter is an optional interface that [Output] implementations
// may satisfy to indicate they handle their own delivery metrics
// reporting. When satisfied and [DeliveryReporter.ReportsDelivery]
// returns true, the core auditor skips its default per-event
// [Metrics.RecordEvent] calls for that output — the output is
// responsible for calling them after actual delivery.
type DeliveryReporter interface {
	ReportsDelivery() bool
}

// EventMetadata carries per-event context for outputs that need
// structured access to framework fields (e.g., for Loki labels or
// Elasticsearch index routing). The struct is constructed once per
// delivery pass in [deliverToOutputs] and passed by value to
// [MetadataWriter.WriteWithMetadata].
//
// The struct is small (64 bytes on amd64), passed by value, and
// zero-allocation by design. All fields are read from existing local
// variables in the drain goroutine.
type EventMetadata struct { //nolint:govet // fieldalignment: readability over struct packing for a 4-field value type
	// EventType is the taxonomy event type name (e.g. "user_create").
	EventType string

	// Severity is the resolved severity (0-10) for this event.
	Severity int

	// Category is the delivery-specific category. Empty for
	// uncategorised events. When an event belongs to multiple
	// categories, each delivery pass has a different Category.
	Category string

	// Timestamp is the wall-clock time recorded at drain time.
	Timestamp time.Time
}

// MetadataWriter is an optional interface that [Output] implementations
// may satisfy to receive structured event metadata alongside
// pre-serialised bytes. When an output implements MetadataWriter,
// the library calls WriteWithMetadata instead of [Output.Write].
//
// Implementations MUST NOT retain meta or take its address after
// returning. The library passes meta by value on the stack; retaining
// it forces heap allocation. The caller must not assume the value
// remains valid after return.
type MetadataWriter interface {
	WriteWithMetadata(data []byte, meta EventMetadata) error
}

// FrameworkFieldReceiver is an optional interface that [Output]
// implementations may satisfy to receive auditor-wide framework fields
// (app_name, host, timezone, pid) at construction time. The library
// calls SetFrameworkFields once after all options are applied and
// before the first Write or WriteWithMetadata call.
//
// This is the output-side analogue of [FrameworkFieldSetter] for
// formatters. Outputs that need framework fields for labelling or
// routing (e.g., Loki stream labels) implement this interface.
// Outputs that do not implement it are silently skipped.
type FrameworkFieldReceiver interface {
	SetFrameworkFields(appName, host, timezone string, pid int)
}

// DiagnosticLoggerReceiver is an optional interface that [Output] implementations
// may satisfy to receive the library's [log/slog.Logger] for diagnostic
// output. The library calls SetDiagnosticLogger once after all options are applied.
// Outputs that do not implement it use the package-level [slog.Default].
type DiagnosticLoggerReceiver interface {
	SetDiagnosticLogger(l *slog.Logger)
}

// OutputMetricsReceiver is an optional interface that [Output]
// implementations may satisfy to receive per-output metrics. The
// library calls SetOutputMetrics once after construction, before the
// first Write call. Outputs that do not implement it operate without
// per-output metrics.
//
// This is the output-side analogue of [DiagnosticLoggerReceiver] and
// [FrameworkFieldReceiver]. The [OutputMetrics] value is created by
// the [OutputMetricsFactory] registered via
// outputconfig.WithOutputMetrics.
type OutputMetricsReceiver interface {
	SetOutputMetrics(m OutputMetrics)
}

// MaxOutputNameLength is the maximum allowed length for an output name.
const MaxOutputNameLength = 128

// ValidateOutputName checks that an output name is safe for use in
// metric labels, log messages, and YAML keys. Returns an error if
// the name is empty, too long, starts with an underscore (reserved),
// or contains characters outside [a-zA-Z0-9_-].
//
// ValidateOutputName is called by outputconfig.Load for YAML-sourced
// output names. Programmatic names (via [WithNamedOutput]) are not
// validated because auto-generated names may contain characters
// outside the YAML-safe set (e.g. "webhook:host:port").
func ValidateOutputName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: output name must not be empty", ErrConfigInvalid)
	}
	if len(name) > MaxOutputNameLength {
		return fmt.Errorf("%w: output name %q exceeds maximum length %d",
			ErrConfigInvalid, name, MaxOutputNameLength)
	}
	if name[0] == '_' {
		return fmt.Errorf("%w: output name %q must not start with underscore (reserved)",
			ErrConfigInvalid, name)
	}
	if err := validateOutputNameChars(name); err != nil {
		return err
	}
	if c := name[0]; c >= '0' && c <= '9' {
		return fmt.Errorf("%w: output name %q must start with a letter",
			ErrConfigInvalid, name)
	}
	return nil
}

// validateOutputNameChars checks that every byte in name is in the
// allowed set [a-zA-Z0-9_-].
func validateOutputNameChars(name string) error {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isValidOutputNameChar(c) {
			continue
		}
		return fmt.Errorf("%w: output name %q contains invalid character %q at position %d; "+
			"only [a-zA-Z0-9_-] are allowed", ErrConfigInvalid, name, string(c), i)
	}
	return nil
}

func isValidOutputNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '-'
}
