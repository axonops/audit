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

// Package audit provides a standalone, taxonomy-driven audit logging framework
// for Go applications.
//
// The library validates every audit event against a consumer-defined taxonomy,
// delivers events asynchronously via a buffered channel, and fans out to
// multiple configurable outputs.
//
// # Multi-Module Structure
//
// Output backends live in separate Go modules so consumers import only
// what they need:
//
//   - github.com/axonops/go-audit — core (this package; depends on gopkg.in/yaml.v3 for [ParseTaxonomyYAML])
//   - github.com/axonops/go-audit/file — file output with rotation
//   - github.com/axonops/go-audit/syslog — RFC 5424 syslog (TCP/UDP/TLS)
//   - github.com/axonops/go-audit/webhook — batched HTTP webhook
//   - github.com/axonops/go-audit/outputconfig — YAML-based output configuration
//
// [StdoutOutput] and the audittest package ship with core and require
// no additional import.
//
// # Stability
//
// This package is pre-release (v0.x). The API is not yet stable; breaking
// changes may occur between minor versions until v1.0.0 is released.
//
// # Quick Start
//
// Define a taxonomy describing your event types, create a logger with
// a stdout output, and emit an event:
//
//	taxonomy := audit.Taxonomy{
//	    Version: 1,
//	    Categories: map[string]*audit.CategoryDef{
//	        "write": {Events: []string{"user_create"}},
//	    },
//	    Events: map[string]*audit.EventDef{
//	        "user_create": {Required: []string{"outcome", "actor_id"}},
//	    },
//	}
//
//	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	logger, err := audit.NewLogger(
//	    audit.Config{Version: 1, Enabled: true},
//	    audit.WithTaxonomy(taxonomy),
//	    audit.WithOutputs(stdout),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer func() {
//	    if err := logger.Close(); err != nil {
//	        log.Printf("audit close: %v", err)
//	    }
//	}()
//
//	// This prints a JSON line to stdout:
//	if err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
//	    "outcome":  "success",
//	    "actor_id": "alice",
//	})); err != nil {
//	    log.Printf("audit: %v", err)
//	}
//
// # Core API
//
//   - [Logger] — core audit logger; created via [NewLogger]
//   - [Config] — logger configuration (buffer size, drain timeout, validation mode)
//   - [Option] — functional option for [NewLogger]: [WithTaxonomy], [WithOutputs], [WithFormatter], [WithMetrics]
//
// # Events
//
//   - [Event] — interface for typed audit events; pass to [Logger.AuditEvent]
//   - [NewEvent] — creates an event for dynamic use without code generation
//   - [EventType] — pre-validated handle for zero-allocation audit calls; see [Logger.MustHandle]
//   - [Fields] — type alias for map[string]any
//
// # Outputs
//
//   - [Output] — interface for audit event destinations (file, syslog, webhook, stdout)
//   - [StdoutOutput] — writes events to stdout or any io.Writer; included in core
//   - [WithOutputs] — registers unnamed outputs; [WithNamedOutput] for per-output routing
//   - [DeliveryReporter] — optional interface for outputs that handle their own delivery metrics
//
// # Formatters
//
//   - [Formatter] — interface for event serialisation
//   - [JSONFormatter] — default; line-delimited JSON with deterministic field order
//   - [CEFFormatter] — Common Event Format for SIEM integration (Splunk, ArcSight, QRadar)
//   - [FormatOptions] — per-output context for sensitivity label exclusion
//
// # Taxonomy
//
//   - [Taxonomy] — consumer-defined event schema; registered via [WithTaxonomy]
//   - [EventDef] — definition of a single event type's required and optional fields
//   - [CategoryDef] — category grouping with optional default severity
//   - [ParseTaxonomyYAML] — parses a YAML document into a [Taxonomy]; use with //go:embed
//   - [ValidateTaxonomy] — validates a [Taxonomy] for internal consistency
//   - [SensitivityConfig] — sensitivity label definitions for field classification
//   - [SensitivityLabel] — a single label with global field mappings and regex patterns
//
// # Event Routing
//
//   - [EventRoute] — per-output event filter (include/exclude categories, severity range)
//   - [ValidateEventRoute] — validates route configuration against a taxonomy
//   - [MatchesRoute] — checks whether an event matches a route filter
//
// # HTTP Middleware
//
//   - [Middleware] — wraps an HTTP handler to capture request metadata for audit logging
//   - [Hints] — per-request audit metadata populated by handlers via [HintsFromContext]
//   - [TransportMetadata] — auto-captured HTTP fields (client IP, method, status code, duration)
//   - [EventBuilder] — callback that transforms hints + transport into an audit event
//
// # Metrics
//
//   - [Metrics] — optional instrumentation interface; track deliveries, drops, and errors
//
// # Code Generation Support
//
//   - [LabelInfo] — sensitivity label descriptor; embedded in [FieldInfo]
//   - [FieldInfo] — field descriptor with name, required flag, and labels; returned by generated builders
//   - [CategoryInfo] — category descriptor with name and optional severity; returned by generated builders
//
// # Advanced
//
//   - [OutputFactory] — function signature for output factory registration
//   - [RegisterOutputFactory] — registers a factory by type name (used by output modules)
//   - [LookupOutputFactory] — retrieves a registered factory by type name
//   - [TLSPolicy] — shared TLS version and cipher suite policy for outputs
//   - [InjectLifecycleEvents] — adds startup/shutdown events to a taxonomy
//   - [MigrateTaxonomy] — applies version migration to a [Taxonomy]
//
// # Taxonomy
//
// The framework does not hardcode event types, field names, or categories.
// Consumers register their entire audit taxonomy at bootstrap via
// [WithTaxonomy]. The framework then validates every [Logger.AuditEvent] call
// against the registered definitions, catching missing required fields,
// unknown event types, and unrecognised field names at runtime.
//
// # Sensitivity Labels
//
// Consumers MAY define sensitivity labels in [SensitivityConfig] to classify
// fields (e.g., "pii", "financial"). Labels are assigned to fields via three
// mechanisms: explicit per-event annotation in the YAML fields: map, global
// field name mapping in [SensitivityLabel.Fields], and regex patterns in
// [SensitivityLabel.Patterns]. Per-output field stripping is configured via
// [WithNamedOutput] using the excludeLabels parameter. Framework fields
// (timestamp, event_type, severity, duration_ms) are never stripped.
//
// # Async Delivery
//
// Events are enqueued to a buffered channel (configurable capacity, default
// 10,000) and drained by a single background goroutine. If the buffer is
// full, [Logger.AuditEvent] returns [ErrBufferFull] and the drop is recorded via
// the [Metrics] interface.
//
// # Graceful Shutdown
//
// [Logger.Close] MUST be called when the logger is no longer needed. Failing
// to call Close leaks the drain goroutine and causes any buffered events to be
// lost. Close signals the drain goroutine to stop, waits up to
// [Config.DrainTimeout] for pending events to flush, then closes all outputs
// in sequence. Events still in the buffer when DrainTimeout expires are lost;
// a warning is emitted via [log/slog]. Close is idempotent via [sync.Once].
package audit
