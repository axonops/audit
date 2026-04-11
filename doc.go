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
//   - github.com/axonops/go-audit — core (this package; depends on github.com/goccy/go-yaml for [ParseTaxonomyYAML])
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
//	taxonomy := &audit.Taxonomy{
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
//   - [NewEventKV] — creates an event from alternating key-value pairs (slog-style)
//   - [EventType] — pre-validated handle for zero-allocation audit calls; see [Logger.MustHandle]
//   - [Fields] — defined type over map[string]any with [Fields.Has], [Fields.String], [Fields.Int] accessors
//
// # Outputs
//
//   - [Output] — interface for audit event destinations (file, syslog, webhook, stdout)
//   - [Stdout] — convenience constructor for [StdoutOutput] writing to [os.Stdout]
//   - [StdoutOutput] — writes events to stdout or any io.Writer; included in core
//   - [WithOutputs] — registers unnamed outputs; [WithNamedOutput] for per-output routing
//   - [DeliveryReporter] — optional interface for outputs that handle their own delivery metrics
//   - [MetadataWriter] — optional interface for outputs that need structured per-event context (event type, severity, category, timestamp)
//   - [EventMetadata] — per-event value type passed to [MetadataWriter.WriteWithMetadata]
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
//   - [DevTaxonomy] — creates a permissive development taxonomy (not for production)
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
// # Error Discrimination
//
// Validation errors returned by [Logger.AuditEvent] wrap [ErrValidation]
// as a parent sentinel. Specific sub-sentinels identify the failure:
//
//   - [ErrUnknownEventType] — event type not in taxonomy
//   - [ErrMissingRequiredField] — required fields absent
//   - [ErrUnknownField] — unrecognised fields (strict mode only)
//
// Use [errors.Is] to match broadly or narrowly:
//
//	if errors.Is(err, audit.ErrValidation) { /* any validation failure */ }
//	if errors.Is(err, audit.ErrUnknownEventType) { /* specific case */ }
//
// Use [errors.As] to access the [ValidationError] struct:
//
//	var ve *audit.ValidationError
//	if errors.As(err, &ve) { log.Println(ve.Error()) }
//
// [ErrBufferFull] and [ErrClosed] are NOT validation errors and will
// never match [ErrValidation].
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
//   - [HMACConfig] — per-output HMAC integrity configuration
//   - [ComputeHMAC] — computes HMAC over a payload, returns lowercase hex
//   - [VerifyHMAC] — verifies an HMAC value matches a payload
//   - [ValidateHMACConfig] — validates HMAC configuration at startup
//   - [OutputOption] — per-output configuration for [WithNamedOutput]: [OutputRoute], [OutputFormatter], [OutputExcludeLabels], [OutputHMAC]
//   - [MigrateTaxonomy] — applies version migration to a [Taxonomy]
//
// # How Taxonomy Validation Works
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
// (timestamp, event_type, severity, duration_ms, event_category,
// app_name, host, timezone, pid) are never stripped.
//
// # Reserved Standard Fields
//
// The library defines 31 well-known audit field names (actor_id,
// source_ip, reason, target_id, etc.) that are always accepted without
// taxonomy declaration. These reserved standard fields have generated
// setter methods on every builder and map to standard ArcSight CEF
// extension keys. See [ReservedStandardFieldNames] for the complete list.
//
// # Framework Fields
//
// Every serialised event includes framework fields that identify
// the deployment: app_name, host, timezone (set via [WithAppName],
// [WithHost], [WithTimezone] or outputs YAML), and pid (auto-captured
// via os.Getpid). These fields cannot be stripped by sensitivity labels
// and are emitted in both JSON and CEF output.
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
