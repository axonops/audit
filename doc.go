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
//
// [StdoutOutput] ships with core and requires no additional import.
//
// # Stability
//
// This package is pre-release (v0.x). The API is not yet stable; breaking
// changes may occur between minor versions until v1.0.0 is released.
//
// # Quick Start
//
// Define a taxonomy describing your event types, then create a logger:
//
//	taxonomy := audit.Taxonomy{
//	    Version: 1,
//	    Categories: map[string][]string{
//	        "write":    {"user_create", "user_delete"},
//	        "security": {"auth_failure"},
//	    },
//	    Events: map[string]audit.EventDef{
//	        "user_create":  {Category: "write", Required: []string{"outcome", "actor_id"}},
//	        "user_delete":  {Category: "write", Required: []string{"outcome", "actor_id"}},
//	        "auth_failure": {Category: "security", Required: []string{"outcome", "actor_id"}},
//	    },
//	    DefaultEnabled: []string{"write", "security"},
//	}
//
//	logger, err := audit.NewLogger(
//	    audit.Config{Version: 1, Enabled: true},
//	    audit.WithTaxonomy(taxonomy),
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
//	if err := logger.Audit("user_create", audit.Fields{
//	    "outcome":  "success",
//	    "actor_id": "alice",
//	}); err != nil {
//	    log.Printf("audit: %v", err)
//	}
//
// # Key Types
//
//   - [Logger] — core audit logger; created via [NewLogger]
//   - [Taxonomy] — consumer-defined event schema; registered via [WithTaxonomy]
//   - [EventDef] — definition of a single event type's fields
//   - [Config] — logger configuration (buffer size, drain timeout, validation mode)
//   - [Output] — interface for audit event destinations
//   - [DeliveryReporter] — optional interface for outputs that handle their own delivery metrics
//   - [EventType] — handle for zero-allocation audit calls; see [Logger.MustHandle]
//   - [Formatter] — interface for custom serialisation; see [WithFormatter]
//   - [JSONFormatter] — default formatter; line-delimited JSON with deterministic field order
//   - [CEFFormatter] — Common Event Format formatter for SIEM integration
//   - [TLSPolicy] — shared TLS version and cipher suite policy for outputs; see [TLSPolicy.Apply]
//   - [EventRoute] — per-output event filter (include/exclude modes); see [WithNamedOutput]
//   - [Middleware] — router-agnostic HTTP middleware; captures transport metadata automatically
//   - [Hints] — per-request mutable audit metadata; populated by handlers via [HintsFromContext]
//   - [TransportMetadata] — HTTP transport fields captured by the middleware
//   - [EventBuilder] — callback that transforms hints + transport into an audit event
//   - [Metrics] — optional core instrumentation interface
//   - [ParseTaxonomyYAML] — parses a YAML document into a [Taxonomy]; use with //go:embed
//   - [ErrInvalidInput] — sentinel for YAML structural errors (vs [ErrTaxonomyInvalid] for semantic errors)
//   - [ValidateTaxonomy] — validates a [Taxonomy] for internal consistency
//   - [InjectLifecycleEvents] — adds the "lifecycle" category with startup/shutdown events
//   - [MigrateTaxonomy] — applies version migration to a [Taxonomy]
//
// # Taxonomy
//
// The framework does not hardcode event types, field names, or categories.
// Consumers register their entire audit taxonomy at bootstrap via
// [WithTaxonomy]. The framework then validates every [Logger.Audit] call
// against the registered definitions, catching missing required fields,
// unknown event types, and unrecognised field names at runtime.
//
// # Async Delivery
//
// Events are enqueued to a buffered channel (configurable capacity, default
// 10,000) and drained by a single background goroutine. If the buffer is
// full, [Logger.Audit] returns [ErrBufferFull] and the drop is recorded via
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
