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
	"slices"
	"sync"
)

// OutputFactory creates a named [Output] from raw YAML configuration
// bytes, core pipeline metrics, and an optional diagnostic logger.
//
// name is the consumer-chosen output name from the YAML config (e.g.
// "compliance_file"). The factory SHOULD use this to set the output's
// identity via [WrapOutput] or equivalent.
//
// rawConfig is the YAML bytes of the type-specific configuration block
// (e.g. the content under the "file:" key). The factory MUST NOT
// retain rawConfig after returning.
//
// coreMetrics is the auditor-level [Metrics] recorder (may be nil).
// Forwarded to outputs that need it (e.g. webhook for delivery
// reporting). Per-output-type metrics are auto-detected via type
// assertion: if coreMetrics satisfies the output's specific Metrics
// interface (e.g. file.Metrics, syslog.Metrics), the output receives
// per-output metrics automatically. For separate per-output metrics
// implementations, use the output's NewFactory with
// outputconfig.WithFactory.
//
// logger is the auditor's diagnostic logger, plumbed through from
// [outputconfig.WithDiagnosticLogger] or [audit.WithDiagnosticLogger]
// so that construction-time warnings (TLS policy, file permission
// mode) reach the consumer's configured handler. Factories SHOULD
// pass it via the output module's WithDiagnosticLogger option. A nil
// logger is valid and is treated as [slog.Default].
//
// fctx is the auditor-wide framework context ([FrameworkContext]),
// plumbed through from [outputconfig.WithFrameworkContext]. Factories
// SHOULD pass it to the output module's New constructor so that
// construction-time cascades (syslog RFC 5424 APP-NAME defaulting from
// the top-level app_name, etc.) apply to the first connection / first
// request. The zero value is valid and disables the cascade; outputs
// then fall back to their own defaults (#583).
type OutputFactory func(name string, rawConfig []byte, coreMetrics Metrics, logger *slog.Logger, fctx FrameworkContext) (Output, error)

// registry is a global mutable map protected by registryMu. This is an
// intentional exception to the "no global mutable state" convention in
// CLAUDE.md — output factory registration via init() is a standard Go
// idiom (database/sql, image, encoding) and is the only practical
// pattern for compile-time output plugin discovery.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]OutputFactory)
)

// RegisterOutputFactory registers a factory for the given output type
// name (e.g. "file", "syslog", "webhook"). It is intended to be
// called from init() functions in output modules.
//
// Registering the same name twice overwrites the previous factory.
// This allows consumers to replace init()-registered default factories
// with metrics-aware factories before calling the config loader.
//
// RegisterOutputFactory returns an error wrapping [ErrValidation] if
// typeName is empty or factory is nil. These are programming errors;
// callers in init() SHOULD panic on a non-nil return so the
// programmer error surfaces at startup:
//
//	func init() {
//	    if err := audit.RegisterOutputFactory("mine", mineFactory); err != nil {
//	        panic("audit/mine: register: " + err.Error())
//	    }
//	}
//
// Prior to #590 this function panicked directly; the signature change
// removes the last library-boundary panic in the public API.
func RegisterOutputFactory(typeName string, factory OutputFactory) error {
	if typeName == "" {
		return fmt.Errorf("%w: RegisterOutputFactory called with empty type name", ErrValidation)
	}
	if factory == nil {
		return fmt.Errorf("%w: RegisterOutputFactory called with nil factory for type %q", ErrValidation, typeName)
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[typeName] = factory
	return nil
}

// MustRegisterOutputFactory is like [RegisterOutputFactory] but
// panics if typeName is empty or factory is nil. Intended for init()
// call sites where the inputs are literal and a programmer error
// should crash at startup. Mirrors [regexp.MustCompile] /
// [template.Must] — the canonical Go pattern.
//
//	func init() {
//	    audit.MustRegisterOutputFactory("mine", mineFactory)
//	}
func MustRegisterOutputFactory(typeName string, factory OutputFactory) {
	if err := RegisterOutputFactory(typeName, factory); err != nil {
		// err.Error() already starts with "audit: " via the wrapped
		// ErrValidation sentinel — no second prefix needed.
		panic(err.Error())
	}
}

// LookupOutputFactory returns the registered factory for the given
// type name, or nil if no factory has been registered for that type.
func LookupOutputFactory(typeName string) OutputFactory {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[typeName]
}

// RegisteredOutputTypes returns a sorted list of all registered output
// type names. Useful for error messages suggesting available types.
func RegisteredOutputTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	types := make([]string, 0, len(registry))
	for name := range registry {
		types = append(types, name)
	}
	slices.Sort(types)
	return types
}

// Compile-time assertions: namedOutput satisfies all optional output
// interfaces so the wrapper is transparent to the core auditor.
var (
	_ MetadataWriter           = (*namedOutput)(nil)
	_ FrameworkFieldReceiver   = (*namedOutput)(nil)
	_ DiagnosticLoggerReceiver = (*namedOutput)(nil)
	_ OutputMetricsReceiver    = (*namedOutput)(nil)
)

// namedOutput wraps an [Output] to override its [Output.Name] method
// with a consumer-chosen name from the YAML config. All other methods
// delegate to the inner output, including optional interfaces
// ([MetadataWriter], [FrameworkFieldReceiver], [DiagnosticLoggerReceiver],
// [OutputMetricsReceiver], [DestinationKeyer], [DeliveryReporter]).
type namedOutput struct {
	Output
	outputName string
}

// Name returns the consumer-chosen output name from the YAML config,
// overriding the inner output's auto-generated name.
func (n *namedOutput) Name() string { return n.outputName }

// DestinationKey forwards to the inner output if it implements
// [DestinationKeyer]. This ensures destination collision detection
// works correctly even with the name wrapper.
func (n *namedOutput) DestinationKey() string {
	if dk, ok := n.Output.(DestinationKeyer); ok {
		return dk.DestinationKey()
	}
	return ""
}

// ReportsDelivery forwards to the inner output if it implements
// [DeliveryReporter]. This ensures the core auditor correctly skips
// per-event metrics for self-reporting outputs like webhook.
func (n *namedOutput) ReportsDelivery() bool {
	if dr, ok := n.Output.(DeliveryReporter); ok {
		return dr.ReportsDelivery()
	}
	return false
}

// WriteWithMetadata forwards to the inner output if it implements
// [MetadataWriter]. This preserves per-event metadata (severity,
// category, timestamp) for outputs like syslog that map audit
// severity to protocol-level severity. When the inner output does
// not implement MetadataWriter, the call falls back to plain Write.
func (n *namedOutput) WriteWithMetadata(data []byte, meta EventMetadata) error {
	if mw, ok := n.Output.(MetadataWriter); ok {
		return mw.WriteWithMetadata(data, meta) //nolint:wrapcheck // transparent proxy
	}
	return n.Write(data)
}

// SetFrameworkFields forwards to the inner output if it implements
// [FrameworkFieldReceiver]. This preserves framework field injection
// for outputs like Loki that use app_name, host, timezone, and pid
// as stream labels.
func (n *namedOutput) SetFrameworkFields(appName, host, timezone string, pid int) {
	if fr, ok := n.Output.(FrameworkFieldReceiver); ok {
		fr.SetFrameworkFields(appName, host, timezone, pid)
	}
}

// SetDiagnosticLogger forwards to the inner output if it implements
// [DiagnosticLoggerReceiver]. This ensures the library's diagnostic logger
// propagates through the name wrapper to outputs created via YAML
// config.
func (n *namedOutput) SetDiagnosticLogger(l *slog.Logger) {
	if lr, ok := n.Output.(DiagnosticLoggerReceiver); ok {
		lr.SetDiagnosticLogger(l)
	}
}

// SetOutputMetrics forwards to the inner output if it implements
// [OutputMetricsReceiver]. This ensures per-output metrics propagate
// through the name wrapper to outputs created via YAML config.
func (n *namedOutput) SetOutputMetrics(m OutputMetrics) {
	if omr, ok := n.Output.(OutputMetricsReceiver); ok {
		omr.SetOutputMetrics(m)
	}
}

// WrapOutput wraps an [Output] with a consumer-chosen name. The
// returned output delegates all methods to the inner output except
// [Output.Name], which returns the provided name. This function is
// for [OutputFactory] implementors — regular consumers use
// [WithOutputs] or [WithNamedOutput] directly.
//
// The returned output always satisfies [DestinationKeyer],
// [DeliveryReporter], [MetadataWriter], [FrameworkFieldReceiver],
// [DiagnosticLoggerReceiver], and [OutputMetricsReceiver] regardless of the
// inner output. When the inner
// output does not implement these interfaces, the wrapper returns
// zero-value behaviour: empty string for DestinationKey, false for
// ReportsDelivery, delegation to Write for WriteWithMetadata, and
// no-op for SetFrameworkFields and SetDiagnosticLogger.
func WrapOutput(inner Output, name string) Output {
	return &namedOutput{Output: inner, outputName: name}
}
