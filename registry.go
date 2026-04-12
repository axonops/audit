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
	"log/slog"
	"slices"
	"sync"
)

// OutputFactory creates a named [Output] from raw YAML configuration
// bytes and core pipeline metrics.
//
// name is the consumer-chosen output name from the YAML config (e.g.
// "compliance_file"). The factory SHOULD use this to set the output's
// identity via [WrapOutput] or equivalent.
//
// rawConfig is the YAML bytes of the type-specific configuration block
// (e.g. the content under the "file:" key). The factory MUST NOT
// retain rawConfig after returning.
//
// coreMetrics is the logger-level [Metrics] recorder (may be nil).
// Forwarded to outputs that need it (e.g. webhook for delivery
// reporting). Per-output-type metrics (e.g. file rotation, syslog
// reconnection) are NOT passed through this signature — they are
// captured in the factory closure at registration time.
type OutputFactory func(name string, rawConfig []byte, coreMetrics Metrics) (Output, error)

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
// RegisterOutputFactory panics if typeName is empty or factory is nil.
// These are programming errors that should be caught at startup.
func RegisterOutputFactory(typeName string, factory OutputFactory) {
	if typeName == "" {
		panic("audit: RegisterOutputFactory called with empty type name")
	}
	if factory == nil {
		panic("audit: RegisterOutputFactory called with nil factory")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[typeName] = factory
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
// interfaces so the wrapper is transparent to the core logger.
var (
	_ MetadataWriter         = (*namedOutput)(nil)
	_ FrameworkFieldReceiver = (*namedOutput)(nil)
	_ LoggerReceiver         = (*namedOutput)(nil)
)

// namedOutput wraps an [Output] to override its [Output.Name] method
// with a consumer-chosen name from the YAML config. All other methods
// delegate to the inner output, including optional interfaces
// ([MetadataWriter], [FrameworkFieldReceiver], [LoggerReceiver],
// [DestinationKeyer], [DeliveryReporter]).
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
// [DeliveryReporter]. This ensures the core logger correctly skips
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

// SetLogger forwards to the inner output if it implements
// [LoggerReceiver]. This ensures the library's diagnostic logger
// propagates through the name wrapper to outputs created via YAML
// config.
func (n *namedOutput) SetLogger(l *slog.Logger) {
	if lr, ok := n.Output.(LoggerReceiver); ok {
		lr.SetLogger(l)
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
// and [LoggerReceiver] regardless of the inner output. When the inner
// output does not implement these interfaces, the wrapper returns
// zero-value behaviour: empty string for DestinationKey, false for
// ReportsDelivery, delegation to Write for WriteWithMetadata, and
// no-op for SetFrameworkFields and SetLogger.
func WrapOutput(inner Output, name string) Output {
	return &namedOutput{Output: inner, outputName: name}
}
