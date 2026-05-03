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

package syslog

import (
	"log/slog"

	"github.com/axonops/audit"
)

// Option configures a syslog [Output] at construction time. Options
// are passed as variadic arguments to [New] and applied in order
// before any configuration validation, TLS setup, or warning emission.
type Option func(*options)

// options holds resolved construction-time settings. Zero value is
// valid — all fields receive sensible defaults inside [New].
type options struct {
	logger        *slog.Logger
	outputMetrics audit.OutputMetrics
}

// WithDiagnosticLogger routes construction-time and runtime warnings
// (TLS policy, reconnection backoff, buffer-full drops) to the given
// logger. When nil or not supplied, warnings go to [slog.Default].
//
// Consumers normally do not call this directly when using
// [github.com/axonops/audit/outputconfig.Load] — outputconfig plumbs
// the auditor's diagnostic logger into every output it constructs.
// Use this option when constructing a syslog output programmatically
// and you want its warnings to match your application's log handler.
//
// The option mirrors [github.com/axonops/audit.WithDiagnosticLogger]
// at the auditor level; the same logger may be passed to both for
// consistent routing.
func WithDiagnosticLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithOutputMetrics sets the [audit.OutputMetrics] sink for this
// output. When omitted or nil, metrics calls become no-ops via
// [audit.NoOpOutputMetrics]. Mirrors [WithDiagnosticLogger] in usage
// and zero-value semantics.
//
// If the supplied value also implements [ReconnectRecorder],
// reconnection telemetry is wired in automatically (structural
// typing — see [net/http.Flusher] precedent).
//
// Consumers normally do not call this directly when using
// [github.com/axonops/audit/outputconfig.Load] — outputconfig wires
// per-output metrics through the [audit.OutputMetricsFactory]
// supplied via outputconfig.WithOutputMetricsFactory.
func WithOutputMetrics(m audit.OutputMetrics) Option {
	return func(o *options) {
		if m == nil {
			m = audit.NoOpOutputMetrics{}
		}
		o.outputMetrics = m
	}
}

// resolveOptions applies the given options over a defaulted value.
// A nil logger (either absent or explicitly WithDiagnosticLogger(nil))
// falls back to [slog.Default]. A nil outputMetrics falls back to
// [audit.NoOpOutputMetrics].
func resolveOptions(opts []Option) options {
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	if o.outputMetrics == nil {
		o.outputMetrics = audit.NoOpOutputMetrics{}
	}
	return o
}
