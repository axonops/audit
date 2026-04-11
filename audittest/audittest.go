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

package audittest

import (
	"testing"

	audit "github.com/axonops/go-audit"
)

// Option configures the test logger created by [NewLogger].
type Option func(*config)

type config struct {
	extraOpts []audit.Option
}

// WithConfig applies a [audit.Config] struct to the test logger.
// Non-zero fields override the test defaults (BufferSize=100).
func WithConfig(cfg audit.Config) Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithConfig(cfg)) }
}

// WithValidationMode sets the taxonomy validation mode.
// Default is [audit.ValidationStrict].
func WithValidationMode(mode audit.ValidationMode) Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithValidationMode(mode)) }
}

// WithDisabled creates a disabled (no-op) test logger. Events are
// accepted without error but not delivered.
func WithDisabled() Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithDisabled()) }
}

// NewLogger creates a test audit logger with an in-memory [Recorder]
// and [MetricsRecorder]. The taxonomy is parsed from YAML bytes.
//
// The logger is created with sensible test defaults: Enabled=true,
// Version=1, BufferSize=100. The buffer size is intentionally small
// since the in-memory recorder has no I/O cost — large buffers only
// increase the window where events may not yet be flushed before
// assertions run. Override with [WithConfig] if needed.
// tb.Cleanup is registered to call
// logger.Close() as a safety net against goroutine leaks.
//
// Callers MUST call logger.Close() before making assertions — events
// are delivered asynchronously and are only available in the recorder
// after the drain goroutine has processed them. Close is idempotent;
// the cleanup call is harmless.
func NewLogger(tb testing.TB, taxonomyYAML []byte, opts ...Option) (*audit.Logger, *Recorder, *MetricsRecorder) {
	tb.Helper()
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		tb.Fatalf("audittest: parse taxonomy: %v", err)
	}
	return newTestLogger(tb, tax, opts...)
}

// NewLoggerQuick creates a test audit logger with a permissive
// taxonomy containing the named event types. No required fields, no
// unknown field validation. Use for tests that only care about which
// events were emitted, not about field validation.
func NewLoggerQuick(tb testing.TB, eventTypes ...string) (*audit.Logger, *Recorder, *MetricsRecorder) {
	tb.Helper()
	return newTestLogger(tb, QuickTaxonomy(eventTypes...), WithValidationMode(audit.ValidationPermissive))
}

// QuickTaxonomy builds a minimal [*audit.Taxonomy] where every listed
// event type accepts any fields. All events are in a single enabled
// category ("test"). The returned taxonomy does not enforce required
// fields; pair it with [audit.ValidationPermissive] (as [NewLoggerQuick]
// does) for fully unconstrained testing.
func QuickTaxonomy(eventTypes ...string) *audit.Taxonomy {
	events := make(map[string]*audit.EventDef, len(eventTypes))
	for _, et := range eventTypes {
		events[et] = &audit.EventDef{}
	}
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"test": {Events: eventTypes},
		},
		Events: events,
	}
}

func newTestLogger(tb testing.TB, tax *audit.Taxonomy, opts ...Option) (*audit.Logger, *Recorder, *MetricsRecorder) {
	tb.Helper()

	c := &config{}
	for _, o := range opts {
		o(c)
	}

	rec := NewRecorder()
	met := NewMetricsRecorder()

	auditOpts := []audit.Option{
		audit.WithBufferSize(100), // small buffer — recorder has no I/O cost
		audit.WithTaxonomy(tax),
		audit.WithOutputs(rec),
		audit.WithMetrics(met),
	}
	auditOpts = append(auditOpts, c.extraOpts...)

	logger, err := audit.NewLogger(auditOpts...)
	if err != nil {
		tb.Fatalf("audittest: create logger: %v", err)
	}

	tb.Cleanup(func() { _ = logger.Close() })

	return logger, rec, met
}
