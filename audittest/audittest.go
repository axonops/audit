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
	"io"
	"log/slog"
	"testing"

	"github.com/axonops/audit"
)

// Option configures the test auditor created by [New].
type Option func(*config)

type config struct {
	extraOpts []audit.Option
	async     bool // opt out of default synchronous delivery
	verbose   bool // re-enable diagnostic logs (silenced by default)
}

// WithConfig applies a [audit.Config] struct to the test auditor.
// Non-zero fields override the test defaults (QueueSize=100).
func WithConfig(cfg audit.Config) Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithConfig(cfg)) }
}

// WithValidationMode sets the taxonomy validation mode.
// Default is [audit.ValidationStrict].
func WithValidationMode(mode audit.ValidationMode) Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithValidationMode(mode)) }
}

// WithDisabled creates a disabled (no-op) test auditor. Events are
// accepted without error but not delivered.
func WithDisabled() Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithDisabled()) }
}

// WithSync creates a synchronous test auditor where events are
// available in the [Recorder] immediately after [audit.Auditor.AuditEvent]
// returns. No Close-before-assert ceremony is needed.
//
// Both [New] and [NewQuick] default to synchronous delivery,
// so this option is only needed to re-enable sync after [WithAsync].
func WithSync() Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, audit.WithSynchronousDelivery()) }
}

// WithAsync creates an asynchronous test auditor. Events are delivered
// by a background goroutine, so callers MUST call auditor.Close()
// before making assertions. Use this only when testing async-specific
// behaviour such as drain timeout or buffer backpressure.
func WithAsync() Option {
	return func(c *config) { c.async = true }
}

// WithAuditOption passes an arbitrary [audit.Option] through to the
// underlying [audit.New] call. Use for options not covered by the
// audittest.With* helpers (e.g., WithNamedOutput, WithFormatter,
// WithAppName, WithHost).
func WithAuditOption(opt audit.Option) Option {
	return func(c *config) { c.extraOpts = append(c.extraOpts, opt) }
}

// WithVerbose re-enables diagnostic log output from the auditor. By
// default, test auditors silence diagnostic logs (lifecycle messages,
// shutdown notices) to keep test output clean. Use this option when
// debugging auditor behaviour in tests.
func WithVerbose() Option {
	return func(c *config) { c.verbose = true }
}

// New creates a test auditor with an in-memory [Recorder]
// and [MetricsRecorder]. The taxonomy is parsed from YAML bytes.
//
// The auditor defaults to synchronous delivery — events are available
// in the Recorder immediately after [audit.Auditor.AuditEvent] returns,
// with no Close-before-assert ceremony needed. Use [WithAsync] to opt
// into asynchronous delivery for tests that exercise drain timeout or
// buffer backpressure.
//
// QueueSize defaults to 100 (intentionally small — the in-memory
// recorder has no I/O cost). tb.Cleanup is registered to call
// auditor.Close() as a safety net against goroutine leaks.
func New(tb testing.TB, taxonomyYAML []byte, opts ...Option) (*audit.Auditor, *Recorder, *MetricsRecorder) {
	tb.Helper()
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		tb.Fatalf("audittest: parse taxonomy: %v", err)
	}
	return newTestLogger(tb, tax, opts...)
}

// NewQuick creates a test auditor with a permissive
// taxonomy containing the named event types. No required fields, no
// unknown field validation. Defaults to synchronous delivery — events
// are available in the Recorder immediately without calling Close.
func NewQuick(tb testing.TB, eventTypes ...string) (*audit.Auditor, *Recorder, *MetricsRecorder) {
	tb.Helper()
	return newTestLogger(tb, QuickTaxonomy(eventTypes...), WithValidationMode(audit.ValidationPermissive))
}

// QuickTaxonomy builds a minimal [*audit.Taxonomy] where every listed
// event type accepts any fields. All events are in a single enabled
// category ("test"). The returned taxonomy does not enforce required
// fields; pair it with [audit.ValidationPermissive] (as [NewQuick]
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

func newTestLogger(tb testing.TB, tax *audit.Taxonomy, opts ...Option) (*audit.Auditor, *Recorder, *MetricsRecorder) {
	tb.Helper()

	c := &config{}
	for _, o := range opts {
		o(c)
	}

	rec := NewRecorder()
	met := NewMetricsRecorder()

	auditOpts := []audit.Option{
		audit.WithQueueSize(100), // small buffer — recorder has no I/O cost
		audit.WithTaxonomy(tax),
		audit.WithOutputs(rec),
		audit.WithMetrics(met),
	}
	if !c.verbose {
		auditOpts = append(auditOpts, audit.WithDiagnosticLogger(
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		))
	}
	if !c.async {
		auditOpts = append(auditOpts, audit.WithSynchronousDelivery())
	}
	auditOpts = append(auditOpts, c.extraOpts...)

	auditor, err := audit.New(auditOpts...)
	if err != nil {
		tb.Fatalf("audittest: create auditor: %v", err)
	}

	tb.Cleanup(func() { _ = auditor.Close() })

	return auditor, rec, met
}
