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
	extraOpts     []audit.Option
	excludeLabels []excludeLabelsEntry
	async         bool // opt out of default synchronous delivery
	verbose       bool // re-enable diagnostic logs (silenced by default)
}

// excludeLabelsEntry records a single [WithExcludeLabels] call so the
// labels can be applied to the recorder via [audit.WithNamedOutput]
// inside [newTestLogger].
type excludeLabelsEntry struct {
	outputName string
	labels     []string
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

// WithExcludeLabels applies sensitivity-label exclusion to the test
// [Recorder], mirroring [audit.WithExcludeLabels] on a named output.
// Fields whose taxonomy labels match any of the given labels are
// stripped before delivery to the recorder.
//
// Use this to unit-test compliance workflows — e.g., verify that a
// "pii"-labelled field does not appear in an output configured for
// an external analytics pipeline. The taxonomy passed to [New] MUST
// define a sensitivity section covering every label, else [audit.New]
// returns an error and the test fails at construction.
//
// outputName MUST match the recorder's name — "recorder" by default,
// or whatever was passed to [NewNamedRecorder]. The parameter is
// explicit for symmetry with [audit.WithNamedOutput] and to leave
// room for future multi-output audittest expansion. A mismatch causes
// [New] / [NewQuick] to call tb.Fatalf.
//
// Multiple calls accumulate: WithExcludeLabels("recorder", "pii"),
// WithExcludeLabels("recorder", "financial") strips both. Passing no
// labels (WithExcludeLabels("recorder")) is a no-op at the strip
// level — it still engages the named-output plumbing branch but
// no fields are stripped. Framework fields are never stripped, per
// [audit.WithExcludeLabels].
func WithExcludeLabels(outputName string, labels ...string) Option {
	return func(c *config) {
		c.excludeLabels = append(c.excludeLabels, excludeLabelsEntry{
			outputName: outputName,
			labels:     labels,
		})
	}
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
		audit.WithMetrics(met),
	}

	// Wire the recorder. When any per-output option is present (e.g.
	// WithExcludeLabels), we must use audit.WithNamedOutput — the two
	// ways of registering outputs are mutually exclusive. Otherwise,
	// audit.WithOutputs stays the path to preserve observable parity
	// with callers that never touch per-output options.
	if len(c.excludeLabels) > 0 {
		var labels []string
		for _, el := range c.excludeLabels {
			if el.outputName != rec.Name() {
				// Fatalf on a real *testing.T performs runtime.Goexit so
				// execution halts here; tb implementations that do not
				// Goexit will fall through. Return explicitly to avoid
				// partial registration under those TBs.
				tb.Fatalf("audittest: WithExcludeLabels targets output %q but the test recorder is named %q",
					el.outputName, rec.Name())
				return nil, rec, met
			}
			labels = append(labels, el.labels...)
		}
		auditOpts = append(auditOpts, audit.WithNamedOutput(rec, audit.WithExcludeLabels(labels...)))
	} else {
		auditOpts = append(auditOpts, audit.WithOutputs(rec))
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
		// See the WithExcludeLabels Fatalf above — return explicitly so
		// non-Goexit TBs do not proceed to register Cleanup against a
		// nil auditor.
		tb.Fatalf("audittest: create auditor: %v", err)
		return nil, rec, met
	}

	tb.Cleanup(func() { _ = auditor.Close() })

	return auditor, rec, met
}
