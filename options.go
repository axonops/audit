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

// Option configures a [Logger] during construction via [NewLogger].
type Option func(*Logger) error

// WithTaxonomy registers the event taxonomy for validation. This option
// is required; [NewLogger] returns an error if no taxonomy is provided.
//
// The taxonomy is validated at startup. Lifecycle events (startup and
// shutdown) are injected automatically if not already present.
func WithTaxonomy(t Taxonomy) Option {
	return func(l *Logger) error {
		injectLifecycleEvents(&t)
		if err := migrateTaxonomy(&t); err != nil {
			return err
		}
		if err := validateTaxonomy(t); err != nil {
			return err
		}
		l.taxonomy = &t
		l.filter = newFilterState(&t)
		return nil
	}
}

// WithMetrics sets the metrics recorder for the logger. If m is nil,
// or if WithMetrics is not called, metrics are silently discarded.
// Implementations MUST be safe for concurrent calls from the drain
// goroutine.
func WithMetrics(m Metrics) Option {
	return func(l *Logger) error {
		l.metrics = m
		return nil
	}
}

// WithOutputs sets the output destinations for the logger. Events are
// fanned out to all provided outputs. If no outputs are configured,
// events are validated and filtered but silently discarded. This is
// useful for testing but SHOULD NOT be used in production.
func WithOutputs(outputs ...Output) Option {
	return func(l *Logger) error {
		l.outputs = outputs
		return nil
	}
}
