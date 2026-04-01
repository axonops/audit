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

import "fmt"

// Option configures a [Logger] during construction via [NewLogger].
type Option func(*Logger) error

// WithTaxonomy registers the event taxonomy for validation. This option
// is required; [NewLogger] returns an error if no taxonomy is provided.
// WithTaxonomy SHOULD be called exactly once per [NewLogger] call.
// Calling it more than once replaces the taxonomy and resets all
// runtime category and event overrides established by the previous call.
//
// The taxonomy is validated and pre-computed at construction time.
func WithTaxonomy(t Taxonomy) Option {
	return func(l *Logger) error {
		if err := MigrateTaxonomy(&t); err != nil {
			return err
		}
		if err := ValidateTaxonomy(t); err != nil {
			return err
		}
		precomputeTaxonomy(&t)
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

// WithFormatter sets the event serialisation formatter. If not
// provided, a [JSONFormatter] is created from the [Config]. Use this
// to configure a [CEFFormatter] or a custom [Formatter] implementation.
func WithFormatter(f Formatter) Option {
	return func(l *Logger) error {
		if f == nil {
			return fmt.Errorf("audit: formatter must not be nil")
		}
		l.formatter = f
		return nil
	}
}

// WithOutputs sets the output destinations for the logger. Events are
// fanned out to all provided outputs. Each output receives all
// globally-enabled events (no per-output filtering). Use
// [WithNamedOutput] to configure per-output event routes or formatters.
//
// WithOutputs MUST NOT be combined with [WithNamedOutput]; mixing the
// two returns an error. Duplicate output destinations are also
// detected: if two outputs implement [DestinationKeyer] and return
// the same key, WithOutputs returns an error. If no outputs are
// configured, events are validated and filtered but silently discarded.
func WithOutputs(outputs ...Output) Option {
	return func(l *Logger) error {
		if len(l.entries) > 0 {
			return fmt.Errorf("audit: WithOutputs cannot be used with WithNamedOutput")
		}
		byName := make(map[string]*outputEntry, len(outputs))
		byDest := make(map[string]string) // destination key → output name
		entries := make([]*outputEntry, len(outputs))
		for i, o := range outputs {
			name := o.Name()
			if _, dup := byName[name]; dup {
				return fmt.Errorf("audit: duplicate output name %q", name)
			}
			if err := checkDestinationDup(o, name, byDest); err != nil {
				return err
			}
			oe := &outputEntry{output: o}
			entries[i] = oe
			byName[name] = oe
		}
		l.entries = entries
		l.outputsByName = byName
		l.usedWithOutputs = true
		return nil
	}
}

// WithNamedOutput adds a single named output with an optional
// [EventRoute] and per-output [Formatter]. The route restricts which
// events are delivered to this output. If formatter is nil, the
// logger's default formatter is used.
//
// excludeLabels specifies sensitivity labels whose fields should be
// stripped from events before delivery to this output. When non-empty,
// the taxonomy MUST define a [SensitivityConfig] and every label in
// excludeLabels MUST be defined within it; [NewLogger] returns an
// error if either condition is violated. An empty slice means no
// field stripping — the output receives all fields. Framework fields
// (timestamp, event_type, severity, duration_ms) are never stripped.
//
// WithNamedOutput MUST NOT be combined with [WithOutputs]; if
// [WithOutputs] was already applied, WithNamedOutput returns an error.
//
// Output names MUST be unique across all outputs; duplicate names
// cause [NewLogger] to return an error. Duplicate destinations are
// also detected via [DestinationKeyer]. Routes are validated against
// the taxonomy after all options have been applied.
func WithNamedOutput(output Output, route *EventRoute, formatter Formatter, excludeLabels ...string) Option {
	return func(l *Logger) error {
		if l.usedWithOutputs {
			return fmt.Errorf("audit: WithNamedOutput cannot be used with WithOutputs")
		}
		return l.addNamedOutput(output, route, formatter, excludeLabels)
	}
}

// addNamedOutput registers a named output with dedup checking and
// optional route/formatter/exclude-label configuration.
func (l *Logger) addNamedOutput(output Output, route *EventRoute, formatter Formatter, excludeLabels []string) error {
	name := output.Name()
	if l.outputsByName == nil {
		l.outputsByName = make(map[string]*outputEntry)
	}
	if l.destKeys == nil {
		l.destKeys = make(map[string]string)
	}
	if _, dup := l.outputsByName[name]; dup {
		return fmt.Errorf("audit: duplicate output name %q", name)
	}
	if err := checkDestinationDup(output, name, l.destKeys); err != nil {
		return err
	}
	oe := &outputEntry{
		output:    output,
		formatter: formatter,
	}
	if route != nil {
		oe.setRoute(route)
	}
	if len(excludeLabels) > 0 {
		oe.excludedLabels = buildLabelSet(excludeLabels)
	}
	l.entries = append(l.entries, oe)
	l.outputsByName[name] = oe
	return nil
}

// buildLabelSet converts a slice of label names to a set.
func buildLabelSet(labels []string) map[string]struct{} {
	m := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		m[l] = struct{}{}
	}
	return m
}

// checkDestinationDup checks whether the output's destination key
// collides with a previously registered output. If the output does not
// implement [DestinationKeyer], the check is skipped. On collision,
// returns an error naming both outputs and the conflicting key.
func checkDestinationDup(o Output, name string, seen map[string]string) error {
	dk, ok := o.(DestinationKeyer)
	if !ok {
		return nil
	}
	key := dk.DestinationKey()
	if key == "" {
		return nil
	}
	if existing, dup := seen[key]; dup {
		return fmt.Errorf("%w: outputs %q and %q share %q", ErrDuplicateDestination, existing, name, key)
	}
	seen[key] = name
	return nil
}
