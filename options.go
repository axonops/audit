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
	"time"
)

// Option configures a [Logger] during construction via [NewLogger].
type Option func(*Logger) error

// WithTaxonomy registers the event taxonomy for validation. This option
// is required; [NewLogger] returns an error if no taxonomy is provided.
// WithTaxonomy SHOULD be called exactly once per [NewLogger] call.
// Calling it more than once replaces the taxonomy and resets all
// runtime category and event overrides established by the previous call.
//
// WithTaxonomy makes a deep copy of t; mutations to t after this call
// have no effect on the logger. When t was returned by
// [ParseTaxonomyYAML], redundant re-validation is skipped.
func WithTaxonomy(t *Taxonomy) Option {
	return func(l *Logger) error {
		if t == nil {
			return fmt.Errorf("%w: taxonomy must not be nil", ErrTaxonomyInvalid)
		}
		cp := deepCopyTaxonomy(t)
		if !cp.validated {
			if err := MigrateTaxonomy(cp); err != nil {
				return err
			}
			if err := ValidateTaxonomy(*cp); err != nil {
				return err
			}
			if err := precomputeTaxonomy(cp); err != nil {
				return err
			}
		}
		l.taxonomy = cp
		l.filter = newFilterState(cp)
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

// WithAppName sets the application name emitted as a framework field
// in every serialised event. The value must be non-empty.
func WithAppName(name string) Option {
	return func(l *Logger) error {
		if name == "" {
			return fmt.Errorf("audit: app_name must not be empty")
		}
		if len(name) > 255 {
			return fmt.Errorf("audit: app_name exceeds maximum length of 255 bytes")
		}
		l.appName = name
		return nil
	}
}

// WithHost sets the hostname emitted as a framework field in every
// serialised event. The value must be non-empty and at most 255 bytes.
func WithHost(host string) Option {
	return func(l *Logger) error {
		if host == "" {
			return fmt.Errorf("audit: host must not be empty")
		}
		if len(host) > 255 {
			return fmt.Errorf("audit: host exceeds maximum length of 255 bytes")
		}
		l.host = host
		return nil
	}
}

// WithTimezone sets the timezone name emitted as a framework field in
// every serialised event. The value must be non-empty and at most 64
// bytes. If not set, no timezone field is emitted.
func WithTimezone(tz string) Option {
	return func(l *Logger) error {
		if tz == "" {
			return fmt.Errorf("audit: timezone must not be empty")
		}
		if len(tz) > 64 {
			return fmt.Errorf("audit: timezone exceeds maximum length of 64 bytes")
		}
		l.timezone = tz
		return nil
	}
}

// WithStandardFieldDefaults sets deployment-wide default values for
// reserved standard fields. Defaults are applied in [Logger.AuditEvent]
// before validation — a default satisfies required: true constraints.
// Per-event values always override defaults (key existence check, not
// zero value). When called multiple times, the last call wins.
func WithStandardFieldDefaults(defaults map[string]string) Option {
	return func(l *Logger) error {
		for k := range defaults {
			if !IsReservedStandardField(k) {
				return fmt.Errorf("audit: standard field default key %q is not a reserved standard field", k)
			}
		}
		// Copy to prevent caller mutation after construction.
		cp := make(map[string]string, len(defaults))
		for k, v := range defaults {
			cp[k] = v
		}
		l.standardFieldDefaults = cp
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

// OutputOption configures a single output registered via
// [WithNamedOutput]. Use [OutputRoute], [OutputFormatter],
// [OutputExcludeLabels], and [OutputHMAC] to customise per-output
// behaviour.
type OutputOption func(*outputEntryBuilder)

// outputEntryBuilder accumulates per-output configuration before
// the output entry is registered on the logger.
type outputEntryBuilder struct {
	formatter     Formatter
	route         *EventRoute
	hmacConfig    *HMACConfig
	excludeLabels []string
}

// OutputRoute sets the per-output event route. The route restricts
// which events are delivered to this output. Nil means all
// globally-enabled events are delivered.
func OutputRoute(r *EventRoute) OutputOption {
	return func(b *outputEntryBuilder) {
		b.route = r
	}
}

// OutputFormatter overrides the logger's default formatter for this
// output. Nil means the logger's default formatter is used.
func OutputFormatter(f Formatter) OutputOption {
	return func(b *outputEntryBuilder) {
		b.formatter = f
	}
}

// OutputExcludeLabels specifies sensitivity labels whose fields should
// be stripped from events before delivery to this output. When
// non-empty, the taxonomy MUST define a [SensitivityConfig] and every
// label MUST be defined within it; [NewLogger] returns an error if
// either condition is violated. An empty call means no field stripping.
// Framework fields are never stripped.
func OutputExcludeLabels(labels ...string) OutputOption {
	return func(b *outputEntryBuilder) {
		b.excludeLabels = labels
	}
}

// OutputHMAC configures per-output HMAC integrity. The config is
// validated eagerly during [NewLogger] option application — invalid
// configs (short salt, unknown algorithm) cause [NewLogger] to return
// an error. Nil means no HMAC for this output.
func OutputHMAC(cfg *HMACConfig) OutputOption {
	return func(b *outputEntryBuilder) {
		b.hmacConfig = cfg
	}
}

// WithNamedOutput adds a single named output with optional per-output
// configuration. Use [OutputRoute], [OutputFormatter],
// [OutputExcludeLabels], and [OutputHMAC] to customise behaviour.
//
// WithNamedOutput MUST NOT be combined with [WithOutputs]; if
// [WithOutputs] was already applied, WithNamedOutput returns an error.
//
// Output names MUST be unique across all outputs; duplicate names
// cause [NewLogger] to return an error. Duplicate destinations are
// also detected via [DestinationKeyer]. Routes are validated against
// the taxonomy after all options have been applied.
func WithNamedOutput(output Output, opts ...OutputOption) Option {
	return func(l *Logger) error {
		if l.usedWithOutputs {
			return fmt.Errorf("audit: WithNamedOutput cannot be used with WithOutputs")
		}
		var b outputEntryBuilder
		for _, opt := range opts {
			opt(&b)
		}
		if b.hmacConfig != nil {
			if err := ValidateHMACConfig(b.hmacConfig); err != nil {
				return err
			}
		}
		return l.addNamedOutput(output, &b)
	}
}

// addNamedOutput registers a named output with dedup checking and
// optional route/formatter/exclude-label/HMAC configuration.
func (l *Logger) addNamedOutput(output Output, b *outputEntryBuilder) error {
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
		formatter: b.formatter,
	}
	if b.route != nil {
		oe.setRoute(b.route)
	}
	if len(b.excludeLabels) > 0 {
		oe.excludedLabels = buildLabelSet(b.excludeLabels)
	}
	if b.hmacConfig != nil {
		oe.hmacConfig = b.hmacConfig
	}
	l.entries = append(l.entries, oe)
	l.outputsByName[name] = oe
	return nil
}

// WithBufferSize sets the async channel capacity for the logger.
// Zero or negative values are ignored (the default of
// [DefaultBufferSize] applies). Values above [MaxBufferSize] cause
// [NewLogger] to return an error wrapping [ErrConfigInvalid].
func WithBufferSize(n int) Option {
	return func(l *Logger) error {
		l.cfg.BufferSize = n
		return nil
	}
}

// WithDrainTimeout sets the maximum time [Logger.Close] waits for
// pending events to flush. Zero or negative values are ignored (the
// default of [DefaultDrainTimeout] applies). Values above
// [MaxDrainTimeout] cause [NewLogger] to return an error wrapping
// [ErrConfigInvalid].
func WithDrainTimeout(d time.Duration) Option {
	return func(l *Logger) error {
		l.cfg.DrainTimeout = d
		return nil
	}
}

// WithValidationMode sets how [Logger.AuditEvent] handles unknown
// fields. Must be one of [ValidationStrict], [ValidationWarn], or
// [ValidationPermissive]. An invalid mode causes [NewLogger] to
// return an error wrapping [ErrConfigInvalid].
func WithValidationMode(m ValidationMode) Option {
	return func(l *Logger) error {
		l.cfg.ValidationMode = m
		return nil
	}
}

// WithOmitEmpty enables omission of empty, nil, and zero-value fields
// from serialised output. When enabled, only non-zero fields are
// serialised. Consumers operating under compliance regimes that
// require all registered fields SHOULD NOT use this option.
func WithOmitEmpty() Option {
	return func(l *Logger) error {
		l.cfg.OmitEmpty = true
		return nil
	}
}

// WithDisabled creates a no-op logger that discards all events without
// validation or delivery. [Logger.AuditEvent] returns nil immediately.
// This is the explicit opt-out for audit logging — the default is
// enabled, because silent audit disablement is worse than noisy audit
// failure.
func WithDisabled() Option {
	return func(l *Logger) error {
		l.disabled = true
		return nil
	}
}

// WithConfig applies configuration from a [Config] struct. Non-zero
// fields override the corresponding defaults. When combined with
// individual With* options, the last option applied wins.
//
// Boolean fields at their zero value (false) are indistinguishable
// from unset — use [WithOmitEmpty] or [WithDisabled] for explicit
// opt-in to boolean behaviours.
func WithConfig(cfg Config) Option {
	return func(l *Logger) error {
		if cfg.BufferSize > 0 {
			l.cfg.BufferSize = cfg.BufferSize
		}
		if cfg.DrainTimeout > 0 {
			l.cfg.DrainTimeout = cfg.DrainTimeout
		}
		if cfg.ValidationMode != "" {
			l.cfg.ValidationMode = cfg.ValidationMode
		}
		if cfg.OmitEmpty {
			l.cfg.OmitEmpty = true
		}
		return nil
	}
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
