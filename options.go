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
	"time"
)

// Option configures a [Auditor] during construction via [New].
//
// Options fall into three classes (#593 B-45):
//
//   - Required options — [New] returns a sentinel error if the
//     option is absent:
//     [WithTaxonomy] ([ErrTaxonomyRequired]),
//     [WithAppName] ([ErrAppNameRequired]),
//     [WithHost] ([ErrHostRequired]).
//     These inputs have no library-supplied default.
//
//   - Validated-on-call options — optional to call, but reject empty
//     arguments when called:
//     [WithFormatter] (nil rejected; omitting yields a default
//     [JSONFormatter]),
//     [WithTimezone] (empty rejected; omitting emits no timezone
//     framework field).
//
//   - Optional options — accept nil / unset with a documented default:
//     [WithMetrics]         — nil or unset disables metrics collection.
//     [WithDiagnosticLogger] — nil or unset uses [slog.Default].
//     [WithStandardFieldDefaults] — nil or unset uses no defaults.
//
// Remaining options configure behaviour via value types
// ([WithQueueSize], [WithShutdownTimeout], [WithValidationMode],
// [WithOmitEmpty], [WithDisabled], [WithOutputs], [WithNamedOutput],
// [WithSynchronousDelivery]) and have their own documented
// zero-value semantics.
//
// The split mirrors the [net/http] convention — [http.Client.Transport]
// is optional with [http.DefaultTransport] as the documented
// nil-default, but the Handler on [http.Server] is required.
type Option func(*Auditor) error

// WithTaxonomy registers the event taxonomy for validation. This option
// is required; [New] returns an error if no taxonomy is provided.
// WithTaxonomy SHOULD be called exactly once per [New] call.
// Calling it more than once replaces the taxonomy and resets all
// runtime category and event overrides established by the previous call.
//
// WithTaxonomy makes a deep copy of t; mutations to t after this call
// have no effect on the auditor. When t was returned by
// [ParseTaxonomyYAML], redundant re-validation is skipped.
func WithTaxonomy(t *Taxonomy) Option {
	return func(a *Auditor) error {
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
		a.taxonomy = cp
		a.filter = newFilterState(cp)
		return nil
	}
}

// WithMetrics sets the metrics recorder for the auditor.
//
// Optional. If m is nil, or if WithMetrics is not called, metrics
// are silently discarded (no metrics collection). Implementations
// MUST be safe for concurrent calls from the drain goroutine.
func WithMetrics(m Metrics) Option {
	return func(a *Auditor) error {
		a.metrics = m
		return nil
	}
}

// WithAppName sets the application name emitted as a framework field
// in every serialised event.
//
// Required. [New] returns [ErrAppNameRequired] if WithAppName is
// unset (unless [WithDisabled] is also applied). The value must be
// non-empty and at most 255 bytes.
func WithAppName(name string) Option {
	return func(a *Auditor) error {
		if name == "" {
			return fmt.Errorf("audit: app_name must not be empty")
		}
		if len(name) > 255 {
			return fmt.Errorf("audit: app_name exceeds maximum length of 255 bytes")
		}
		a.appName = name
		return nil
	}
}

// WithHost sets the hostname emitted as a framework field in every
// serialised event.
//
// Required. [New] returns [ErrHostRequired] if WithHost is unset
// (unless [WithDisabled] is also applied). The value must be
// non-empty and at most 255 bytes.
func WithHost(host string) Option {
	return func(a *Auditor) error {
		if host == "" {
			return fmt.Errorf("audit: host must not be empty")
		}
		if len(host) > 255 {
			return fmt.Errorf("audit: host exceeds maximum length of 255 bytes")
		}
		a.host = host
		return nil
	}
}

// WithTimezone sets the timezone name emitted as a framework field in
// every serialised event.
//
// Optional to call; if omitted, no timezone field is emitted. If
// called, tz MUST be non-empty (the option returns an error for an
// empty string since there is no sane default to substitute at that
// point). At most 64 bytes.
func WithTimezone(tz string) Option {
	return func(a *Auditor) error {
		if tz == "" {
			return fmt.Errorf("audit: timezone must not be empty")
		}
		if len(tz) > 64 {
			return fmt.Errorf("audit: timezone exceeds maximum length of 64 bytes")
		}
		a.timezone = tz
		return nil
	}
}

// WithSynchronousDelivery configures the auditor to deliver events
// inline within [Auditor.AuditEvent] instead of via the async channel
// and drain goroutine. Events are immediately available in outputs
// after AuditEvent returns.
//
// This mode is useful for testing (no Close-before-assert ceremony)
// and for simple deployments (CLI tools, Lambda functions) where
// async complexity is unwanted. [Auditor.Close] is still safe to call
// but is not required before reading output.
func WithSynchronousDelivery() Option {
	return func(a *Auditor) error {
		a.synchronous = true
		return nil
	}
}

// WithDiagnosticLogger sets the [log/slog.Logger] used for library
// diagnostics (lifecycle messages, buffer drops, format errors).
//
// Optional. When not set or when l is nil, [slog.Default] is used.
// Pass slog.New(slog.DiscardHandler) to silence all library output.
func WithDiagnosticLogger(l *slog.Logger) Option {
	return func(a *Auditor) error {
		a.logger = l
		return nil
	}
}

// WithStandardFieldDefaults sets deployment-wide default values for
// reserved standard fields. Defaults are applied in [Auditor.AuditEvent]
// before validation — a default satisfies required: true constraints.
// Per-event values always override defaults (key existence check, not
// zero value). When called multiple times, the last call wins.
//
// Optional. Nil or empty map means "no defaults".
func WithStandardFieldDefaults(defaults map[string]string) Option {
	return func(a *Auditor) error {
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
		a.standardFieldDefaults = cp
		return nil
	}
}

// WithFormatter sets the event serialisation formatter.
//
// Optional to call; if WithFormatter is not called, a [JSONFormatter]
// with default settings is used. If WithFormatter is called, f MUST
// be non-nil — the option returns an error for a nil formatter since
// there is no sane default to substitute at that point. Use this to
// configure a [CEFFormatter] or a custom [Formatter] implementation.
func WithFormatter(f Formatter) Option {
	return func(a *Auditor) error {
		if f == nil {
			return fmt.Errorf("audit: formatter must not be nil")
		}
		a.formatter = f
		return nil
	}
}

// WithOutputs sets the output destinations for the auditor. Events are
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
	return func(a *Auditor) error {
		if len(a.entries) > 0 {
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
		a.entries = entries
		a.outputsByName = byName
		a.usedWithOutputs = true
		return nil
	}
}

// OutputOption configures a single output registered via
// [WithNamedOutput]. Use [WithRoute], [WithOutputFormatter],
// [WithExcludeLabels], and [WithHMAC] to customise per-output
// behaviour.
type OutputOption func(*outputEntryBuilder)

// outputEntryBuilder accumulates per-output configuration before
// the output entry is registered on the auditor.
type outputEntryBuilder struct {
	formatter     Formatter
	route         *EventRoute
	hmacConfig    *HMACConfig
	excludeLabels []string
}

// WithRoute sets the per-output event route. The route restricts
// which events are delivered to this output. Nil means all
// globally-enabled events are delivered.
func WithRoute(r *EventRoute) OutputOption {
	return func(b *outputEntryBuilder) {
		b.route = r
	}
}

// WithOutputFormatter overrides the auditor's default formatter for
// this output. Nil means the auditor's default formatter is used.
//
// The "Output" prefix disambiguates from the auditor-level
// [WithFormatter] option; the two options set different defaults
// (auditor-wide vs per-output).
func WithOutputFormatter(f Formatter) OutputOption {
	return func(b *outputEntryBuilder) {
		b.formatter = f
	}
}

// WithExcludeLabels specifies sensitivity labels whose fields should
// be stripped from events before delivery to this output. When
// non-empty, the taxonomy MUST define a [SensitivityConfig] and every
// label MUST be defined within it; [New] returns an error if
// either condition is violated. An empty call means no field stripping.
// Framework fields are never stripped.
func WithExcludeLabels(labels ...string) OutputOption {
	return func(b *outputEntryBuilder) {
		b.excludeLabels = labels
	}
}

// WithHMAC configures per-output HMAC integrity. The config is
// validated eagerly during [New] option application — invalid
// configs (short salt, unknown algorithm) cause [New] to return
// an error. Nil means no HMAC for this output.
func WithHMAC(cfg *HMACConfig) OutputOption {
	return func(b *outputEntryBuilder) {
		b.hmacConfig = cfg
	}
}

// WithNamedOutput adds a single named output with optional per-output
// configuration. Use [WithRoute], [WithOutputFormatter],
// [WithExcludeLabels], and [WithHMAC] to customise behaviour.
//
// WithNamedOutput MUST NOT be combined with [WithOutputs]; if
// [WithOutputs] was already applied, WithNamedOutput returns an error.
//
// Output names MUST be unique across all outputs; duplicate names
// cause [New] to return an error. Duplicate destinations are
// also detected via [DestinationKeyer]. Routes are validated against
// the taxonomy after all options have been applied.
func WithNamedOutput(output Output, opts ...OutputOption) Option {
	return func(a *Auditor) error {
		if a.usedWithOutputs {
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
		return a.addNamedOutput(output, &b)
	}
}

// addNamedOutput registers a named output with dedup checking and
// optional route/formatter/exclude-label/HMAC configuration.
func (a *Auditor) addNamedOutput(output Output, b *outputEntryBuilder) error {
	name := output.Name()
	if a.outputsByName == nil {
		a.outputsByName = make(map[string]*outputEntry)
	}
	if a.destKeys == nil {
		a.destKeys = make(map[string]string)
	}
	if _, dup := a.outputsByName[name]; dup {
		return fmt.Errorf("audit: duplicate output name %q", name)
	}
	if err := checkDestinationDup(output, name, a.destKeys); err != nil {
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
	a.entries = append(a.entries, oe)
	a.outputsByName[name] = oe
	return nil
}

// WithQueueSize sets the async intake queue capacity for the auditor.
// Zero or negative values are ignored (the default of
// [DefaultQueueSize] applies). Values above [MaxQueueSize] cause
// [New] to return an error wrapping [ErrConfigInvalid].
func WithQueueSize(n int) Option {
	return func(a *Auditor) error {
		a.cfg.QueueSize = n
		return nil
	}
}

// WithShutdownTimeout sets the maximum time [Auditor.Close] waits for
// pending events to flush. Zero or negative values are ignored (the
// default of [DefaultShutdownTimeout] applies). Values above
// [MaxShutdownTimeout] cause [New] to return an error wrapping
// [ErrConfigInvalid].
func WithShutdownTimeout(d time.Duration) Option {
	return func(a *Auditor) error {
		a.cfg.ShutdownTimeout = d
		return nil
	}
}

// WithValidationMode sets how [Auditor.AuditEvent] handles unknown
// fields. Must be one of [ValidationStrict], [ValidationWarn], or
// [ValidationPermissive]. An invalid mode causes [New] to
// return an error wrapping [ErrConfigInvalid].
func WithValidationMode(m ValidationMode) Option {
	return func(a *Auditor) error {
		a.cfg.ValidationMode = m
		return nil
	}
}

// WithOmitEmpty enables omission of empty, nil, and zero-value fields
// from serialised output. When enabled, only non-zero fields are
// serialised. Consumers operating under compliance regimes that
// require all registered fields SHOULD NOT use this option.
func WithOmitEmpty() Option {
	return func(a *Auditor) error {
		a.cfg.OmitEmpty = true
		return nil
	}
}

// WithDisabled creates a no-op auditor that discards all events without
// validation or delivery. [Auditor.AuditEvent] returns nil immediately.
// This is the explicit opt-out for audit logging — the default is
// enabled, because silent audit disablement is worse than noisy audit
// failure.
func WithDisabled() Option {
	return func(a *Auditor) error {
		a.disabled = true
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
		// Deliberately omit the destination key from the error message:
		// for webhook/loki outputs the key contains the URL path, which
		// may carry a secret (Slack /services/<TOKEN>, Splunk HEC path).
		// The two output names are sufficient to identify the conflict
		// (#475).
		return fmt.Errorf("%w: outputs %q and %q share the same destination", ErrDuplicateDestination, existing, name)
	}
	seen[key] = name
	return nil
}
