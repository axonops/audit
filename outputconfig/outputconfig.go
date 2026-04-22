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

package outputconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

// ErrOutputConfigInvalid is the sentinel error wrapped by output
// configuration validation failures.
var ErrOutputConfigInvalid = errors.New("audit: output config validation failed")

// MaxOutputConfigSize is the maximum YAML input size accepted by [Load].
const MaxOutputConfigSize = 1 << 20 // 1 MiB

// MaxOutputCount is the maximum number of outputs in a single config.
const MaxOutputCount = 100

// Loaded is the result of parsing an outputs YAML configuration via
// [Load]. It aggregates the constructed outputs and the
// [audit.Option] values required to create an auditor. Fields are
// unexported — use the method accessors below.
//
// The zero value is not usable; always obtain via [Load].
type Loaded struct {
	options        []audit.Option
	outputs        []namedOutput
	appName        string
	host           string
	timezone       string
	standardFields map[string]string

	// config retains the parsed [audit.Config] for package-internal
	// introspection (e.g., black-box tests that assert YAML parsing
	// correctness via export_test.go). Never exposed publicly — the
	// equivalent audit.Option values are already in options, and
	// exposing Config here re-creates the #577 double-apply footgun.
	config audit.Config
}

// Options returns the slice of [audit.Option] values ready to pass to
// [audit.New], including framework-field options (app_name, host,
// timezone), config-equivalent options ([audit.WithQueueSize],
// etc.), standard-field defaults, and one [audit.WithNamedOutput]
// per configured output.
//
// The returned slice aliases the internal storage with capacity
// trimmed to length, so a caller's `append(loaded.Options(), extra)`
// cannot silently mutate the internal slice — append will allocate
// a new backing array. The caller must still not mutate the
// returned elements themselves.
//
// The caller must also supply [audit.WithTaxonomy] separately; it
// is not part of the returned slice because the same taxonomy is
// typically needed independently by the application.
func (l *Loaded) Options() []audit.Option {
	if l == nil {
		return nil
	}
	// Trim capacity to length so `append(l.Options(), x)` is guaranteed
	// to allocate a new backing array rather than silently overwriting
	// unused capacity of l.options.
	return l.options[:len(l.options):len(l.options)]
}

// Outputs returns the constructed [audit.Output] instances in YAML
// declaration order. Intended for cleanup when the caller decides
// not to construct an auditor after a successful [Load] — call
// [Loaded.Close] or iterate and close each output individually.
//
// The returned slice is a shallow copy; mutating it does not affect
// subsequent calls to Outputs, OutputMetadata, or the auditor.
func (l *Loaded) Outputs() []audit.Output {
	if l == nil {
		return nil
	}
	out := make([]audit.Output, len(l.outputs))
	for i := range l.outputs {
		out[i] = l.outputs[i].Output
	}
	return out
}

// OutputMetadata returns a diagnostic snapshot of each configured
// output — name, type, route, formatter, HMAC config, exclude
// labels — in YAML declaration order. Useful for tests asserting
// that a YAML config parsed as intended.
//
// The returned slice is a shallow copy; the [OutputInfo] values
// themselves reference the same underlying pointers as the auditor
// pipeline, so callers MUST NOT mutate the referenced values.
func (l *Loaded) OutputMetadata() []OutputInfo {
	if l == nil {
		return nil
	}
	info := make([]OutputInfo, len(l.outputs))
	for i, o := range l.outputs {
		// namedOutput and OutputInfo share identical fields —
		// direct conversion avoids listing every field.
		info[i] = OutputInfo(o)
	}
	return info
}

// AppName returns the application name parsed from the top-level
// `app_name:` key. Always non-empty after a successful [Load].
func (l *Loaded) AppName() string {
	if l == nil {
		return ""
	}
	return l.appName
}

// Host returns the hostname parsed from the top-level `host:` key.
// Always non-empty after a successful [Load].
func (l *Loaded) Host() string {
	if l == nil {
		return ""
	}
	return l.host
}

// Timezone returns the timezone name parsed from the top-level
// `timezone:` key. Empty string when not specified in the YAML.
func (l *Loaded) Timezone() string {
	if l == nil {
		return ""
	}
	return l.timezone
}

// StandardFields returns the reserved-standard-field defaults parsed
// from the top-level `standard_fields:` section, or nil when not
// specified. The returned map is the internal one; callers MUST NOT
// mutate it.
func (l *Loaded) StandardFields() map[string]string {
	if l == nil {
		return nil
	}
	return l.standardFields
}

// Close closes every output constructed by [Load]. Intended for use
// when the caller decides not to construct an auditor after a
// successful Load — for example, if [audit.New] returns an error
// and the outputs need cleanup. Returns the first non-nil Close
// error encountered; subsequent errors are swallowed.
//
// Close is not safe to call more than once, and MUST NOT be called
// after the [Loaded.Outputs] have been handed to a live
// [audit.Auditor] — the auditor takes ownership in that case.
func (l *Loaded) Close() error {
	if l == nil {
		return nil
	}
	var first error
	for _, o := range l.outputs {
		if err := o.Output.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// String returns a safe representation of Loaded that never
// includes credentials, header values, or resolved environment
// variable values.
func (l *Loaded) String() string {
	if l == nil {
		return "<nil>"
	}
	names := make([]string, len(l.outputs))
	for i, o := range l.outputs {
		names[i] = o.Name
	}
	return fmt.Sprintf("Loaded{outputs: [%s], options: %d}",
		strings.Join(names, ", "), len(l.options))
}

// OutputInfo is a diagnostic snapshot of a single configured output,
// returned by [Loaded.OutputMetadata]. Fields mirror the YAML
// declaration; modifying them has no effect on the auditor
// pipeline.
type OutputInfo struct {
	// Name is the config-level name of the output, as declared in the
	// YAML outputs map key.
	Name string
	// Type is the output type name (e.g. "file", "syslog", "webhook",
	// "loki", "stdout") as declared in the YAML type: field.
	Type string
	// Output is the constructed output instance.
	Output audit.Output
	// Route is the optional per-output event filter. Nil means all
	// events are delivered to this output.
	Route *audit.EventRoute
	// Formatter is the optional per-output formatter override. Nil
	// means the auditor's default formatter is used.
	Formatter audit.Formatter
	// HMACConfig is the optional per-output HMAC configuration.
	// Nil means no HMAC for this output.
	HMACConfig *audit.HMACConfig
	// ExcludeLabels lists sensitivity label names whose fields are
	// stripped from events before delivery to this output. Nil or
	// empty means no field stripping.
	ExcludeLabels []string
}

// String returns a safe representation of OutputInfo that never
// includes credentials, header values, or resolved environment
// variable values.
func (o *OutputInfo) String() string {
	if o == nil {
		return "<nil>"
	}
	outputName := "<nil>"
	if o.Output != nil {
		outputName = o.Output.Name()
	}
	return fmt.Sprintf("OutputInfo{name: %q, output: %q, route: %t, formatter: %t}",
		o.Name, outputName, o.Route != nil, o.Formatter != nil)
}

// namedOutput is the internal pipeline struct that Load builds and
// Loaded retains. Public callers inspect it via [Loaded.OutputMetadata]
// which returns the equivalent exported [OutputInfo].
type namedOutput struct {
	Name          string
	Type          string
	Output        audit.Output
	Route         *audit.EventRoute
	Formatter     audit.Formatter
	HMACConfig    *audit.HMACConfig
	ExcludeLabels []string
}

// Load parses a YAML output configuration, constructs all outputs via
// the registry, validates routes against the taxonomy, and returns
// [audit.Option] values ready for [audit.New].
//
// Load fails hard on any error — unknown output types, missing factory
// registrations, invalid YAML, unknown YAML keys, malformed routes,
// unresolvable environment variables, or route references to taxonomy
// entries that don't exist. Audit is a compliance function — silent
// misconfiguration is worse than refusing to start.
//
// Environment variable substitution (${VAR} and ${VAR:-default}) runs
// on string values in the parsed YAML tree, NOT on raw bytes. This
// prevents YAML injection via env var values.
//
// Secret reference resolution (ref+SCHEME://PATH#KEY) runs after env
// var expansion when providers are registered via [WithSecretProvider]
// or configured in the YAML secrets: section. The ctx parameter
// controls timeout for network I/O during secret resolution. Use
// [WithSecretTimeout] or the YAML secrets.timeout field to configure
// the resolution timeout.
//
// When providers are configured in the YAML secrets: section, they are
// constructed, used for resolution, and closed within Load. They do
// not outlive the call.
func Load(ctx context.Context, data []byte, taxonomy *audit.Taxonomy, opts ...LoadOption) (*Loaded, error) { //nolint:gocognit,gocyclo,cyclop // linear pipeline with 8+ phases
	lo := resolveOptions(opts)

	// Phase 1: Size check.
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: input is empty", ErrOutputConfigInvalid)
	}
	if len(data) > MaxOutputConfigSize {
		return nil, fmt.Errorf("%w: input size %d exceeds maximum %d",
			ErrOutputConfigInvalid, len(data), MaxOutputConfigSize)
	}

	// Phase 2: Parse top-level YAML into a MapSlice (preserves key ordering).
	var doc yaml.MapSlice
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		// Use %s + sanitized text to avoid echoing adversarial
		// input bytes (NUL / CR / LF) from the YAML parser's
		// error message into consumer log streams (#481).
		return nil, fmt.Errorf("%w: %s", ErrOutputConfigInvalid, sanitizeParserErrorMsg(err))
	}

	// Phase 3: Reject multi-document.
	var discard any
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: multiple YAML documents", ErrOutputConfigInvalid)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content: %s", ErrOutputConfigInvalid, sanitizeParserErrorMsg(err))
	}

	// Phase 3b: Extract and parse secrets: section (pre-pass).
	// The secrets: section is parsed BEFORE the resolver is built because
	// it creates the providers needed for ref+ resolution. Only env var
	// substitution is applied — ref+ URIs are not resolved (circular).
	filteredDoc, yamlProviders, yamlTimeout, sErr := extractAndParseSecrets(doc)
	if sErr != nil {
		return nil, sErr
	}
	// Ensure YAML-created providers are closed on all exit paths.
	defer func() {
		for _, p := range yamlProviders {
			_ = p.Close()
		}
	}()

	// Merge YAML-created providers with programmatic ones.
	allProviders, mErr := mergeProviders(lo.providers, yamlProviders)
	if mErr != nil {
		return nil, mErr
	}

	// Determine effective secret timeout.
	// Precedence: WithSecretTimeout > YAML timeout > DefaultSecretTimeout.
	secretTimeout := lo.secretTimeout
	if !lo.secretTimeoutSet && yamlTimeout > 0 {
		secretTimeout = yamlTimeout
	}

	// Build the secret resolver from combined providers.
	secretResolver, rErr := newResolver(allProviders)
	if rErr != nil {
		return nil, rErr
	}
	// Drop resolved-value references from the resolver caches on the
	// way out. The resolver is already local to this call and becomes
	// GC-unreachable at return; clearing the caches narrows the live
	// reference set by one layer before GC runs. Defence-in-depth per
	// #479 — not a zeroing guarantee.
	defer secretResolver.clearCaches()

	// Derive a context with the secret timeout applied.
	secretCtx := ctx
	if secretResolver != nil {
		var cancel context.CancelFunc
		secretCtx, cancel = contextWithSecretTimeout(ctx, secretTimeout)
		defer cancel()
	}

	// Phase 4-6: Parse top-level fields, validate version, resolve config.
	// Extract ordered outputs separately (goccy/go-yaml decodes nested
	// maps as map[string]any which loses key order).
	orderedOutputs, orderedErr := extractOutputsOrdered(data)
	top, err := parseTopLevel(secretCtx, filteredDoc, orderedOutputs, orderedErr, secretResolver)
	if err != nil {
		return nil, err
	}

	// Phase 7: Process outputs from the raw MapSlice (preserves order,
	// detects duplicate names).
	if len(top.outputsRaw) == 0 {
		return nil, fmt.Errorf("%w: at least one output is required",
			ErrOutputConfigInvalid)
	}

	// Pre-count outputs before constructing any (prevents resource
	// exhaustion from a config with hundreds of output entries).
	outputCount := len(top.outputsRaw)
	if outputCount > MaxOutputCount {
		return nil, fmt.Errorf("%w: %d outputs exceed maximum %d",
			ErrOutputConfigInvalid, outputCount, MaxOutputCount)
	}

	// closeAll cleans up already-constructed outputs on error.
	closeAll := func(outputs []namedOutput) {
		for _, o := range outputs {
			_ = o.Output.Close()
		}
	}

	seen := make(map[string]struct{})
	outputs := make([]namedOutput, 0, outputCount)

	for _, item := range top.outputsRaw {
		name, ok := item.Key.(string)
		if !ok {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: output name must be a string",
				ErrOutputConfigInvalid)
		}

		if err := audit.ValidateOutputName(name); err != nil {
			closeAll(outputs)
			// ValidateOutputName wraps ErrConfigInvalid; re-wrap with
			// ErrOutputConfigInvalid so callers can match either sentinel.
			return nil, fmt.Errorf("%w: output %q: %w", ErrOutputConfigInvalid, name, err)
		}

		if _, dup := seen[name]; dup {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: duplicate output name %q",
				ErrOutputConfigInvalid, name)
		}
		seen[name] = struct{}{}

		no, err := buildOutput(secretCtx, name, item.Value, taxonomy, top.appName, top.host, lo.coreMetrics, lo.factories, lo.diagnosticLogger, secretResolver)
		if err != nil {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: %w", ErrOutputConfigInvalid, err)
		}
		if no == nil {
			continue // enabled: false
		}
		outputs = append(outputs, *no)
	}

	if len(outputs) == 0 {
		return nil, fmt.Errorf("%w: all outputs are disabled; at least one enabled output is required",
			ErrOutputConfigInvalid)
	}

	// Phase 7b: Wire per-output metrics via OutputMetricsReceiver.
	if lo.outputMetricsFactory != nil {
		for i := range outputs {
			if recv, ok := outputs[i].Output.(audit.OutputMetricsReceiver); ok {
				recv.SetOutputMetrics(lo.outputMetricsFactory(outputs[i].Type, outputs[i].Name))
			}
		}
	}

	// Phase 8: Build Options slice.
	loaded := &Loaded{
		outputs:        outputs,
		appName:        top.appName,
		host:           top.host,
		timezone:       top.timezone,
		standardFields: top.standardFields,
		config:         top.auditorResult.config,
	}

	// Config-equivalent options so callers can use audit.New(loaded.Options()...).
	cfg := top.auditorResult.config
	if cfg.QueueSize > 0 {
		loaded.options = append(loaded.options, audit.WithQueueSize(cfg.QueueSize))
	}
	if cfg.ShutdownTimeout > 0 {
		loaded.options = append(loaded.options, audit.WithShutdownTimeout(cfg.ShutdownTimeout))
	}
	if cfg.ValidationMode != "" {
		loaded.options = append(loaded.options, audit.WithValidationMode(cfg.ValidationMode))
	}
	if cfg.OmitEmpty {
		loaded.options = append(loaded.options, audit.WithOmitEmpty())
	}
	if top.auditorResult.disabled {
		loaded.options = append(loaded.options, audit.WithDisabled())
	}

	// Framework field options.
	loaded.options = append(loaded.options, audit.WithAppName(top.appName), audit.WithHost(top.host))
	if top.timezone != "" {
		loaded.options = append(loaded.options, audit.WithTimezone(top.timezone))
	}

	// Standard field defaults.
	if len(top.standardFields) > 0 {
		loaded.options = append(loaded.options, audit.WithStandardFieldDefaults(top.standardFields))
	}

	for i := range outputs {
		var outOpts []audit.OutputOption
		if outputs[i].Route != nil {
			outOpts = append(outOpts, audit.WithRoute(outputs[i].Route))
		}
		if outputs[i].Formatter != nil {
			outOpts = append(outOpts, audit.WithOutputFormatter(outputs[i].Formatter))
		}
		if len(outputs[i].ExcludeLabels) > 0 {
			outOpts = append(outOpts, audit.WithExcludeLabels(outputs[i].ExcludeLabels...))
		}
		if outputs[i].HMACConfig != nil && outputs[i].HMACConfig.Enabled {
			outOpts = append(outOpts, audit.WithHMAC(outputs[i].HMACConfig))
		}
		loaded.options = append(loaded.options, audit.WithNamedOutput(outputs[i].Output, outOpts...))
	}

	return loaded, nil
}

// topLevel holds parsed top-level YAML fields.
type topLevel struct {
	outputsRaw     yaml.MapSlice // preserves output declaration order
	standardFields map[string]string
	appName        string
	host           string
	timezone       string
	auditorResult  auditorConfigResult
}

// parseTopLevel extracts and validates top-level YAML fields.
// When r is non-nil, ref+ URIs in string values are resolved after
// env var expansion.
func parseTopLevel(ctx context.Context, doc, orderedOutputs yaml.MapSlice, orderedErr error, r *resolver) (*topLevel, error) { //nolint:gocyclo,cyclop,gocognit // YAML field dispatch
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrOutputConfigInvalid)
	}

	var (
		version    int
		auditorRaw any
		result     topLevel
	)
	for _, item := range doc {
		key, ok := item.Key.(string)
		if !ok {
			return nil, fmt.Errorf("%w: top-level key must be a string", ErrOutputConfigInvalid)
		}
		switch key {
		case "version":
			v, err := toInt(item.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: version: %w", ErrOutputConfigInvalid, err)
			}
			version = v
		case "default_formatter":
			return nil, fmt.Errorf("%w: default_formatter has been removed; set formatter on each output individually",
				ErrOutputConfigInvalid)
		case "auditor":
			auditorRaw = item.Value
		case "outputs":
			if orderedOutputs == nil {
				if orderedErr != nil {
					return nil, fmt.Errorf("%w: outputs: %w", ErrOutputConfigInvalid, orderedErr)
				}
				return nil, fmt.Errorf("%w: outputs must be a YAML mapping",
					ErrOutputConfigInvalid)
			}
			result.outputsRaw = orderedOutputs
		case "app_name":
			expanded, err := expandEnvInValue(item.Value, "app_name")
			if err != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, err)
			}
			resolved, rErr := expandSecretsInValue(ctx, expanded, "app_name", r)
			if rErr != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, rErr)
			}
			if vnErr := validateNoUnresolvedRefs(resolved, "app_name"); vnErr != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, vnErr)
			}
			s, sErr := toString(resolved)
			if sErr != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, sErr)
			}
			result.appName = s
		case "host":
			expanded, err := expandEnvInValue(item.Value, "host")
			if err != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, err)
			}
			resolved, rErr := expandSecretsInValue(ctx, expanded, "host", r)
			if rErr != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, rErr)
			}
			if vnErr := validateNoUnresolvedRefs(resolved, "host"); vnErr != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, vnErr)
			}
			s, sErr := toString(resolved)
			if sErr != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, sErr)
			}
			result.host = s
		case "timezone":
			expanded, err := expandEnvInValue(item.Value, "timezone")
			if err != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, err)
			}
			resolved, rErr := expandSecretsInValue(ctx, expanded, "timezone", r)
			if rErr != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, rErr)
			}
			if vnErr := validateNoUnresolvedRefs(resolved, "timezone"); vnErr != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, vnErr)
			}
			s, sErr := toString(resolved)
			if sErr != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, sErr)
			}
			if s == "" {
				return nil, fmt.Errorf("%w: timezone must be non-empty when specified", ErrOutputConfigInvalid)
			}
			result.timezone = s
		case "standard_fields":
			expanded, err := expandEnvInValue(item.Value, "standard_fields")
			if err != nil {
				return nil, fmt.Errorf("%w: standard_fields: %w", ErrOutputConfigInvalid, err)
			}
			resolved, rErr := expandSecretsInValue(ctx, expanded, "standard_fields", r)
			if rErr != nil {
				return nil, fmt.Errorf("%w: standard_fields: %w", ErrOutputConfigInvalid, rErr)
			}
			if vnErr := validateNoUnresolvedRefs(resolved, "standard_fields"); vnErr != nil {
				return nil, fmt.Errorf("%w: standard_fields: %w", ErrOutputConfigInvalid, vnErr)
			}
			sf, sfErr := parseStandardFields(resolved)
			if sfErr != nil {
				return nil, sfErr
			}
			result.standardFields = sf
		case "logger":
			return nil, fmt.Errorf("%w: unknown top-level key %q (renamed to %q in this version)",
				ErrOutputConfigInvalid, "logger", "auditor")
		case "tls_policy":
			// Removed in #476 (pre-v1.0). TLS policy is now configured
			// per-output (syslog/webhook/loki) and per-provider
			// (vault/openbao). Provide a targeted migration hint so
			// operators aren't left guessing at a generic "unknown key"
			// error.
			return nil, fmt.Errorf("%w: tls_policy is no longer a top-level key; configure tls_policy under each output (syslog, webhook, loki) and each provider (vault, openbao) — see #476",
				ErrOutputConfigInvalid)
		default:
			return nil, fmt.Errorf("%w: unknown top-level key %q", ErrOutputConfigInvalid, key)
		}
	}

	if version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d (expected 1)",
			ErrOutputConfigInvalid, version)
	}

	if auditorRaw != nil {
		expanded, err := expandEnvInValue(auditorRaw, "auditor")
		if err != nil {
			return nil, fmt.Errorf("%w: auditor: %w", ErrOutputConfigInvalid, err)
		}
		resolved, rErr := expandSecretsInValue(ctx, expanded, "auditor", r)
		if rErr != nil {
			return nil, fmt.Errorf("%w: auditor: %w", ErrOutputConfigInvalid, rErr)
		}
		if vnErr := validateNoUnresolvedRefs(resolved, "auditor"); vnErr != nil {
			return nil, fmt.Errorf("%w: auditor: %w", ErrOutputConfigInvalid, vnErr)
		}
		lr, cfgErr := parseAuditorConfig(resolved)
		if cfgErr != nil {
			return nil, fmt.Errorf("%w: auditor: %w", ErrOutputConfigInvalid, cfgErr)
		}
		result.auditorResult = lr
	} else {
		result.auditorResult = defaultAuditorConfigResult()
	}

	if result.appName == "" {
		return nil, fmt.Errorf("%w: app_name is required and must be non-empty", ErrOutputConfigInvalid)
	}
	if len(result.appName) > 255 {
		return nil, fmt.Errorf("%w: app_name exceeds maximum length of 255 bytes", ErrOutputConfigInvalid)
	}
	if result.host == "" {
		return nil, fmt.Errorf("%w: host is required and must be non-empty", ErrOutputConfigInvalid)
	}
	if len(result.host) > 255 {
		return nil, fmt.Errorf("%w: host exceeds maximum length of 255 bytes", ErrOutputConfigInvalid)
	}
	if result.timezone != "" && len(result.timezone) > 64 {
		return nil, fmt.Errorf("%w: timezone exceeds maximum length of 64 bytes", ErrOutputConfigInvalid)
	}

	return &result, nil
}

// outputsOrderHelper is used to extract outputs with preserved key
// ordering. goccy/go-yaml decodes nested mappings as map[string]any
// which loses order. This struct uses yaml.MapSlice for the outputs
// field specifically.
type outputsOrderHelper struct {
	Outputs yaml.MapSlice `yaml:"outputs"`
}

func extractOutputsOrdered(rawYAML []byte) (yaml.MapSlice, error) {
	var helper outputsOrderHelper
	if err := yaml.Unmarshal(rawYAML, &helper); err != nil {
		// Sanitise third-party YAML error text to prevent
		// log-injection via adversarial input bytes (#481).
		return nil, fmt.Errorf("extract outputs: %s", sanitizeParserErrorMsg(err))
	}
	return helper.Outputs, nil
}
