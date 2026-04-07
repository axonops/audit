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
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/goccy/go-yaml"
)

// ErrOutputConfigInvalid is the sentinel error wrapped by output
// configuration validation failures.
var ErrOutputConfigInvalid = errors.New("audit: output config validation failed")

// MaxOutputConfigSize is the maximum YAML input size accepted by [Load].
const MaxOutputConfigSize = 1 << 20 // 1 MiB

// MaxOutputCount is the maximum number of outputs in a single config.
const MaxOutputCount = 100

// LoadResult holds the outputs, options, and logger configuration
// produced by [Load], ready to be passed to [audit.NewLogger].
type LoadResult struct { //nolint:govet // fieldalignment: readability preferred
	// Config is the logger configuration parsed from the optional
	// top-level `logger:` section. If the section is omitted, Config
	// contains Version: 1 and Enabled: true; other fields are zero-valued
	// and will be filled with sensible defaults by [audit.NewLogger]
	// (BufferSize: 10,000, DrainTimeout: 5s, ValidationMode: strict).
	// Pass this directly to [audit.NewLogger] as the first argument.
	Config audit.Config

	// Options contains framework field options ([audit.WithAppName],
	// [audit.WithHost], optionally [audit.WithTimezone]) and one
	// [audit.WithNamedOutput] per configured output. Pass these
	// directly to [audit.NewLogger].
	Options []audit.Option

	// Outputs is the ordered list of constructed outputs for
	// inspection or testing.
	Outputs []NamedOutput

	// AppName is the application name parsed from the top-level
	// `app_name:` key. Always non-empty after a successful Load.
	AppName string

	// Host is the hostname parsed from the top-level `host:` key.
	// Always non-empty after a successful Load.
	Host string

	// Timezone is the timezone name parsed from the top-level
	// `timezone:` key. Empty when not specified in the YAML.
	Timezone string

	// StandardFields maps reserved standard field names to their
	// deployment-wide default values, parsed from the top-level
	// `standard_fields:` section. Nil when not specified. Pass to
	// [audit.WithStandardFieldDefaults] (when available).
	StandardFields map[string]string
}

// NamedOutput pairs a constructed output with its config-level name
// and resolved formatter and route.
type NamedOutput struct {
	// Name is the config-level name of the output, as declared in the
	// YAML outputs map key.
	Name string
	// Output is the constructed output instance, ready for use.
	Output audit.Output
	// Route is the optional per-output event filter. Nil means all
	// events are delivered to this output.
	Route *audit.EventRoute
	// Formatter is the optional per-output formatter override. Nil
	// means the logger's default formatter is used.
	Formatter audit.Formatter
	// HMACConfig is the optional per-output HMAC configuration.
	// Nil means no HMAC for this output.
	HMACConfig *audit.HMACConfig
	// ExcludeLabels lists sensitivity label names whose fields are
	// stripped from events before delivery to this output. Nil or
	// empty means no field stripping.
	ExcludeLabels []string
}

// String returns a safe representation of LoadResult that never
// includes credentials, header values, or resolved environment
// variable values.
func (r *LoadResult) String() string {
	if r == nil {
		return "<nil>"
	}
	names := make([]string, len(r.Outputs))
	for i, o := range r.Outputs {
		names[i] = o.Name
	}
	return fmt.Sprintf("LoadResult{outputs: [%s], options: %d}",
		strings.Join(names, ", "), len(r.Options))
}

// String returns a safe representation of NamedOutput that never
// includes credentials, header values, or resolved environment
// variable values.
func (o *NamedOutput) String() string {
	if o == nil {
		return "<nil>"
	}
	outputName := "<nil>"
	if o.Output != nil {
		outputName = o.Output.Name()
	}
	hasRoute := o.Route != nil
	hasFormatter := o.Formatter != nil
	return fmt.Sprintf("NamedOutput{name: %q, output: %q, route: %t, formatter: %t}",
		o.Name, outputName, hasRoute, hasFormatter)
}

// Load parses a YAML output configuration, constructs all outputs via
// the registry, validates routes against the taxonomy, and returns
// [audit.Option] values ready for [audit.NewLogger].
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
func Load(data []byte, taxonomy *audit.Taxonomy, coreMetrics audit.Metrics) (*LoadResult, error) { //nolint:gocognit,gocyclo,cyclop // linear pipeline with 8 phases
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
		return nil, fmt.Errorf("%w: %w", ErrOutputConfigInvalid, err)
	}

	// Phase 3: Reject multi-document.
	var discard any
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: multiple YAML documents", ErrOutputConfigInvalid)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content: %w", ErrOutputConfigInvalid, err)
	}

	// Phase 4-6: Parse top-level fields, validate version, resolve config.
	// Extract ordered outputs separately (goccy/go-yaml decodes nested
	// maps as map[string]any which loses key order).
	orderedOutputs, orderedErr := extractOutputsOrdered(data)
	top, err := parseTopLevel(doc, orderedOutputs, orderedErr)
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
	closeAll := func(outputs []NamedOutput) {
		for _, o := range outputs {
			_ = o.Output.Close()
		}
	}

	seen := make(map[string]struct{})
	outputs := make([]NamedOutput, 0, outputCount)

	for _, item := range top.outputsRaw {
		name, ok := item.Key.(string)
		if !ok {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: output name must be a string",
				ErrOutputConfigInvalid)
		}

		if _, dup := seen[name]; dup {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: duplicate output name %q",
				ErrOutputConfigInvalid, name)
		}
		seen[name] = struct{}{}

		no, err := buildOutput(name, item.Value, taxonomy, top.tlsPolicyRaw, top.appName, top.host, coreMetrics)
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
		closeAll(outputs)
		return nil, fmt.Errorf("%w: all outputs are disabled; at least one enabled output is required",
			ErrOutputConfigInvalid)
	}

	// Phase 8: Build Options slice.
	result := &LoadResult{
		Config:         top.config,
		Outputs:        outputs,
		AppName:        top.appName,
		Host:           top.host,
		Timezone:       top.timezone,
		StandardFields: top.standardFields,
	}

	// Framework field options.
	result.Options = append(result.Options, audit.WithAppName(top.appName), audit.WithHost(top.host))
	if top.timezone != "" {
		result.Options = append(result.Options, audit.WithTimezone(top.timezone))
	}

	for i := range outputs {
		result.Options = append(result.Options,
			audit.WithNamedOutput(outputs[i].Output, outputs[i].Route, outputs[i].Formatter, outputs[i].ExcludeLabels...))
		if outputs[i].HMACConfig != nil && outputs[i].HMACConfig.Enabled {
			result.Options = append(result.Options,
				audit.WithOutputHMAC(outputs[i].Name, outputs[i].HMACConfig))
		}
	}

	return result, nil
}

// topLevel holds parsed top-level YAML fields.
type topLevel struct {
	outputsRaw     yaml.MapSlice // preserves output declaration order
	tlsPolicyRaw   any           // global tls_policy, injected into outputs that don't specify their own
	standardFields map[string]string
	appName        string
	host           string
	timezone       string
	config         audit.Config
}

// parseLoggerConfig parses the logger: value into an audit.Config.
// It accepts any (expected to be map[string]any after YAML decoding)
// and walks the map manually so that env-var-expanded string values
// are correctly handled for numeric fields.
func parseLoggerConfig(raw any) (audit.Config, error) { //nolint:gocyclo,gocognit,cyclop // YAML field dispatch
	m, ok := raw.(map[string]any)
	if !ok {
		return audit.Config{}, fmt.Errorf("expected mapping, got %T", raw)
	}
	cfg := audit.Config{
		Version: 1,
		Enabled: true,
	}
	for key, val := range m {
		switch key {
		case "enabled":
			v, err := toBool(val)
			if err != nil {
				return cfg, fmt.Errorf("enabled: %w", err)
			}
			cfg.Enabled = v
		case "buffer_size":
			v, err := toInt(val)
			if err != nil {
				return cfg, fmt.Errorf("buffer_size: %w", err)
			}
			if v < 0 {
				return cfg, fmt.Errorf("buffer_size: must be non-negative, got %d", v)
			}
			if v > audit.MaxBufferSize {
				return cfg, fmt.Errorf("buffer_size: %d exceeds maximum %d", v, audit.MaxBufferSize)
			}
			cfg.BufferSize = v
		case "drain_timeout":
			s, err := toString(val)
			if err != nil {
				return cfg, fmt.Errorf("drain_timeout: %w", err)
			}
			if s != "" {
				d, err := time.ParseDuration(s)
				if err != nil {
					return cfg, fmt.Errorf("drain_timeout: invalid duration %q: %w", s, err)
				}
				if d < 0 {
					return cfg, fmt.Errorf("drain_timeout: must be non-negative, got %s", s)
				}
				if d > audit.MaxDrainTimeout {
					return cfg, fmt.Errorf("drain_timeout: %s exceeds maximum %s", d, audit.MaxDrainTimeout)
				}
				cfg.DrainTimeout = d
			}
		case "validation_mode":
			s, err := toString(val)
			if err != nil {
				return cfg, fmt.Errorf("validation_mode: %w", err)
			}
			if s != "" {
				switch audit.ValidationMode(s) {
				case audit.ValidationStrict, audit.ValidationWarn, audit.ValidationPermissive:
					cfg.ValidationMode = audit.ValidationMode(s)
				default:
					return cfg, fmt.Errorf("validation_mode: unknown mode %q (valid: strict, warn, permissive)", s)
				}
			}
		case "omit_empty":
			v, err := toBool(val)
			if err != nil {
				return cfg, fmt.Errorf("omit_empty: %w", err)
			}
			cfg.OmitEmpty = v
		default:
			return cfg, fmt.Errorf("unknown field %q", key)
		}
	}
	return cfg, nil
}

// defaultLoggerConfig returns an audit.Config with sensible defaults
// for when the logger: section is omitted from YAML.
func defaultLoggerConfig() audit.Config {
	return audit.Config{
		Version: 1,
		Enabled: true,
	}
}

// parseTopLevel extracts and validates top-level YAML fields.
func parseTopLevel(doc, orderedOutputs yaml.MapSlice, orderedErr error) (*topLevel, error) { //nolint:gocyclo,cyclop,gocognit // YAML field dispatch
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrOutputConfigInvalid)
	}

	var (
		version   int
		loggerRaw any
		result    topLevel
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
		case "logger":
			loggerRaw = item.Value
		case "tls_policy":
			result.tlsPolicyRaw = item.Value
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
			s, sErr := toString(expanded)
			if sErr != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, sErr)
			}
			result.appName = s
		case "host":
			expanded, err := expandEnvInValue(item.Value, "host")
			if err != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, err)
			}
			s, sErr := toString(expanded)
			if sErr != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, sErr)
			}
			result.host = s
		case "timezone":
			expanded, err := expandEnvInValue(item.Value, "timezone")
			if err != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, err)
			}
			s, sErr := toString(expanded)
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
			sf, sfErr := parseStandardFields(expanded)
			if sfErr != nil {
				return nil, sfErr
			}
			result.standardFields = sf
		default:
			return nil, fmt.Errorf("%w: unknown top-level key %q", ErrOutputConfigInvalid, key)
		}
	}

	if version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d (expected 1)",
			ErrOutputConfigInvalid, version)
	}

	if loggerRaw != nil {
		expanded, err := expandEnvInValue(loggerRaw, "logger")
		if err != nil {
			return nil, fmt.Errorf("%w: logger: %w", ErrOutputConfigInvalid, err)
		}
		cfg, cfgErr := parseLoggerConfig(expanded)
		if cfgErr != nil {
			return nil, fmt.Errorf("%w: logger: %w", ErrOutputConfigInvalid, cfgErr)
		}
		result.config = cfg
	} else {
		result.config = defaultLoggerConfig()
	}

	// Expand env vars and validate global TLS policy eagerly so that
	// typos and unknown fields are caught at startup, not deferred to
	// individual output factory invocations.
	if result.tlsPolicyRaw != nil {
		expanded, err := expandEnvInValue(result.tlsPolicyRaw, "tls_policy")
		if err != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, err)
		}
		result.tlsPolicyRaw = expanded
		// Validate structure — reject unknown fields like typos.
		tlsBytes, mErr := yaml.Marshal(expanded)
		if mErr != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, mErr)
		}
		var validated yamlTLSPolicy
		if uErr := yaml.UnmarshalWithOptions(tlsBytes, &validated, yaml.DisallowUnknownField()); uErr != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, uErr)
		}
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

// parseStandardFields parses the standard_fields: value into a
// map[string]string. Keys must be reserved standard field names; values
// must be non-empty strings.
func parseStandardFields(raw any) (map[string]string, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: standard_fields must be a mapping", ErrOutputConfigInvalid)
	}
	result := make(map[string]string, len(m))
	for key, val := range m {
		if !audit.IsReservedStandardField(key) {
			return nil, fmt.Errorf("%w: standard_fields: unknown field %q -- only reserved standard field names are accepted",
				ErrOutputConfigInvalid, key)
		}
		s, err := toString(val)
		if err != nil {
			return nil, fmt.Errorf("%w: standard_fields: field %q: %w",
				ErrOutputConfigInvalid, key, err)
		}
		if s == "" {
			return nil, fmt.Errorf("%w: standard_fields: field %q must have a non-empty value",
				ErrOutputConfigInvalid, key)
		}
		result[key] = s
	}
	return result, nil
}

// yamlRoute maps to [audit.EventRoute] fields.
type yamlRoute struct {
	// MinSeverity (YAML: min_severity) — minimum severity threshold.
	// Events with severity below this value are not delivered. Nil = no filter.
	MinSeverity *int `yaml:"min_severity"`
	// MaxSeverity (YAML: max_severity) — maximum severity threshold.
	// Events with severity above this value are not delivered. Nil = no filter.
	MaxSeverity       *int     `yaml:"max_severity"`
	IncludeCategories []string `yaml:"include_categories"`
	IncludeEventTypes []string `yaml:"include_event_types"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	ExcludeEventTypes []string `yaml:"exclude_event_types"`
}

// outputFields holds parsed fields from a single output value.
type outputFields struct { //nolint:govet // fieldalignment: readability preferred
	typeName      string
	excludeLabels []string
	enabled       bool
	routeRaw      any
	formatterRaw  any
	typeConfigRaw any
	hmacRaw       any
}

// buildOutput constructs a single named output from its raw YAML value.
// Returns nil (not error) when the output is disabled (enabled: false).
func buildOutput(name string, raw any, taxonomy *audit.Taxonomy, globalTLSRaw any, globalAppName, globalHost string, coreMetrics audit.Metrics) (*NamedOutput, error) {
	fields, err := extractOutputFields(name, raw)
	if err != nil {
		return nil, err
	}
	if !fields.enabled {
		return nil, nil //nolint:nilnil // nil signals disabled output
	}
	if expandErr := expandOutputEnvVars(name, fields); expandErr != nil {
		return nil, expandErr
	}

	if fmtErr := validateLokiFormatter(name, fields); fmtErr != nil {
		return nil, fmtErr
	}

	output, err := invokeFactory(name, fields, globalTLSRaw, globalAppName, globalHost, coreMetrics)
	if err != nil {
		return nil, err
	}
	route, err := buildRoute(name, fields.routeRaw, taxonomy)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}
	formatter, err := buildOutputFormatter(name, fields.formatterRaw)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}

	hmacCfg, err := buildHMACConfig(name, fields.hmacRaw)
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	no := &NamedOutput{Name: name, Output: output, Route: route, Formatter: formatter, HMACConfig: hmacCfg}
	if len(fields.excludeLabels) > 0 {
		no.ExcludeLabels = fields.excludeLabels
	}
	return no, nil
}

// validateLokiFormatter rejects non-JSON formatters on Loki outputs
// before invoking the factory. Loki requires JSON format for label
// extraction and LogQL queries.
func validateLokiFormatter(name string, fields *outputFields) error {
	if fields.typeName != "loki" || fields.formatterRaw == nil {
		return nil
	}
	fmtType := extractFormatterType(fields.formatterRaw)
	if fmtType != "" && fmtType != "json" {
		return fmt.Errorf("output %q: loki does not support custom formatters; "+
			"loki requires JSON format for label extraction and LogQL queries", name)
	}
	return nil
}

func extractOutputFields(name string, raw any) (*outputFields, error) { //nolint:gocognit,gocyclo,cyclop // YAML field extraction with validation
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("output %q: expected a YAML mapping", name)
	}
	f := &outputFields{enabled: true}
	var foundType bool
	var typeConfigKey string
	for key, val := range m {
		switch key {
		case "type":
			s, err := toString(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: type: %w", name, err)
			}
			f.typeName = s
			foundType = true
		case "enabled":
			v, err := toBool(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: enabled: %w", name, err)
			}
			f.enabled = v
		case "route":
			f.routeRaw = val
		case "formatter":
			f.formatterRaw = val
		case "exclude_labels":
			labels, err := toStringSlice(val)
			if err != nil {
				return nil, fmt.Errorf("output %q: exclude_labels: %w", name, err)
			}
			f.excludeLabels = labels
		case "hmac":
			f.hmacRaw = val
		default:
			if f.typeConfigRaw != nil {
				return nil, fmt.Errorf("output %q: unexpected key %q; only 'type', 'enabled', 'route', 'formatter', 'exclude_labels', 'hmac', and one type-specific config block are allowed", name, key)
			}
			f.typeConfigRaw = val
			typeConfigKey = key
		}
	}
	if !foundType {
		return nil, fmt.Errorf("output %q: missing required field 'type'", name)
	}
	// Validate config key matches type name.
	if f.typeConfigRaw != nil && typeConfigKey != f.typeName {
		return nil, fmt.Errorf("output %q: config key %q does not match type %q", name, typeConfigKey, f.typeName)
	}
	return f, nil
}

func expandOutputEnvVars(name string, f *outputFields) error {
	base := "outputs." + name
	if f.typeConfigRaw != nil {
		expanded, err := expandEnvInValue(f.typeConfigRaw, base+"."+f.typeName)
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.typeConfigRaw = expanded
	}
	if f.routeRaw != nil {
		expanded, err := expandEnvInValue(f.routeRaw, base+".route")
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.routeRaw = expanded
	}
	if f.formatterRaw != nil {
		expanded, err := expandEnvInValue(f.formatterRaw, base+".formatter")
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.formatterRaw = expanded
	}
	return nil
}

// deepCopyValue creates a deep copy of a YAML value tree so that
// mutations in one consumer do not affect others.
func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(val))
		for k, child := range val {
			cp[k] = deepCopyValue(child)
		}
		return cp
	case []any:
		cp := make([]any, len(val))
		for i, child := range val {
			cp[i] = deepCopyValue(child)
		}
		return cp
	default:
		// Scalars (string, int, float64, bool, nil) are immutable.
		return v
	}
}

// injectGlobalTLSPolicy adds the global tls_policy to an output's
// type-specific config map if the output does not already define one.
// A deep copy of the global value is injected so that per-output env
// var expansion does not mutate the shared original.
func injectGlobalTLSPolicy(typeConfig map[string]any, globalTLS any) {
	if typeConfig == nil || globalTLS == nil {
		return
	}
	// Check if the output already has a tls_policy key.
	if _, exists := typeConfig["tls_policy"]; exists {
		return // per-output policy exists — do not override
	}
	// Inject a deep copy so mutations don't affect other outputs.
	typeConfig["tls_policy"] = deepCopyValue(globalTLS)
}

// injectSyslogGlobals injects global app_name and hostname into a
// syslog output's type-config map if not already set per-output.
func injectSyslogGlobals(f *outputFields, globalAppName, globalHost string) {
	if f.typeName != "syslog" {
		return
	}
	m, ok := f.typeConfigRaw.(map[string]any)
	if !ok {
		return
	}
	if globalAppName != "" {
		injectStringField(m, "app_name", globalAppName)
	}
	if globalHost != "" {
		injectStringField(m, "hostname", globalHost)
	}
}

// injectStringField adds a string key-value pair to a map if the key
// does not already exist.
func injectStringField(m map[string]any, key, value string) {
	if m == nil {
		return
	}
	if _, exists := m[key]; exists {
		return // per-output value exists — do not override
	}
	m[key] = value
}

// yamlTLSPolicy is used for eager validation of the global tls_policy.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

func invokeFactory(name string, f *outputFields, globalTLSRaw any, globalAppName, globalHost string, coreMetrics audit.Metrics) (audit.Output, error) {
	factory := audit.LookupOutputFactory(f.typeName)
	if factory == nil {
		registered := audit.RegisteredOutputTypes()
		return nil, fmt.Errorf("output %q: unknown output type %q (registered: [%s]); did you import _ \"github.com/axonops/go-audit/%s\"?",
			name, f.typeName, strings.Join(registered, ", "), f.typeName)
	}
	// Inject global TLS policy for output types that support it.
	// Only syslog and webhook parse tls_policy — injecting into other
	// types (file, stdout) would cause unknown-field errors.
	if f.typeConfigRaw != nil && globalTLSRaw != nil {
		if m, ok := f.typeConfigRaw.(map[string]any); ok {
			switch f.typeName {
			case "syslog", "webhook":
				injectGlobalTLSPolicy(m, globalTLSRaw)
			}
		}
	}
	// Inject global app_name and hostname into syslog config if not already set.
	injectSyslogGlobals(f, globalAppName, globalHost)

	var rawConfig []byte
	if f.typeConfigRaw != nil {
		var err error
		rawConfig, err = yaml.Marshal(f.typeConfigRaw)
		if err != nil {
			return nil, fmt.Errorf("output %q: marshal %q config: %w", name, f.typeName, err)
		}
	}
	output, err := factory(name, rawConfig, coreMetrics)
	if err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	return output, nil
}

func buildRoute(name string, raw any, taxonomy *audit.Taxonomy) (*audit.EventRoute, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil route = receive all events
	}
	routeBytes, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("output %q route: %w", name, err)
	}
	var yr yamlRoute
	if uErr := yaml.UnmarshalWithOptions(routeBytes, &yr, yaml.DisallowUnknownField()); uErr != nil {
		return nil, fmt.Errorf("output %q route: %w", name, uErr)
	}
	route := &audit.EventRoute{
		IncludeCategories: yr.IncludeCategories,
		IncludeEventTypes: yr.IncludeEventTypes,
		ExcludeCategories: yr.ExcludeCategories,
		ExcludeEventTypes: yr.ExcludeEventTypes,
		MinSeverity:       yr.MinSeverity,
		MaxSeverity:       yr.MaxSeverity,
	}
	if err := audit.ValidateEventRoute(route, taxonomy); err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	return route, nil
}

func buildOutputFormatter(name string, raw any) (audit.Formatter, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil = use logger default
	}
	f, err := buildFormatter(raw)
	if err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	return f, nil
}

// yamlHMACConfig is the intermediate YAML representation of the
// per-output hmac: section.
type yamlHMACConfig struct { //nolint:govet // readability over alignment
	Enabled bool         `yaml:"enabled"`
	Salt    yamlHMACSalt `yaml:"salt"`
	Hash    string       `yaml:"hash"`
}

// yamlHMACSalt is the YAML representation of the hmac.salt section.
type yamlHMACSalt struct {
	Version string `yaml:"version"`
	Value   string `yaml:"value"`
}

// buildHMACConfig parses and validates the hmac: value for an output.
func buildHMACConfig(name string, raw any) (*audit.HMACConfig, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil = no HMAC
	}

	// Expand env vars in the hmac block.
	expanded, err := expandEnvInValue(raw, fmt.Sprintf("outputs.%s.hmac", name))
	if err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
	}

	// Parse with strict field checking.
	hmacBytes, mErr := yaml.Marshal(expanded)
	if mErr != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, mErr)
	}
	var yc yamlHMACConfig
	if uErr := yaml.UnmarshalWithOptions(hmacBytes, &yc, yaml.DisallowUnknownField()); uErr != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, uErr)
	}

	if !yc.Enabled {
		return nil, nil //nolint:nilnil // explicitly disabled
	}

	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: yc.Salt.Version,
		SaltValue:   []byte(yc.Salt.Value),
		Algorithm:   yc.Hash,
	}

	if err := audit.ValidateHMACConfig(cfg); err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}

	return cfg, nil
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
		return nil, fmt.Errorf("extract outputs: %w", err)
	}
	return helper.Outputs, nil
}

// toBool converts a YAML-decoded value to bool. Handles both direct
// bool values and string representations (from env var expansion).
func toBool(v any) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case string:
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			return false, fmt.Errorf("invalid boolean %q: %w", val, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("expected boolean, got %T", v)
	}
}

// toInt converts a YAML-decoded value to int. Handles int, uint64,
// float64 (YAML numbers), and string representations (from env var
// expansion).
func toInt(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case uint64:
		return int(val), nil //nolint:gosec // config values are small integers, no overflow risk
	case float64:
		iv := int(val)
		if float64(iv) != val {
			return 0, fmt.Errorf("expected integer, got fractional number %v", val)
		}
		return iv, nil
	case string:
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q: %w", val, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

// toString converts a YAML-decoded value to string. Handles string
// values directly and converts numeric/bool types via fmt.Sprintf.
func toString(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case nil:
		return "", nil
	default:
		return fmt.Sprintf("%v", val), nil
	}
}

// toStringSlice converts a YAML-decoded value to []string. Handles
// []any containing string elements.
func toStringSlice(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected sequence, got %T", v)
	}
	result := make([]string, 0, len(arr))
	for i, elem := range arr {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("element [%d]: expected string, got %T", i, elem)
		}
		result = append(result, s)
	}
	return result, nil
}
