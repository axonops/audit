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
	"strings"

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
