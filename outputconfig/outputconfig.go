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
	"gopkg.in/yaml.v3"
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

	// Options contains one [audit.WithNamedOutput] per configured
	// output, plus an optional [audit.WithFormatter] for the default
	// formatter. Pass these directly to [audit.NewLogger].
	Options []audit.Option

	// Outputs is the ordered list of constructed outputs for
	// inspection or testing.
	Outputs []NamedOutput

	// DefaultFormatter is the resolved default formatter. Nil means
	// the logger's built-in JSONFormatter will be used.
	DefaultFormatter audit.Formatter

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

	// Phase 2: Parse top-level YAML.
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOutputConfigInvalid, err)
	}

	// Phase 3: Reject multi-document.
	var discard yaml.Node
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: multiple YAML documents", ErrOutputConfigInvalid)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content: %w", ErrOutputConfigInvalid, err)
	}

	// Phase 4-6: Parse top-level fields, validate version, resolve formatter.
	top, err := parseTopLevel(&doc)
	if err != nil {
		return nil, err
	}

	// Phase 7: Process outputs from the raw YAML node (preserves order,
	// detects duplicate names).
	if top.outputsNode == nil {
		return nil, fmt.Errorf("%w: at least one output is required",
			ErrOutputConfigInvalid)
	}
	if top.outputsNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: outputs must be a YAML mapping",
			ErrOutputConfigInvalid)
	}

	outputNodes := top.outputsNode.Content
	if len(outputNodes) == 0 {
		return nil, fmt.Errorf("%w: at least one output is required",
			ErrOutputConfigInvalid)
	}

	// Pre-count outputs before constructing any (prevents resource
	// exhaustion from a config with hundreds of output entries).
	outputCount := len(outputNodes) / 2
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
	var outputs []NamedOutput

	for i := 0; i+1 < len(outputNodes); i += 2 {
		nameNode := outputNodes[i]
		valueNode := outputNodes[i+1]
		name := nameNode.Value

		if _, dup := seen[name]; dup {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: duplicate output name %q",
				ErrOutputConfigInvalid, name)
		}
		seen[name] = struct{}{}

		no, err := buildOutput(name, valueNode, taxonomy, top.tlsPolicyNode, top.host, coreMetrics)
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
		Config:           top.config,
		Outputs:          outputs,
		DefaultFormatter: top.defaultFmt,
		AppName:          top.appName,
		Host:             top.host,
		Timezone:         top.timezone,
		StandardFields:   top.standardFields,
	}

	// Framework field options.
	result.Options = append(result.Options, audit.WithAppName(top.appName), audit.WithHost(top.host))
	if top.timezone != "" {
		result.Options = append(result.Options, audit.WithTimezone(top.timezone))
	}

	if top.defaultFmt != nil {
		result.Options = append(result.Options, audit.WithFormatter(top.defaultFmt))
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
	outputsNode    *yaml.Node
	tlsPolicyNode  *yaml.Node // global tls_policy, injected into outputs that don't specify their own
	standardFields map[string]string
	defaultFmt     audit.Formatter
	appName        string
	host           string
	timezone       string
	config         audit.Config
}

// parseLoggerConfig parses the logger: YAML node into an audit.Config.
// It walks the mapping manually (like parseTopLevel) so that env-var-
// expanded string values are correctly handled for numeric fields.
func parseLoggerConfig(node *yaml.Node) (audit.Config, error) { //nolint:gocyclo,gocognit,cyclop // YAML field dispatch
	if node.Kind != yaml.MappingNode {
		return audit.Config{}, fmt.Errorf("expected mapping, got %v", node.Kind)
	}
	cfg := audit.Config{
		Version: 1,
		Enabled: true,
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "enabled":
			var v bool
			if err := val.Decode(&v); err != nil {
				var s string
				if sErr := val.Decode(&s); sErr != nil {
					return cfg, fmt.Errorf("enabled: %w", err)
				}
				parsed, pErr := strconv.ParseBool(s)
				if pErr != nil {
					return cfg, fmt.Errorf("enabled: invalid boolean %q: %w", s, pErr)
				}
				v = parsed
			}
			cfg.Enabled = v
		case "buffer_size":
			var v int
			if err := val.Decode(&v); err != nil {
				// After env expansion, the value may be a string.
				var s string
				if sErr := val.Decode(&s); sErr != nil {
					return cfg, fmt.Errorf("buffer_size: %w", err)
				}
				n, pErr := strconv.Atoi(s)
				if pErr != nil {
					return cfg, fmt.Errorf("buffer_size: invalid integer %q: %w", s, pErr)
				}
				v = n
			}
			if v < 0 {
				return cfg, fmt.Errorf("buffer_size: must be non-negative, got %d", v)
			}
			if v > audit.MaxBufferSize {
				return cfg, fmt.Errorf("buffer_size: %d exceeds maximum %d", v, audit.MaxBufferSize)
			}
			cfg.BufferSize = v
		case "drain_timeout":
			var s string
			if err := val.Decode(&s); err != nil {
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
			var s string
			if err := val.Decode(&s); err != nil {
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
			var v bool
			if err := val.Decode(&v); err != nil {
				var s string
				if sErr := val.Decode(&s); sErr != nil {
					return cfg, fmt.Errorf("omit_empty: %w", err)
				}
				parsed, pErr := strconv.ParseBool(s)
				if pErr != nil {
					return cfg, fmt.Errorf("omit_empty: invalid boolean %q: %w", s, pErr)
				}
				v = parsed
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
func parseTopLevel(doc *yaml.Node) (*topLevel, error) { //nolint:gocyclo,cyclop,gocognit // YAML field dispatch
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrOutputConfigInvalid)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: expected a YAML mapping at top level", ErrOutputConfigInvalid)
	}

	var (
		version        int
		defaultFmtNode *yaml.Node
		loggerNode     *yaml.Node
		result         topLevel
	)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]
		switch key {
		case "version":
			if err := val.Decode(&version); err != nil {
				return nil, fmt.Errorf("%w: version: %w", ErrOutputConfigInvalid, err)
			}
		case "default_formatter":
			defaultFmtNode = val
		case "logger":
			loggerNode = val
		case "tls_policy":
			result.tlsPolicyNode = val
		case "outputs":
			result.outputsNode = val
		case "app_name":
			if err := expandEnvInNode(val, "app_name"); err != nil {
				return nil, fmt.Errorf("%w: app_name: %w", ErrOutputConfigInvalid, err)
			}
			result.appName = val.Value
		case "host":
			if err := expandEnvInNode(val, "host"); err != nil {
				return nil, fmt.Errorf("%w: host: %w", ErrOutputConfigInvalid, err)
			}
			result.host = val.Value
		case "timezone":
			if err := expandEnvInNode(val, "timezone"); err != nil {
				return nil, fmt.Errorf("%w: timezone: %w", ErrOutputConfigInvalid, err)
			}
			if val.Value == "" {
				return nil, fmt.Errorf("%w: timezone must be non-empty when specified", ErrOutputConfigInvalid)
			}
			result.timezone = val.Value
		case "standard_fields":
			if err := expandEnvInNode(val, "standard_fields"); err != nil {
				return nil, fmt.Errorf("%w: standard_fields: %w", ErrOutputConfigInvalid, err)
			}
			sf, err := parseStandardFields(val)
			if err != nil {
				return nil, err
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

	if loggerNode != nil {
		if err := expandEnvInNode(loggerNode, "logger"); err != nil {
			return nil, fmt.Errorf("%w: logger: %w", ErrOutputConfigInvalid, err)
		}
		cfg, err := parseLoggerConfig(loggerNode)
		if err != nil {
			return nil, fmt.Errorf("%w: logger: %w", ErrOutputConfigInvalid, err)
		}
		result.config = cfg
	} else {
		result.config = defaultLoggerConfig()
	}

	// Expand env vars and validate global TLS policy eagerly so that
	// typos and unknown fields are caught at startup, not deferred to
	// individual output factory invocations.
	if result.tlsPolicyNode != nil {
		if err := expandEnvInNode(result.tlsPolicyNode, "tls_policy"); err != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, err)
		}
		// Validate structure — reject unknown fields like typos.
		tlsBytes, err := yaml.Marshal(result.tlsPolicyNode)
		if err != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(tlsBytes))
		dec.KnownFields(true)
		var validated yamlTLSPolicy
		if err := dec.Decode(&validated); err != nil {
			return nil, fmt.Errorf("%w: tls_policy: %w", ErrOutputConfigInvalid, err)
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

	if defaultFmtNode != nil {
		if err := expandEnvInNode(defaultFmtNode, "default_formatter"); err != nil {
			return nil, fmt.Errorf("%w: default_formatter: %w", ErrOutputConfigInvalid, err)
		}
		var err error
		result.defaultFmt, err = buildFormatter(defaultFmtNode)
		if err != nil {
			return nil, fmt.Errorf("%w: default_formatter: %w", ErrOutputConfigInvalid, err)
		}
	}

	return &result, nil
}

// parseStandardFields parses the standard_fields: YAML mapping into a
// map[string]string. Keys must be reserved standard field names; values
// must be non-empty strings.
func parseStandardFields(node *yaml.Node) (map[string]string, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: standard_fields must be a mapping", ErrOutputConfigInvalid)
	}
	result := make(map[string]string, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1].Value
		if !audit.IsReservedStandardField(key) {
			return nil, fmt.Errorf("%w: standard_fields: unknown field %q -- only reserved standard field names are accepted",
				ErrOutputConfigInvalid, key)
		}
		if val == "" {
			return nil, fmt.Errorf("%w: standard_fields: field %q must have a non-empty value",
				ErrOutputConfigInvalid, key)
		}
		result[key] = val
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

// outputFields holds parsed fields from a single output YAML node.
type outputFields struct { //nolint:govet // fieldalignment: readability preferred
	typeName       string
	excludeLabels  []string
	enabled        bool
	routeNode      *yaml.Node
	formatterNode  *yaml.Node
	typeConfigNode *yaml.Node
	hmacNode       *yaml.Node
}

// buildOutput constructs a single named output from its YAML node.
// Returns nil (not error) when the output is disabled (enabled: false).
func buildOutput(name string, node *yaml.Node, taxonomy *audit.Taxonomy, globalTLSNode *yaml.Node, globalHost string, coreMetrics audit.Metrics) (*NamedOutput, error) {
	fields, err := extractOutputFields(name, node)
	if err != nil {
		return nil, err
	}
	if !fields.enabled {
		return nil, nil //nolint:nilnil // nil signals disabled output
	}
	if expandErr := expandOutputEnvVars(name, fields); expandErr != nil {
		return nil, expandErr
	}
	output, err := invokeFactory(name, fields, globalTLSNode, globalHost, coreMetrics)
	if err != nil {
		return nil, err
	}
	route, err := buildRoute(name, fields.routeNode, taxonomy)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}
	formatter, err := buildOutputFormatter(name, fields.formatterNode)
	if err != nil {
		_ = output.Close() // best-effort cleanup; returning the original error
		return nil, err
	}
	hmacCfg, err := buildHMACConfig(name, fields.hmacNode)
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

func extractOutputFields(name string, node *yaml.Node) (*outputFields, error) { //nolint:gocognit,gocyclo,cyclop // YAML field extraction with validation
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("output %q: expected a YAML mapping", name)
	}
	f := &outputFields{enabled: true}
	var foundType bool
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "type":
			f.typeName = val.Value
			foundType = true
		case "enabled":
			if err := val.Decode(&f.enabled); err != nil {
				return nil, fmt.Errorf("output %q: enabled: %w", name, err)
			}
		case "route":
			f.routeNode = val
		case "formatter":
			f.formatterNode = val
		case "exclude_labels":
			if err := val.Decode(&f.excludeLabels); err != nil {
				return nil, fmt.Errorf("output %q: exclude_labels: %w", name, err)
			}
		case "hmac":
			f.hmacNode = val
		default:
			if f.typeConfigNode != nil {
				return nil, fmt.Errorf("output %q: unexpected key %q; only 'type', 'enabled', 'route', 'formatter', 'exclude_labels', 'hmac', and one type-specific config block are allowed", name, key)
			}
			f.typeConfigNode = val
		}
	}
	if !foundType {
		return nil, fmt.Errorf("output %q: missing required field 'type'", name)
	}
	// Validate config key matches type name.
	if f.typeConfigNode != nil {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i+1] == f.typeConfigNode {
				if configKey := node.Content[i].Value; configKey != f.typeName {
					return nil, fmt.Errorf("output %q: config key %q does not match type %q", name, configKey, f.typeName)
				}
				break
			}
		}
	}
	return f, nil
}

func expandOutputEnvVars(name string, f *outputFields) error {
	base := "outputs." + name
	if f.typeConfigNode != nil {
		if err := expandEnvInNode(f.typeConfigNode, base+"."+f.typeName); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	if f.routeNode != nil {
		if err := expandEnvInNode(f.routeNode, base+".route"); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	if f.formatterNode != nil {
		if err := expandEnvInNode(f.formatterNode, base+".formatter"); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	return nil
}

// deepCopyNode creates a deep copy of a YAML node tree so that
// mutations in one consumer do not affect others.
func deepCopyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			cp.Content[i] = deepCopyNode(child)
		}
	}
	return &cp
}

// injectGlobalTLSPolicy adds the global tls_policy to an output's
// type-specific config node if the output does not already define one.
// A deep copy of the global node is injected so that per-output env
// var expansion does not mutate the shared original.
func injectGlobalTLSPolicy(typeNode, globalNode *yaml.Node) {
	if typeNode == nil || globalNode == nil || typeNode.Kind != yaml.MappingNode {
		return
	}
	// Check if the output already has a tls_policy key.
	for i := 0; i+1 < len(typeNode.Content); i += 2 {
		if typeNode.Content[i].Value == "tls_policy" {
			return // per-output policy exists — do not override
		}
	}
	// Inject a deep copy so mutations don't affect other outputs.
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "tls_policy", Tag: "!!str"}
	typeNode.Content = append(typeNode.Content, keyNode, deepCopyNode(globalNode))
}

// injectStringField adds a string key-value pair to a YAML mapping
// node if the key does not already exist.
func injectStringField(typeNode *yaml.Node, key, value string) {
	if typeNode == nil || typeNode.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(typeNode.Content); i += 2 {
		if typeNode.Content[i].Value == key {
			return // per-output value exists — do not override
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: "!!str"}
	typeNode.Content = append(typeNode.Content, keyNode, valNode)
}

// yamlTLSPolicy is used for eager validation of the global tls_policy.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

func invokeFactory(name string, f *outputFields, globalTLSNode *yaml.Node, globalHost string, coreMetrics audit.Metrics) (audit.Output, error) {
	factory := audit.LookupOutputFactory(f.typeName)
	if factory == nil {
		registered := audit.RegisteredOutputTypes()
		return nil, fmt.Errorf("output %q: unknown output type %q (registered: [%s]); did you import _ \"github.com/axonops/go-audit/%s\"?",
			name, f.typeName, strings.Join(registered, ", "), f.typeName)
	}
	// Inject global TLS policy for output types that support it.
	// Only syslog and webhook parse tls_policy — injecting into other
	// types (file, stdout) would cause unknown-field errors.
	if f.typeConfigNode != nil && globalTLSNode != nil {
		switch f.typeName {
		case "syslog", "webhook":
			injectGlobalTLSPolicy(f.typeConfigNode, globalTLSNode)
		}
	}
	// Inject global hostname into syslog config if not already set.
	if f.typeName == "syslog" && globalHost != "" {
		injectStringField(f.typeConfigNode, "hostname", globalHost)
	}

	var rawConfig []byte
	if f.typeConfigNode != nil {
		var err error
		rawConfig, err = yaml.Marshal(f.typeConfigNode)
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

func buildRoute(name string, routeNode *yaml.Node, taxonomy *audit.Taxonomy) (*audit.EventRoute, error) {
	if routeNode == nil {
		return nil, nil //nolint:nilnil // nil route = receive all events
	}
	routeBytes, err := yaml.Marshal(routeNode)
	if err != nil {
		return nil, fmt.Errorf("output %q route: %w", name, err)
	}
	var yr yamlRoute
	routeDec := yaml.NewDecoder(bytes.NewReader(routeBytes))
	routeDec.KnownFields(true)
	if err := routeDec.Decode(&yr); err != nil {
		return nil, fmt.Errorf("output %q route: %w", name, err)
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

func buildOutputFormatter(name string, fmtNode *yaml.Node) (audit.Formatter, error) {
	if fmtNode == nil {
		return nil, nil //nolint:nilnil // nil = use logger default
	}
	f, err := buildFormatter(fmtNode)
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

// buildHMACConfig parses and validates the hmac: YAML node for an output.
func buildHMACConfig(name string, hmacNode *yaml.Node) (*audit.HMACConfig, error) {
	if hmacNode == nil {
		return nil, nil //nolint:nilnil // nil = no HMAC
	}

	// Expand env vars in the hmac block.
	if err := expandEnvInNode(hmacNode, fmt.Sprintf("outputs.%s.hmac", name)); err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
	}

	// Parse with strict field checking.
	hmacBytes, err := yaml.Marshal(hmacNode)
	if err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(hmacBytes))
	dec.KnownFields(true)
	var yc yamlHMACConfig
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
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
