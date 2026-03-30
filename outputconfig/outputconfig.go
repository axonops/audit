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

// Package outputconfig loads audit output configuration from YAML files.
// It uses a registry pattern: output modules register factories via
// [audit.RegisterOutputFactory], and this package constructs outputs
// from YAML without importing the output modules directly.
//
// The consumer controls which output types are available via blank
// imports:
//
//	import (
//	    "github.com/axonops/go-audit/outputconfig"
//	    _ "github.com/axonops/go-audit/file"
//	    _ "github.com/axonops/go-audit/syslog"
//	)
//
//	result, err := outputconfig.Load(yamlData, &taxonomy, metrics)
package outputconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

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

// LoadResult holds the outputs and options produced by [Load], ready
// to be passed to [audit.NewLogger].
type LoadResult struct {
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
}

// NamedOutput pairs a constructed output with its config-level name
// and resolved formatter and route.
type NamedOutput struct {
	Name      string
	Output    audit.Output
	Route     *audit.EventRoute
	Formatter audit.Formatter
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
func Load(data []byte, taxonomy *audit.Taxonomy, coreMetrics audit.Metrics) (*LoadResult, error) {
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
		return nil, fmt.Errorf("%w: %v", ErrOutputConfigInvalid, err)
	}

	// Phase 3: Reject multi-document.
	var discard yaml.Node
	if err := dec.Decode(&discard); err == nil {
		return nil, fmt.Errorf("%w: multiple YAML documents", ErrOutputConfigInvalid)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content: %v", ErrOutputConfigInvalid, err)
	}

	// Phase 4: Walk root mapping node manually to extract fields
	// while preserving the outputs node as raw yaml.Node.
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
		outputsNode    *yaml.Node
	)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		val := root.Content[i+1]
		switch key {
		case "version":
			if err := val.Decode(&version); err != nil {
				return nil, fmt.Errorf("%w: version: %v", ErrOutputConfigInvalid, err)
			}
		case "default_formatter":
			defaultFmtNode = val
		case "outputs":
			outputsNode = val
		default:
			return nil, fmt.Errorf("%w: unknown top-level key %q", ErrOutputConfigInvalid, key)
		}
	}

	// Phase 5: Validate version.
	if version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d (expected 1)",
			ErrOutputConfigInvalid, version)
	}

	// Phase 6: Resolve default formatter (with env var expansion).
	var defaultFmt audit.Formatter
	if defaultFmtNode != nil {
		if err := expandEnvInNode(defaultFmtNode, "default_formatter"); err != nil {
			return nil, fmt.Errorf("%w: default_formatter: %v",
				ErrOutputConfigInvalid, err)
		}
		var err error
		defaultFmt, err = buildFormatter(defaultFmtNode)
		if err != nil {
			return nil, fmt.Errorf("%w: default_formatter: %v",
				ErrOutputConfigInvalid, err)
		}
	}

	// Phase 7: Process outputs from the raw YAML node (preserves order,
	// detects duplicate names).
	if outputsNode == nil {
		return nil, fmt.Errorf("%w: at least one output is required",
			ErrOutputConfigInvalid)
	}
	if outputsNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: outputs must be a YAML mapping",
			ErrOutputConfigInvalid)
	}

	outputNodes := outputsNode.Content
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

		no, err := buildOutput(name, valueNode, taxonomy, coreMetrics)
		if err != nil {
			closeAll(outputs)
			return nil, fmt.Errorf("%w: %v", ErrOutputConfigInvalid, err)
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
		Outputs:          outputs,
		DefaultFormatter: defaultFmt,
	}
	if defaultFmt != nil {
		result.Options = append(result.Options, audit.WithFormatter(defaultFmt))
	}
	for i := range outputs {
		result.Options = append(result.Options,
			audit.WithNamedOutput(outputs[i].Output, outputs[i].Route, outputs[i].Formatter))
	}

	return result, nil
}

// yamlRoute maps to [audit.EventRoute] fields.
type yamlRoute struct {
	IncludeCategories []string `yaml:"include_categories"`
	IncludeEventTypes []string `yaml:"include_event_types"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	ExcludeEventTypes []string `yaml:"exclude_event_types"`
}

// outputFields holds parsed fields from a single output YAML node.
type outputFields struct {
	typeName       string
	enabled        bool
	routeNode      *yaml.Node
	formatterNode  *yaml.Node
	typeConfigNode *yaml.Node
}

// buildOutput constructs a single named output from its YAML node.
// Returns nil (not error) when the output is disabled (enabled: false).
func buildOutput(name string, node *yaml.Node, taxonomy *audit.Taxonomy, coreMetrics audit.Metrics) (*NamedOutput, error) {
	fields, err := extractOutputFields(name, node)
	if err != nil {
		return nil, err
	}
	if !fields.enabled {
		return nil, nil //nolint:nilnil // nil signals disabled output
	}
	if err := expandOutputEnvVars(name, fields); err != nil {
		return nil, err
	}
	output, err := invokeFactory(name, fields, coreMetrics)
	if err != nil {
		return nil, err
	}
	route, err := buildRoute(name, fields.routeNode, taxonomy)
	if err != nil {
		return nil, err
	}
	formatter, err := buildOutputFormatter(name, fields.formatterNode)
	if err != nil {
		return nil, err
	}
	return &NamedOutput{Name: name, Output: output, Route: route, Formatter: formatter}, nil
}

func extractOutputFields(name string, node *yaml.Node) (*outputFields, error) {
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
		default:
			if f.typeConfigNode != nil {
				return nil, fmt.Errorf("output %q: unexpected key %q", name, key)
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

func invokeFactory(name string, f *outputFields, coreMetrics audit.Metrics) (audit.Output, error) {
	factory := audit.LookupOutputFactory(f.typeName)
	if factory == nil {
		registered := audit.RegisteredOutputTypes()
		return nil, fmt.Errorf("output %q: unknown output type %q (registered: [%s]); did you import _ \"github.com/axonops/go-audit/%s\"?",
			name, f.typeName, strings.Join(registered, ", "), f.typeName)
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
