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
	"fmt"

	audit "github.com/axonops/go-audit"
	"gopkg.in/yaml.v3"
)

// yamlFormatterConfig is the YAML representation of a formatter.
// CEF SeverityFunc, DescriptionFunc, and FieldMapping are NOT
// configurable via YAML — they require Go code.
type yamlFormatterConfig struct { //nolint:govet // fieldalignment: readability preferred
	Type      string `yaml:"type"`
	Timestamp string `yaml:"timestamp"`
	OmitEmpty bool   `yaml:"omit_empty"`
	Vendor    string `yaml:"vendor"`
	Product   string `yaml:"product"`
	Version   string `yaml:"version"`
}

// buildFormatter constructs a [audit.Formatter] from a YAML node.
// Returns nil if the node is nil or empty (use logger default).
// Returns an error for unknown formatter types or invalid options.
func buildFormatter(node *yaml.Node) (audit.Formatter, error) {
	if node == nil || (node.Kind == yaml.ScalarNode && node.Value == "") {
		return nil, nil
	}

	fmtBytes, marshalErr := yaml.Marshal(node)
	if marshalErr != nil {
		return nil, fmt.Errorf("formatter: %w", marshalErr)
	}
	var cfg yamlFormatterConfig
	dec := yaml.NewDecoder(bytes.NewReader(fmtBytes))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("formatter: %w", err)
	}

	switch cfg.Type {
	case "json", "":
		return buildJSONFormatter(&cfg)
	case "cef":
		return buildCEFFormatter(&cfg)
	default:
		return nil, fmt.Errorf("formatter: unknown type %q (valid: json, cef)", cfg.Type)
	}
}

func buildJSONFormatter(cfg *yamlFormatterConfig) (*audit.JSONFormatter, error) {
	// Reject CEF-specific fields on a JSON formatter.
	if cfg.Vendor != "" || cfg.Product != "" || cfg.Version != "" {
		return nil, fmt.Errorf("formatter: json does not support vendor/product/version options")
	}

	ts := audit.TimestampFormat(cfg.Timestamp)
	if ts == "" {
		ts = audit.TimestampRFC3339Nano
	}
	switch ts {
	case audit.TimestampRFC3339Nano, audit.TimestampUnixMillis:
		// valid
	default:
		return nil, fmt.Errorf("formatter: unknown timestamp format %q (valid: rfc3339nano, unix_ms)", cfg.Timestamp)
	}
	return &audit.JSONFormatter{
		Timestamp: ts,
		OmitEmpty: cfg.OmitEmpty,
	}, nil
}

func buildCEFFormatter(cfg *yamlFormatterConfig) (*audit.CEFFormatter, error) {
	// Reject JSON-specific fields on a CEF formatter.
	if cfg.Timestamp != "" {
		return nil, fmt.Errorf("formatter: cef does not support timestamp option (got %q)", cfg.Timestamp)
	}

	return &audit.CEFFormatter{
		Vendor:    cfg.Vendor,
		Product:   cfg.Product,
		Version:   cfg.Version,
		OmitEmpty: cfg.OmitEmpty,
		// SeverityFunc, DescriptionFunc, and FieldMapping are NOT
		// configurable via YAML. Consumers who need these should
		// construct the CEFFormatter programmatically.
	}, nil
}
