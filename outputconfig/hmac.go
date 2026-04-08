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
	"fmt"

	audit "github.com/axonops/go-audit"
	"github.com/goccy/go-yaml"
)

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
