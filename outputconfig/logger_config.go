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
	"time"

	audit "github.com/axonops/go-audit"
)

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
