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

	"github.com/axonops/audit"
)

// auditorConfigResult holds the [audit.Option] values and the disabled
// flag parsed from the YAML auditor: section. Disabled is tracked
// separately so callers can combine it with other auditor-level options
// (e.g. [audit.WithMetrics]) added after parse time.
//
// parseAuditorConfig produces audit.Option values directly — the
// library no longer exposes a Config struct (#579).
type auditorConfigResult struct { //nolint:govet // fieldalignment: readability preferred over packing
	opts []audit.Option
	// queueSize..disabled retained for internal test introspection via
	// export_test.go. Not part of the public surface.
	validationMode  audit.ValidationMode
	shutdownTimeout time.Duration
	queueSize       int
	omitEmpty       bool
	disabled        bool
}

func parseAuditorConfig(raw any) (auditorConfigResult, error) { //nolint:gocyclo,gocognit,cyclop // YAML field dispatch
	m, ok := raw.(map[string]any)
	if !ok {
		return auditorConfigResult{}, fmt.Errorf("expected mapping, got %T", raw)
	}
	var result auditorConfigResult
	for key, val := range m {
		switch key {
		case "enabled":
			v, err := toBool(val)
			if err != nil {
				return result, fmt.Errorf("enabled: %w", err)
			}
			if !v {
				result.disabled = true
			}
		case "queue_size":
			v, err := toInt(val)
			if err != nil {
				return result, fmt.Errorf("queue_size: %w", err)
			}
			if v < 0 {
				return result, fmt.Errorf("queue_size: must be non-negative, got %d", v)
			}
			if v > audit.MaxQueueSize {
				return result, fmt.Errorf("queue_size: %d exceeds maximum %d", v, audit.MaxQueueSize)
			}
			result.queueSize = v
			if v > 0 {
				result.opts = append(result.opts, audit.WithQueueSize(v))
			}
		case "shutdown_timeout":
			s, err := toString(val)
			if err != nil {
				return result, fmt.Errorf("shutdown_timeout: %w", err)
			}
			if s != "" {
				d, err := time.ParseDuration(s)
				if err != nil {
					return result, fmt.Errorf("shutdown_timeout: invalid duration %q: %w", s, err)
				}
				if d < 0 {
					return result, fmt.Errorf("shutdown_timeout: must be non-negative, got %s", s)
				}
				if d > audit.MaxShutdownTimeout {
					return result, fmt.Errorf("shutdown_timeout: %s exceeds maximum %s", d, audit.MaxShutdownTimeout)
				}
				result.shutdownTimeout = d
				if d > 0 {
					result.opts = append(result.opts, audit.WithShutdownTimeout(d))
				}
			}
		case "validation_mode":
			s, err := toString(val)
			if err != nil {
				return result, fmt.Errorf("validation_mode: %w", err)
			}
			if s != "" {
				switch audit.ValidationMode(s) {
				case audit.ValidationStrict, audit.ValidationWarn, audit.ValidationPermissive:
					result.validationMode = audit.ValidationMode(s)
					result.opts = append(result.opts, audit.WithValidationMode(audit.ValidationMode(s)))
				default:
					return result, fmt.Errorf("validation_mode: unknown mode %q (valid: strict, warn, permissive)", s)
				}
			}
		case "omit_empty":
			v, err := toBool(val)
			if err != nil {
				return result, fmt.Errorf("omit_empty: %w", err)
			}
			result.omitEmpty = v
			if v {
				result.opts = append(result.opts, audit.WithOmitEmpty())
			}
		case "drain_timeout":
			return result, fmt.Errorf("unknown field %q (renamed to %q in this version)", "drain_timeout", "shutdown_timeout")
		default:
			return result, fmt.Errorf("unknown field %q (valid: enabled, omit_empty, queue_size, shutdown_timeout, validation_mode)", key)
		}
	}
	return result, nil
}

// defaultAuditorConfigResult returns a default auditor config result
// for when the auditor: section is omitted from YAML.
func defaultAuditorConfigResult() auditorConfigResult {
	return auditorConfigResult{}
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
