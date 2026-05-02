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
	"math"
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
		return auditorConfigResult{}, fmt.Errorf("expected YAML mapping, got %T — auditor must be a mapping with fields like queue_size, validation_mode, shutdown_timeout", raw)
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

func parseStandardFields(raw any) (map[string]any, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: standard_fields must be a mapping", ErrOutputConfigInvalid)
	}
	result := make(map[string]any, len(m))
	for key, val := range m {
		t, isReserved := audit.ReservedStandardFieldType(key)
		if !isReserved {
			return nil, fmt.Errorf("%w: standard_fields: unknown field %q -- only reserved standard field names are accepted",
				ErrOutputConfigInvalid, key)
		}
		// Reject empty string values regardless of reserved-field type;
		// a deployment-time empty default is always a configuration
		// mistake.
		if s, isStr := val.(string); isStr && s == "" {
			return nil, fmt.Errorf("%w: standard_fields: field %q must have a non-empty value",
				ErrOutputConfigInvalid, key)
		}
		// Normalise YAML-native types to the Go types the audit
		// package's WithStandardFieldDefaults validation expects.
		// goccy/go-yaml decodes integers as uint64 (positive) or
		// int64 (negative) and timestamps as string; the audit
		// package wants int / time.Time. Reject overflows and
		// malformed timestamps with clear errors here so the
		// failure mode points at the YAML, not at New().
		coerced, err := coerceStandardFieldValue(key, val, t)
		if err != nil {
			return nil, fmt.Errorf("%w: standard_fields: field %q: %w",
				ErrOutputConfigInvalid, key, err)
		}
		result[key] = coerced
	}
	return result, nil
}

// coerceStandardFieldValue converts a YAML-decoded value to the Go
// type declared for the reserved standard field. The conversion is
// loss-less or a clear error: int overflow on int64→int rejects
// rather than silently truncating; string→time.Time uses RFC3339.
//
// Returns the coerced value, or the original value when the YAML-
// decoded type already matches the declared type (so the audit-
// package validator can do the final type assertion).
func coerceStandardFieldValue(key string, val any, t audit.ReservedFieldType) (any, error) { //nolint:gocyclo,cyclop,gocognit // flat type switch over reserved-field declared types
	switch t {
	case audit.ReservedFieldInt:
		return coerceToInt(val)
	case audit.ReservedFieldInt64:
		return coerceToInt64(val)
	case audit.ReservedFieldFloat64:
		if f, ok := val.(float64); ok {
			return f, nil
		}
		if i, ok := val.(uint64); ok {
			return float64(i), nil
		}
		if i, ok := val.(int64); ok {
			return float64(i), nil
		}
		return nil, fmt.Errorf("expected float64-compatible YAML number, got %T", val)
	case audit.ReservedFieldBool:
		if b, ok := val.(bool); ok {
			return b, nil
		}
		return nil, fmt.Errorf("expected YAML bool, got %T", val)
	case audit.ReservedFieldTime:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("expected RFC3339 timestamp string, got %T", val)
		}
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, fmt.Errorf("invalid RFC3339 timestamp %q: %w", s, err)
		}
		return ts, nil
	case audit.ReservedFieldDuration:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("expected duration string, got %T", val)
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return d, nil
	case audit.ReservedFieldString:
		if _, ok := val.(string); !ok {
			return nil, fmt.Errorf("expected string, got %T", val)
		}
		return val, nil
	}
	// Unknown ReservedFieldType (forward-compat — new enum value
	// added without updating this switch). Pass through and let the
	// audit-package validator report a clear error.
	_ = key
	return val, nil
}

func coerceToInt(val any) (int, error) {
	switch v := val.(type) {
	case int:
		return v, nil
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, fmt.Errorf("YAML integer %d exceeds int max %d", v, math.MaxInt)
		}
		return int(v), nil
	case int64:
		if v > int64(math.MaxInt) || v < int64(math.MinInt) {
			return 0, fmt.Errorf("YAML integer %d out of int range [%d, %d]", v, math.MinInt, math.MaxInt)
		}
		return int(v), nil
	}
	return 0, fmt.Errorf("expected YAML integer, got %T", val)
}

func coerceToInt64(val any) (int64, error) {
	switch v := val.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case uint64:
		if v > uint64(math.MaxInt64) {
			return 0, fmt.Errorf("YAML integer %d exceeds int64 max %d", v, int64(math.MaxInt64))
		}
		return int64(v), nil
	}
	return 0, fmt.Errorf("expected YAML integer, got %T", val)
}
