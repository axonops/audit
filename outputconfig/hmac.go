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
	"context"
	"fmt"

	"github.com/axonops/audit"
	"github.com/axonops/audit/secrets"
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
// When r is non-nil and the HMAC is enabled, ref+ URIs in the HMAC
// fields are resolved. When enabled is false (whether literal, from
// env var, or from a secret ref), remaining fields are NOT resolved.
func buildHMACConfig(ctx context.Context, name string, raw any, r *resolver) (*audit.HMACConfig, error) { //nolint:gocyclo,cyclop // linear HMAC pipeline with disabled bypass
	if raw == nil {
		return nil, nil //nolint:nilnil // nil = no HMAC
	}

	// Expand env vars in the hmac block.
	fieldBase := fmt.Sprintf("outputs.%s.hmac", name)
	expanded, err := expandEnvInValue(raw, fieldBase)
	if err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
	}

	// Extract and resolve the "enabled" field before unmarshalling
	// the full struct. This is necessary because if enabled is a ref+
	// URI, YAML unmarshal into a bool would fail.
	enabled, expandedWithoutEnabled, err := extractAndResolveEnabled(ctx, expanded, fieldBase, r)
	if err != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, err)
	}

	if !enabled {
		return nil, nil //nolint:nilnil // explicitly disabled — skip remaining refs
	}

	// Enabled is true — resolve secrets in remaining HMAC fields.
	if r != nil {
		resolved, rErr := expandSecretsInValue(ctx, expandedWithoutEnabled, fieldBase, r)
		if rErr != nil {
			return nil, fmt.Errorf("output %q: hmac: %w", name, rErr)
		}
		expandedWithoutEnabled = resolved

		// Safety net on resolved HMAC fields.
		if unresErr := validateNoUnresolvedRefs(expandedWithoutEnabled, fieldBase); unresErr != nil {
			return nil, fmt.Errorf("output %q: hmac: %w", name, unresErr)
		}
	}

	// Re-inject enabled=true for unmarshalling.
	if m, ok := expandedWithoutEnabled.(map[string]any); ok {
		m["enabled"] = true
	}

	// Parse with strict field checking.
	// safeMarshal (not yaml.Marshal) — see safe_marshal.go (#487).
	hmacBytes, mErr := safeMarshal(expandedWithoutEnabled)
	if mErr != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, mErr)
	}
	var yc yamlHMACConfig
	if uErr := yaml.UnmarshalWithOptions(hmacBytes, &yc, yaml.DisallowUnknownField()); uErr != nil {
		return nil, fmt.Errorf("output %q: hmac: %w", name, audit.WrapUnknownFieldError(uErr, yc))
	}

	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: yc.Salt.Version,
		SaltValue:   []byte(yc.Salt.Value),
		Algorithm:   yc.Hash,
	}

	if vErr := audit.ValidateHMACConfig(cfg); vErr != nil {
		return nil, fmt.Errorf("output %q: %w", name, vErr)
	}

	return cfg, nil
}

// extractAndResolveEnabled extracts the "enabled" field from the raw
// HMAC map, resolves it if it is a ref+, and converts to bool.
// Returns the bool value and the raw map with "enabled" removed.
// extractAndResolveEnabled extracts the "enabled" field from the raw
// HMAC map, resolves it if it is a ref+, and converts to bool.
// Returns the bool value and the raw map with "enabled" removed.
// NOTE: this function MUTATES the input map by deleting the "enabled"
// key. The caller must not reuse the map after this call.
func extractAndResolveEnabled(ctx context.Context, raw any, fieldBase string, r *resolver) (enabled bool, remaining any, err error) { //nolint:gocognit,gocyclo,cyclop // linear extraction with ref resolution
	m, ok := raw.(map[string]any)
	if !ok {
		// Not a map — will fail at unmarshal but let it through.
		return false, raw, nil
	}

	enabledRaw, exists := m["enabled"]
	if !exists {
		// No enabled field — defaults to false.
		return false, raw, nil
	}

	// If enabled is a string, it might be a ref+ URI.
	if s, isStr := enabledRaw.(string); isStr {
		if secrets.ContainsRef(s) && r == nil {
			return false, nil, fmt.Errorf(
				"%s.enabled: contains a secret reference but no provider is registered",
				fieldBase)
		}
		if r != nil {
			ref, pErr := secrets.ParseRef(s)
			if pErr != nil {
				return false, nil, fmt.Errorf("%s.enabled: %w", fieldBase, pErr)
			}
			if !ref.IsZero() {
				resolved, rErr := r.resolve(ctx, ref, fieldBase+".enabled")
				if rErr != nil {
					return false, nil, rErr
				}
				enabledRaw = resolved
			}
		}
	}

	// Guard: if enabledRaw came from a ref resolution, a non-boolean
	// value would leak the resolved secret through toBool's error
	// message. Validate before passing to toBool.
	if s, isStr := enabledRaw.(string); isStr {
		switch s {
		case "true", "false", "1", "0", "t", "f", "TRUE", "FALSE", "True", "False":
			// valid boolean string — fall through to toBool
		default:
			return false, nil, fmt.Errorf(
				"%s.enabled: resolved value is not a valid boolean",
				fieldBase)
		}
	}

	enabled, bErr := toBool(enabledRaw)
	if bErr != nil {
		return false, nil, fmt.Errorf("%s.enabled: %w", fieldBase, bErr)
	}

	// Remove "enabled" from map — it will be re-injected if true.
	delete(m, "enabled")
	return enabled, m, nil
}
