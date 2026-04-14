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
	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/openbao"
	"github.com/axonops/audit/secrets/vault"
	"github.com/goccy/go-yaml"
)

// minSecretTimeout is the minimum secret resolution timeout accepted
// from YAML configuration.
const minSecretTimeout = 1 * time.Second

// maxSecretTimeout is the maximum secret resolution timeout accepted
// from YAML configuration.
const maxSecretTimeout = 120 * time.Second

// supportedProviders lists the provider scheme names recognised by the
// secrets: section. Used in error messages to guide configuration.
var supportedProviders = []string{"openbao", "vault"}

// secretsResult holds the providers and timeout parsed from the YAML
// secrets: section.
type secretsResult struct {
	providers []secrets.Provider
	timeout   time.Duration // zero means not specified in YAML
}

// parseSecretsSection parses the secrets: top-level YAML value into
// provider instances and an optional timeout. Only environment variable
// substitution is applied — ref+ URIs are NOT resolved (providers must
// exist before secret references can be resolved; resolving secrets to
// construct providers would be circular).
//
// Tokens are handled as Go strings during parsing and passed to
// provider constructors which store them as []byte for zeroing in
// Close(). The original Go strings remain in heap memory until GC
// collects them (same caveat as programmatic API usage).
//
// The caller must Close() all returned providers when done.
func parseSecretsSection(raw any) (*secretsResult, error) { //nolint:gocognit,gocyclo,cyclop // YAML field dispatch mirrors parseTopLevel pattern
	// Expand environment variables.
	expanded, err := expandEnvInValue(raw, "secrets")
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}

	m, ok := expanded.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: secrets must be a YAML mapping", ErrOutputConfigInvalid)
	}

	result := &secretsResult{}

	// closeOnError cleans up already-constructed providers when a
	// later step fails. Prevents token material from persisting in
	// memory and HTTP transport leaks.
	closeOnError := func() {
		for _, p := range result.providers {
			_ = p.Close()
		}
	}

	// Process timeout first (fail-fast before any provider construction).
	if val, ok := m["timeout"]; ok {
		s, sErr := toString(val)
		if sErr != nil {
			return nil, fmt.Errorf("%w: secrets.timeout: %w", ErrOutputConfigInvalid, sErr)
		}
		d, dErr := time.ParseDuration(s)
		if dErr != nil {
			return nil, fmt.Errorf("%w: secrets.timeout: invalid duration %q: %w",
				ErrOutputConfigInvalid, s, dErr)
		}
		if d < minSecretTimeout {
			return nil, fmt.Errorf("%w: secrets.timeout: %s is below minimum %s",
				ErrOutputConfigInvalid, d, minSecretTimeout)
		}
		if d > maxSecretTimeout {
			return nil, fmt.Errorf("%w: secrets.timeout: %s exceeds maximum %s",
				ErrOutputConfigInvalid, d, maxSecretTimeout)
		}
		result.timeout = d
		delete(m, "timeout")
	}

	// Remaining keys are provider scheme names.
	for key, val := range m {
		switch key {
		case "openbao":
			p, pErr := parseOpenBaoProvider(val)
			if pErr != nil {
				closeOnError()
				return nil, pErr
			}
			result.providers = append(result.providers, p)

		case "vault":
			p, pErr := parseVaultProvider(val)
			if pErr != nil {
				closeOnError()
				return nil, pErr
			}
			result.providers = append(result.providers, p)

		default:
			closeOnError()
			return nil, fmt.Errorf("%w: secrets: unknown provider %q (supported: %v)",
				ErrOutputConfigInvalid, key, supportedProviders)
		}
	}

	return result, nil
}

// yamlProviderConfig is the YAML structure for both openbao and vault
// provider configuration. Fields match the Go Config structs.
type yamlProviderConfig struct { //nolint:govet // readability over alignment
	Address            string         `yaml:"address"`
	Token              string         `yaml:"token"`
	Namespace          string         `yaml:"namespace"`
	TLSCA              string         `yaml:"tls_ca"`
	TLSCert            string         `yaml:"tls_cert"`
	TLSKey             string         `yaml:"tls_key"`
	TLSPolicy          *yamlTLSPolicy `yaml:"tls_policy"`
	AllowInsecureHTTP  bool           `yaml:"allow_insecure_http"`
	AllowPrivateRanges bool           `yaml:"allow_private_ranges"`
}

// String returns a redacted representation to prevent token leakage
// if the struct is accidentally passed to a logging or formatting call.
func (yamlProviderConfig) String() string { return "[REDACTED]" }

// GoString prevents token leakage via %#v.
func (yamlProviderConfig) GoString() string { return "[REDACTED]" }

// parseOpenBaoProvider constructs an [openbao.Provider] from parsed
// YAML configuration.
func parseOpenBaoProvider(raw any) (secrets.Provider, error) {
	cfg, err := unmarshalProviderConfig(raw, "openbao")
	if err != nil {
		return nil, err
	}

	var tlsPolicy *audit.TLSPolicy
	if cfg.TLSPolicy != nil {
		tlsPolicy = &audit.TLSPolicy{
			AllowTLS12:       cfg.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: cfg.TLSPolicy.AllowWeakCiphers,
		}
	}

	p, pErr := openbao.New(&openbao.Config{
		Address:            cfg.Address,
		Token:              cfg.Token,
		Namespace:          cfg.Namespace,
		TLSCA:              cfg.TLSCA,
		TLSCert:            cfg.TLSCert,
		TLSKey:             cfg.TLSKey,
		TLSPolicy:          tlsPolicy,
		AllowInsecureHTTP:  cfg.AllowInsecureHTTP,
		AllowPrivateRanges: cfg.AllowPrivateRanges,
	})
	if pErr != nil {
		return nil, fmt.Errorf("%w: secrets.openbao: %w", ErrOutputConfigInvalid, pErr)
	}
	return p, nil
}

// parseVaultProvider constructs a [vault.Provider] from parsed YAML
// configuration.
func parseVaultProvider(raw any) (secrets.Provider, error) {
	cfg, err := unmarshalProviderConfig(raw, "vault")
	if err != nil {
		return nil, err
	}

	var tlsPolicy *audit.TLSPolicy
	if cfg.TLSPolicy != nil {
		tlsPolicy = &audit.TLSPolicy{
			AllowTLS12:       cfg.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: cfg.TLSPolicy.AllowWeakCiphers,
		}
	}

	p, pErr := vault.New(&vault.Config{
		Address:            cfg.Address,
		Token:              cfg.Token,
		Namespace:          cfg.Namespace,
		TLSCA:              cfg.TLSCA,
		TLSCert:            cfg.TLSCert,
		TLSKey:             cfg.TLSKey,
		TLSPolicy:          tlsPolicy,
		AllowInsecureHTTP:  cfg.AllowInsecureHTTP,
		AllowPrivateRanges: cfg.AllowPrivateRanges,
	})
	if pErr != nil {
		return nil, fmt.Errorf("%w: secrets.vault: %w", ErrOutputConfigInvalid, pErr)
	}
	return p, nil
}

// unmarshalProviderConfig marshals a parsed YAML value back to bytes
// and unmarshals it into [yamlProviderConfig] with strict field
// checking. This rejects unknown fields (typos) with an actionable
// error.
func unmarshalProviderConfig(raw any, providerName string) (*yamlProviderConfig, error) {
	b, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: secrets.%s: %w", ErrOutputConfigInvalid, providerName, err)
	}

	var cfg yamlProviderConfig
	if uErr := yaml.UnmarshalWithOptions(b, &cfg, yaml.DisallowUnknownField()); uErr != nil {
		return nil, fmt.Errorf("%w: secrets.%s: %w", ErrOutputConfigInvalid, providerName, uErr)
	}

	return &cfg, nil
}

// extractAndParseSecrets extracts the secrets: key from a MapSlice,
// parses it into providers and timeout, and returns the remaining
// MapSlice with secrets: removed. If no secrets: key is present,
// returns the original doc unchanged with nil providers.
func extractAndParseSecrets(doc yaml.MapSlice) (filtered yaml.MapSlice, providers []secrets.Provider, timeout time.Duration, err error) {
	var secretsRaw any
	filtered = make(yaml.MapSlice, 0, len(doc))
	for _, item := range doc {
		key, ok := item.Key.(string)
		if ok && key == "secrets" {
			secretsRaw = item.Value
			continue
		}
		filtered = append(filtered, item)
	}

	if secretsRaw == nil {
		return filtered, nil, 0, nil
	}

	result, pErr := parseSecretsSection(secretsRaw)
	if pErr != nil {
		return nil, nil, 0, pErr
	}

	return filtered, result.providers, result.timeout, nil
}

// mergeProviders combines programmatic providers (from WithSecretProvider)
// with YAML-created providers. Returns an error if a scheme appears in
// both sources.
func mergeProviders(programmatic, yamlCreated []secrets.Provider) ([]secrets.Provider, error) {
	if len(yamlCreated) == 0 {
		return programmatic, nil
	}
	if len(programmatic) == 0 {
		return yamlCreated, nil
	}

	// Check for duplicate schemes between programmatic and YAML.
	progSchemes := make(map[string]struct{}, len(programmatic))
	for _, p := range programmatic {
		progSchemes[p.Scheme()] = struct{}{}
	}
	for _, p := range yamlCreated {
		if _, dup := progSchemes[p.Scheme()]; dup {
			return nil, fmt.Errorf("%w: secret provider scheme %q configured in both YAML and WithSecretProvider",
				ErrOutputConfigInvalid, p.Scheme())
		}
	}

	combined := make([]secrets.Provider, 0, len(programmatic)+len(yamlCreated))
	combined = append(combined, programmatic...)
	combined = append(combined, yamlCreated...)
	return combined, nil
}
