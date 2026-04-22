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

package steps

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cucumber/godog"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
	"github.com/axonops/audit/secrets/vault"
)

// registerRealSecretSteps registers steps for scenarios that use real
// OpenBao/Vault containers (tagged @docker).
func registerRealSecretSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(
		`^a real (openbao|vault) provider at "([^"]*)" with token "([^"]*)" from container "([^"]*)"$`,
		tc.stepRealProvider,
	)

	ctx.Step(
		`^the real provider has secret at path "([^"]*)" with:$`,
		tc.stepRealSeedSecret,
	)

	ctx.Step(
		`^the following output configuration YAML is loaded with the real provider:$`,
		tc.stepLoadYAMLWithRealProvider,
	)

	ctx.Step(
		`^the HMAC config should have salt "([^"]*)"$`,
		tc.stepAssertHMACSalt,
	)

	ctx.Step(
		`^the HMAC config should have algorithm "([^"]*)"$`,
		tc.stepAssertHMACAlgorithm,
	)
}

// stepRealProvider extracts the CA cert from the container and creates
// a real provider.
func (tc *TestContext) stepRealProvider(provider, addr, token, container string) error {
	// Extract CA cert from container.
	out, err := exec.Command("docker", "exec", container,
		"sh", "-c", "cat /tmp/vault-tls*/vault-ca.pem").Output()
	if err != nil {
		return fmt.Errorf("extract CA from %s: %w (is the container running?)", container, err)
	}

	dir, mkErr := os.MkdirTemp("", "bdd-real-secrets-*")
	if mkErr != nil {
		return fmt.Errorf("create temp dir: %w", mkErr)
	}
	tc.realSecretsTempDir = dir
	caPath := filepath.Join(dir, "ca.pem")
	if wErr := os.WriteFile(caPath, out, 0o600); wErr != nil {
		return fmt.Errorf("write CA cert: %w", wErr)
	}

	tc.realProviderAddr = addr
	tc.realProviderToken = token
	tc.realProviderCAPath = caPath

	// Create provider.
	switch provider {
	case "openbao":
		p, pErr := openbao.New(&openbao.Config{
			Address:            addr,
			Token:              token,
			TLSCA:              caPath,
			AllowPrivateRanges: true,
		})
		if pErr != nil {
			return fmt.Errorf("create openbao provider: %w", pErr)
		}
		tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(p))
		tc.realProviderCleanup = append(tc.realProviderCleanup, func() { _ = p.Close() })
	case "vault":
		p, pErr := vault.New(&vault.Config{
			Address:            addr,
			Token:              token,
			TLSCA:              caPath,
			AllowPrivateRanges: true,
		})
		if pErr != nil {
			return fmt.Errorf("create vault provider: %w", pErr)
		}
		tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(p))
		tc.realProviderCleanup = append(tc.realProviderCleanup, func() { _ = p.Close() })
	default:
		return fmt.Errorf("unknown provider type %q", provider)
	}

	return nil
}

// stepRealSeedSecret accumulates secret data for seeding.
func (tc *TestContext) stepRealSeedSecret(path string, table *godog.Table) error {
	if tc.realProviderPendingSeeds == nil {
		tc.realProviderPendingSeeds = make(map[string]map[string]string)
	}
	if tc.realProviderPendingSeeds[path] == nil {
		tc.realProviderPendingSeeds[path] = make(map[string]string)
	}
	for _, row := range table.Rows[1:] { // skip header
		key := row.Cells[0].Value
		value := row.Cells[1].Value
		tc.realProviderPendingSeeds[path][key] = value
	}
	return nil
}

// stepLoadYAMLWithRealProvider flushes seeds and loads YAML with the
// real provider.
func (tc *TestContext) stepLoadYAMLWithRealProvider(doc *godog.DocString) error {
	// Flush seeds to real container.
	if err := tc.flushRealSeeds(); err != nil {
		return fmt.Errorf("flush seeds: %w", err)
	}

	// Delegate to the existing provider-aware load step.
	return tc.stepLoadYAMLWithProviders(doc)
}

// flushRealSeeds posts accumulated seeds to the real container.
func (tc *TestContext) flushRealSeeds() error {
	if tc.realProviderPendingSeeds == nil {
		return nil
	}

	client, err := tc.realSeedHTTPClient()
	if err != nil {
		return err
	}

	for path, kv := range tc.realProviderPendingSeeds {
		payload := map[string]any{"data": kv}
		body, mErr := json.Marshal(payload)
		if mErr != nil {
			return fmt.Errorf("marshal seed data: %w", mErr)
		}

		url := tc.realProviderAddr + "/v1/" + path
		req, rErr := http.NewRequestWithContext(context.Background(),
			http.MethodPost, url, bytes.NewReader(body))
		if rErr != nil {
			return fmt.Errorf("build seed request: %w", rErr)
		}
		req.Header.Set("X-Vault-Token", tc.realProviderToken)
		req.Header.Set("Content-Type", "application/json")

		resp, dErr := client.Do(req)
		if dErr != nil {
			return fmt.Errorf("seed %s: %w", path, dErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("seed %s: status %d", path, resp.StatusCode)
		}
	}
	tc.realProviderPendingSeeds = nil
	return nil
}

func (tc *TestContext) realSeedHTTPClient() (*http.Client, error) {
	if tc.realProviderCAPath == "" {
		return nil, fmt.Errorf("no CA cert path — was the provider step run?")
	}
	caCert, err := os.ReadFile(tc.realProviderCAPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert PEM")
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		},
	}, nil
}

// stepAssertHMACSalt checks the HMAC salt on the first output.
func (tc *TestContext) stepAssertHMACSalt(expected string) error {
	if tc.LoadResult == nil {
		return fmt.Errorf("no load result")
	}
	meta := tc.LoadResult.OutputMetadata()
	if len(meta) == 0 {
		return fmt.Errorf("no outputs")
	}
	hmac := meta[0].HMACConfig
	if hmac == nil {
		return fmt.Errorf("HMAC config is nil")
	}
	actual := string(hmac.SaltValue)
	if actual != expected {
		return fmt.Errorf("HMAC salt: got %q, want %q", actual, expected)
	}
	return nil
}

// stepAssertHMACAlgorithm checks the HMAC algorithm on the first output.
func (tc *TestContext) stepAssertHMACAlgorithm(expected string) error {
	if tc.LoadResult == nil {
		return fmt.Errorf("no load result")
	}
	meta := tc.LoadResult.OutputMetadata()
	if len(meta) == 0 {
		return fmt.Errorf("no outputs")
	}
	hmac := meta[0].HMACConfig
	if hmac == nil {
		return fmt.Errorf("HMAC config is nil")
	}
	if hmac.Algorithm != expected {
		return fmt.Errorf("HMAC algorithm: got %q, want %q", hmac.Algorithm, expected)
	}
	return nil
}
