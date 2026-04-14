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

package outputconfig_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
)

// ---------------------------------------------------------------------------
// YAML secrets: section — Load integration tests
// ---------------------------------------------------------------------------

func TestLoad_SecretsSection_OpenBao(t *testing.T) {
	// Start a TLS server that serves a KV v2 response.
	srv := httptest.NewTLSServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "this-is-a-test-salt-value-at-least-16-bytes",
		"version": "v1",
		"hash":    "HMAC-SHA-256",
	}, "test-bao-token"))
	t.Cleanup(srv.Close)

	// Write the server's CA cert to a file for the provider.
	caPath := writeTestCA(t, srv)

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", "test-bao-token")
	t.Setenv("BAO_CA", caPath)

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  timeout: "5s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    tls_ca: "${BAO_CA}"
    allow_private_ranges: true
outputs:
  console:
    type: stdout
    hmac:
      enabled: "ref+openbao://secret/data/hmac#enabled"
      salt:
        version: "ref+openbao://secret/data/hmac#version"
        value: "ref+openbao://secret/data/hmac#salt"
      hash: "ref+openbao://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.True(t, result.Outputs[0].HMACConfig.Enabled)
	assert.Equal(t, "this-is-a-test-salt-value-at-least-16-bytes", string(result.Outputs[0].HMACConfig.SaltValue))
	assert.Equal(t, "v1", result.Outputs[0].HMACConfig.SaltVersion)
}

func TestLoad_SecretsSection_Vault(t *testing.T) {
	srv := httptest.NewTLSServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "vault-salt-value-at-least-sixteen-bytes-long",
		"version": "v2",
		"hash":    "HMAC-SHA-512",
	}, "test-vault-token"))
	t.Cleanup(srv.Close)

	caPath := writeTestCA(t, srv)

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-vault-token")
	t.Setenv("VAULT_CA", caPath)

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    tls_ca: "${VAULT_CA}"
    allow_private_ranges: true
outputs:
  console:
    type: stdout
    hmac:
      enabled: "ref+vault://secret/data/hmac#enabled"
      salt:
        version: "ref+vault://secret/data/hmac#version"
        value: "ref+vault://secret/data/hmac#salt"
      hash: "ref+vault://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.True(t, result.Outputs[0].HMACConfig.Enabled)
	assert.Equal(t, "vault-salt-value-at-least-sixteen-bytes-long", string(result.Outputs[0].HMACConfig.SaltValue))
	assert.Equal(t, "v2", result.Outputs[0].HMACConfig.SaltVersion)
}

func TestLoad_SecretsSection_AllowInsecureHTTP(t *testing.T) {
	// Start an HTTP (not HTTPS) server.
	srv := httptest.NewServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "insecure-salt-value-at-least-sixteen-bytes",
		"version": "v1",
		"hash":    "HMAC-SHA-256",
	}, "test-token"))
	t.Cleanup(srv.Close)

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", "test-token")

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    allow_insecure_http: true
    allow_private_ranges: true
outputs:
  console:
    type: stdout
    hmac:
      enabled: "ref+openbao://secret/data/hmac#enabled"
      salt:
        version: "ref+openbao://secret/data/hmac#version"
        value: "ref+openbao://secret/data/hmac#salt"
      hash: "ref+openbao://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.Equal(t, "insecure-salt-value-at-least-sixteen-bytes", string(result.Outputs[0].HMACConfig.SaltValue))
}

func TestLoad_SecretsSection_UnknownProvider(t *testing.T) {
	t.Parallel()

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  consul:
    address: "https://consul.example.com"
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown provider")
	assert.Contains(t, err.Error(), "consul")
	assert.Contains(t, err.Error(), "openbao")
	assert.Contains(t, err.Error(), "vault")
}

func TestLoad_SecretsSection_UnknownField(t *testing.T) {
	t.Setenv("BAO_ADDR", "https://openbao.example.com")
	t.Setenv("BAO_TOKEN", "test-token")

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    typo_field: true
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "openbao")
}

func TestLoad_SecretsSection_DuplicateScheme_YAMLAndProgrammatic(t *testing.T) {
	t.Setenv("BAO_ADDR", "https://openbao.example.com")
	t.Setenv("BAO_TOKEN", "test-token")

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    allow_private_ranges: true
outputs:
  console:
    type: stdout
`
	// Create a programmatic provider with the same scheme.
	progProvider, err := openbao.New(&openbao.Config{
		Address:            "https://other-openbao.example.com",
		Token:              "other-token",
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	defer func() { _ = progProvider.Close() }()

	tax := testTaxonomy(t)
	_, err = outputconfig.Load(context.Background(), []byte(yamlConfig), tax,
		outputconfig.WithSecretProvider(progProvider),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "openbao")
	assert.Contains(t, err.Error(), "both YAML and WithSecretProvider")
}

func TestLoad_SecretsSection_TimeoutBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout string
		wantErr string
	}{
		{
			name:    "below minimum",
			timeout: "500ms",
			wantErr: "below minimum",
		},
		{
			name:    "above maximum",
			timeout: "5m",
			wantErr: "exceeds maximum",
		},
		{
			name:    "invalid duration",
			timeout: "not-a-duration",
			wantErr: "invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  timeout: "` + tt.timeout + `"
outputs:
  console:
    type: stdout
`
			tax := testTaxonomy(t)
			_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoad_SecretsSection_ValidTimeout(t *testing.T) {
	t.Parallel()

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  timeout: "30s"
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestLoad_SecretsSection_TimeoutPrecedence_WithSecretTimeoutWins(t *testing.T) {
	// Start a slow server that blocks for 4s.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(4 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	caPath := writeTestCA(t, srv)

	t.Setenv("BAO_ADDR", srv.URL)
	t.Setenv("BAO_TOKEN", "test-token")
	t.Setenv("BAO_CA", caPath)

	// YAML timeout is 30s, but WithSecretTimeout is 1s — should timeout.
	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  timeout: "30s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    tls_ca: "${BAO_CA}"
    allow_private_ranges: true
outputs:
  console:
    type: stdout
    hmac:
      enabled: "ref+openbao://secret/data/hmac#enabled"
      salt:
        version: "ref+openbao://secret/data/hmac#version"
        value: "ref+openbao://secret/data/hmac#salt"
      hash: "ref+openbao://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax,
		outputconfig.WithSecretTimeout(1*time.Second),
	)
	require.Error(t, err, "WithSecretTimeout(1s) should override YAML timeout(30s)")
}

func TestLoad_SecretsSection_NoSecrets_StillWorks(t *testing.T) {
	t.Parallel()

	yamlConfig := `
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestLoad_SecretsSection_EmptySecretsSection(t *testing.T) {
	t.Parallel()

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  timeout: "10s"
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestLoad_SecretsSection_MissingEnvVar(t *testing.T) {
	t.Parallel()

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${NONEXISTENT_BAO_ADDR}"
    token: "some-token"
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NONEXISTENT_BAO_ADDR")
}

func TestLoad_SecretsSection_ProviderConstructionError(t *testing.T) {
	// Missing token should cause provider construction to fail.
	t.Setenv("BAO_ADDR", "https://openbao.example.com")

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${BAO_ADDR}"
    token: ""
outputs:
  console:
    type: stdout
`
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "token")
}

func TestLoad_SecretsSection_VaultAllowInsecureHTTP(t *testing.T) {
	srv := httptest.NewServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "vault-http-salt-value-at-least-sixteen-bytes",
		"version": "v1",
		"hash":    "HMAC-SHA-256",
	}, "test-vault-token"))
	t.Cleanup(srv.Close)

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-vault-token")

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    allow_insecure_http: true
    allow_private_ranges: true
outputs:
  console:
    type: stdout
    hmac:
      enabled: "ref+vault://secret/data/hmac#enabled"
      salt:
        version: "ref+vault://secret/data/hmac#version"
        value: "ref+vault://secret/data/hmac#salt"
      hash: "ref+vault://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.Equal(t, "vault-http-salt-value-at-least-sixteen-bytes", string(result.Outputs[0].HMACConfig.SaltValue))
}

func TestLoad_SecretsSection_BothProviders(t *testing.T) {
	baoSrv := httptest.NewTLSServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "bao-salt-value-at-least-sixteen-bytes-long",
		"version": "v1",
		"hash":    "HMAC-SHA-256",
	}, "bao-token"))
	t.Cleanup(baoSrv.Close)

	vaultSrv := httptest.NewTLSServer(kvHandler(map[string]any{
		"enabled": "true",
		"salt":    "vault-salt-value-at-least-sixteen-bytes-long",
		"version": "v2",
		"hash":    "HMAC-SHA-512",
	}, "vault-token"))
	t.Cleanup(vaultSrv.Close)

	baoCA := writeTestCA(t, baoSrv)
	vaultCA := writeTestCA(t, vaultSrv)

	t.Setenv("BAO_ADDR", baoSrv.URL)
	t.Setenv("BAO_TOKEN", "bao-token")
	t.Setenv("BAO_CA", baoCA)
	t.Setenv("VAULT_ADDR", vaultSrv.URL)
	t.Setenv("VAULT_TOKEN", "vault-token")
	t.Setenv("VAULT_CA", vaultCA)

	yamlConfig := `
version: 1
app_name: test
host: test
secrets:
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    tls_ca: "${BAO_CA}"
    allow_private_ranges: true
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
    tls_ca: "${VAULT_CA}"
    allow_private_ranges: true
outputs:
  bao_output:
    type: stdout
    hmac:
      enabled: "ref+openbao://secret/data/hmac#enabled"
      salt:
        version: "ref+openbao://secret/data/hmac#version"
        value: "ref+openbao://secret/data/hmac#salt"
      hash: "ref+openbao://secret/data/hmac#hash"
  vault_output:
    type: stdout
    hmac:
      enabled: "ref+vault://secret/data/hmac#enabled"
      salt:
        version: "ref+vault://secret/data/hmac#version"
        value: "ref+vault://secret/data/hmac#salt"
      hash: "ref+vault://secret/data/hmac#hash"
`
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), []byte(yamlConfig), tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 2)

	assert.Equal(t, "bao-salt-value-at-least-sixteen-bytes-long", string(result.Outputs[0].HMACConfig.SaltValue))
	assert.Equal(t, "vault-salt-value-at-least-sixteen-bytes-long", string(result.Outputs[1].HMACConfig.SaltValue))
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func kvHandler(data map[string]any, expectedToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != expectedToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := map[string]any{
			"data": map[string]any{"data": data},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func writeTestCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	// Extract the server's certificate.
	certs := srv.TLS.Certificates
	require.NotEmpty(t, certs)

	cert, err := x509.ParseCertificate(certs[0].Certificate[0])
	require.NoError(t, err)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	f, err := os.Create(caPath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	return caPath
}

// testTaxonomy is defined in outputconfig_test.go — shared across test files.
