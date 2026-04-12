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

//go:build integration

// Package integration tests the OpenBao provider against a real
// OpenBao server running in Docker with dev-tls mode.
//
// Prerequisites:
//
//	make test-infra-openbao-up
package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/openbao"
)

const (
	openbaoAddr  = "https://localhost:8200"
	openbaoToken = "test-root-token"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}

// extractCA copies the dev-tls CA certificate from the container.
func extractCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	out, err := exec.Command("docker", "exec", "bdd-openbao-1",
		"sh", "-c", "cat /tmp/vault-tls*/vault-ca.pem").Output()
	require.NoError(t, err, "extract CA cert from container")
	require.NotEmpty(t, out, "CA cert must not be empty")

	require.NoError(t, os.WriteFile(caPath, out, 0o600))
	return caPath
}

// seedSecret writes a KV v2 secret to OpenBao.
func seedSecret(t *testing.T, caPath, path string, data map[string]string) {
	t.Helper()
	payload := map[string]any{"data": data}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	url := openbaoAddr + "/v1/" + path
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", openbaoToken)
	req.Header.Set("Content-Type", "application/json")

	client := seedHTTPClient(t, caPath)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"seed secret at %s", path)
}

func seedHTTPClient(t *testing.T, caPath string) *http.Client {
	t.Helper()
	caCert, err := os.ReadFile(caPath) //nolint:gosec // test fixture
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caCert), "parse CA PEM")
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, //nolint:gosec // test only
		},
	}
}

func newProvider(t *testing.T, caPath string) *openbao.Provider {
	t.Helper()
	p, err := openbao.New(&openbao.Config{
		Address:            openbaoAddr,
		Token:              openbaoToken,
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestResolve_Success(t *testing.T) {
	caPath := extractCA(t)
	seedSecret(t, caPath, "secret/data/integration/hmac", map[string]string{
		"salt":      "real-openbao-salt-value-32bytes!",
		"version":   "v1",
		"algorithm": "HMAC-SHA-256",
		"enabled":   "true",
	})
	p := newProvider(t, caPath)

	val, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/integration/hmac", Key: "salt",
	})
	require.NoError(t, err)
	assert.Equal(t, "real-openbao-salt-value-32bytes!", val)
}

func TestResolvePath_AllKeys(t *testing.T) {
	caPath := extractCA(t)
	seedSecret(t, caPath, "secret/data/integration/all-keys", map[string]string{
		"key1": "value1", "key2": "value2", "key3": "value3",
	})
	p := newProvider(t, caPath)

	allKeys, err := p.ResolvePath(context.Background(),
		"secret/data/integration/all-keys")
	require.NoError(t, err)
	assert.Equal(t, "value1", allKeys["key1"])
	assert.Equal(t, "value2", allKeys["key2"])
	assert.Equal(t, "value3", allKeys["key3"])
	assert.Len(t, allKeys, 3)
}

func TestResolve_PathNotFound(t *testing.T) {
	caPath := extractCA(t)
	p := newProvider(t, caPath)

	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/nonexistent", Key: "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolve_KeyNotFound(t *testing.T) {
	caPath := extractCA(t)
	seedSecret(t, caPath, "secret/data/integration/keytest", map[string]string{
		"existing": "value",
	})
	p := newProvider(t, caPath)

	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/integration/keytest", Key: "missing",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolve_AuthFailure(t *testing.T) {
	caPath := extractCA(t)
	p, err := openbao.New(&openbao.Config{
		Address:            openbaoAddr,
		Token:              "wrong-token",
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/integration/hmac", Key: "salt",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
}

func TestResolve_ErrorDoesNotLeakPath(t *testing.T) {
	caPath := extractCA(t)
	p, err := openbao.New(&openbao.Config{
		Address:            openbaoAddr,
		Token:              "wrong-token",
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/sensitive/topology", Key: "key",
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret/data/sensitive/topology",
		"vault path must not leak in error messages")
}
