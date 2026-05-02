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

// Package integration_test contains the triple-integration end-to-end
// test (#574): a real OpenBao container resolves a bearer token via
// outputconfig's ref+openbao:// URI, the resolved token is wired into
// a webhook output's Authorization header, and a real webhook-receiver
// container observes the event with the expected header value.
//
// The test exercises the complete secret-resolution → outputconfig →
// webhook delivery path without any mocks. Without this scenario, the
// secret-resolution unit tests prove the provider works in isolation,
// the webhook unit tests prove the output works in isolation, but
// nothing pins the join: that an outputs.yaml ref+ URI in a header
// reaches the destination as a Bearer header literally containing the
// resolved plaintext.
//
// Requires Docker Compose infrastructure: `make test-infra-up`
// (brings up openbao + webhook-receiver among others).
package integration_test

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
)

const (
	openbaoAddr     = "https://localhost:8200"
	openbaoRootTok  = "test-root-token"
	openbaoSecPath  = "secret/data/audit/integration/webhook-bearer"
	openbaoBearer   = "trIp1e-1nt3gr@ti0n-bearer-32by!" // 32-byte bearer the test seeds
	openbaoSecField = "authorization"
	// fullAuthorization is the literal value the secret stores AND
	// the literal value the webhook receiver MUST observe in the
	// Authorization header. The secret-resolver requires ref+ to be
	// at the start of the YAML string (see docs/secrets.md
	// "Embedding Refs in Larger Strings"), so the "Bearer " prefix
	// is part of the stored secret rather than being concatenated
	// at YAML-load time.
	fullAuthorization = "Bearer " + openbaoBearer
)

// extractOpenbaoCA copies the dev-tls CA cert from the OpenBao
// container into a temp file and returns its path. Mirrors the
// pattern used by secrets/openbao/tests/integration/openbao_test.go:
// the dev-tls server writes its self-signed CA under
// /tmp/vault-tls*/vault-ca.pem (with a per-run subdirectory). The
// glob-shell-cat dance handles the random subdirectory name.
func extractOpenbaoCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "openbao-ca.pem")

	out, err := exec.Command("docker", "exec", "bdd-openbao-1", //nolint:gosec // hard-coded container name from compose
		"sh", "-c", "cat /tmp/vault-tls*/vault-ca.pem").Output()
	require.NoError(t, err, "extract openbao CA cert from bdd-openbao-1 container")
	require.NotEmpty(t, out, "openbao CA cert must not be empty")

	require.NoError(t, os.WriteFile(caPath, out, 0o600))
	return caPath
}

// seedBearerSecret writes the bearer token to OpenBao via the
// HTTP KV v2 API. Equivalent to `bao kv put`.
func seedBearerSecret(t *testing.T, caPath string) {
	t.Helper()

	caCert, err := os.ReadFile(caPath) //nolint:gosec // test fixture
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caCert), "parse openbao CA PEM")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	payload, err := json.Marshal(map[string]any{
		"data": map[string]string{openbaoSecField: fullAuthorization},
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, openbaoAddr+"/v1/"+openbaoSecPath, bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("X-Vault-Token", openbaoRootTok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"seed bearer secret at %s (status=%d)", openbaoSecPath, resp.StatusCode)
}

// TestE2E_SecretsResolveBearer_DeliveredAsAuthorizationHeader pins
// the full path: provider resolution → outputconfig wiring → webhook
// delivery. AC mapping (#574):
//   - AC1: test exists and passes under make test-integration
//   - AC2: real openbao + real webhook-receiver containers (no httptest)
//   - AC3: TestMain in fanout_test.go runs goleak.VerifyTestMain
func TestE2E_SecretsResolveBearer_DeliveredAsAuthorizationHeader(t *testing.T) {
	resetWebhook(t)

	caPath := extractOpenbaoCA(t)
	seedBearerSecret(t, caPath)

	// Build a programmatic openbao provider (the YAML-secrets path
	// exists too, but constructing the provider directly keeps the
	// test self-contained and matches outputconfig.WithSecretProvider's
	// public surface).
	provider, err := openbao.New(&openbao.Config{
		Address:            openbaoAddr,
		Token:              openbaoRootTok,
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	// outputconfig.Load does NOT close programmatically-registered
	// providers (see docs/writing-custom-secret-providers.md §
	// Registration), so the test owns provider.Close().
	defer func() { _ = provider.Close() }()

	// outputs.yaml threads the resolved bearer through to the
	// webhook's Authorization header.
	outputsYAML := []byte(fmt.Sprintf(`
version: 1
app_name: e2e-secrets-webhook
host: integration-host

outputs:
  bearer_webhook:
    type: webhook
    webhook:
      url: %q
      allow_insecure_http: true
      allow_private_ranges: true
      batch_size: 1
      flush_interval: "100ms"
      timeout: "5s"
      max_retries: 1
      headers:
        Authorization: "ref+openbao://%s#%s"
`, webhookURL+"/events", openbaoSecPath, openbaoSecField))

	// Embed a minimal taxonomy so outputconfig.Load has a schema
	// to validate against. Same shape as fanout_test's testTaxonomy
	// but inline to keep this test self-contained.
	taxonomyYAML := []byte(`
version: 1
categories:
  write:
    severity: 3
    events: [user_create]
events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome: { required: true }
      actor_id: { required: true }
`)

	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	require.NoError(t, err)

	loaded, err := outputconfig.Load(context.Background(), outputsYAML, tax,
		outputconfig.WithSecretProvider(provider))
	require.NoError(t, err)

	auditor, err := audit.New(append([]audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithAppName("e2e-secrets-webhook"),
		audit.WithHost("integration-host"),
	}, loaded.Options()...)...)
	require.NoError(t, err)

	// Emit a uniquely-marked event so the assertion can disambiguate
	// our event from anything left in the receiver from a previous
	// test (resetWebhook is also called above, defence in depth).
	m := marker(t)
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"marker":   m,
	}))
	require.NoError(t, err)

	// Close flushes the webhook batch and waits for delivery.
	require.NoError(t, auditor.Close())

	// Assert: the webhook receiver got our event with the resolved
	// bearer in the Authorization header.
	require.True(t,
		waitForWebhookEvents(t, 1, 5*time.Second),
		"webhook-receiver should have received exactly one event")

	events := getWebhookEvents(t)
	require.Len(t, events, 1, "expected exactly one delivered event")

	hdrs, ok := events[0]["headers"].(map[string]any)
	require.True(t, ok, "events[0].headers should decode as an object")
	got, ok := hdrs["Authorization"].(string)
	require.Truef(t, ok, "events[0].headers.Authorization should decode as a string (raw=%v)", hdrs["Authorization"])

	assert.Equalf(t, fullAuthorization, got,
		"webhook receiver should observe the openbao-resolved Authorization value literally (got=%q want=%q)", got, fullAuthorization)

	// Pin the join: the body MUST also contain our marker so we
	// know we're inspecting the right event.
	body, ok := events[0]["body"]
	require.True(t, ok, "events[0].body should be present")
	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyJSON), m,
		"webhook event body should contain the unique marker")
}
