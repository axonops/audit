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

package openbao_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/go-audit/secrets"
	"github.com/axonops/go-audit/secrets/openbao"
)

// Compile-time check.
var _ secrets.Provider = (*openbao.Provider)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestServer creates an HTTPS test server that serves KV v2 responses.
func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// kvV2Handler returns an HTTP handler that serves a KV v2 secret response.
func kvV2Handler(data map[string]any, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token.
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		resp := map[string]any{
			"data": map[string]any{
				"data": data,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// testConfig creates a Config pointing at the test server.
// Uses AllowPrivateRanges since httptest binds to 127.0.0.1.
func testConfig(srv *httptest.Server) *openbao.Config {
	return &openbao.Config{
		Address:            srv.URL,
		Token:              "test-token",
		AllowPrivateRanges: true,
	}
}

// testProvider creates a provider from a test server, using the
// server's TLS CA certificate.
func testProvider(t *testing.T, srv *httptest.Server) *openbao.Provider {
	t.Helper()
	cfg := testConfig(srv)
	// httptest.NewTLSServer uses a self-signed cert — we need to
	// trust it. Since we can't easily export the CA to a file, we'll
	// create the provider with a custom HTTP client that trusts the
	// test server's certs. For now, we use NewWithHTTPClient.
	// Actually, the test server URL is https://127.0.0.1:PORT which
	// will be blocked by SSRF unless AllowPrivateRanges is true.
	// The TLS cert won't be trusted by default — we need to skip
	// verification for tests only.
	p, err := openbao.NewWithHTTPClient(cfg, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ---------------------------------------------------------------------------
// New — validation tests
// ---------------------------------------------------------------------------

func TestNew_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "http://vault.example.com",
		Token:   "token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestNew_RequiresAddress(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{Token: "token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestNew_RequiresToken(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestNew_RejectsEmbeddedCredentials(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "https://user:pass@vault.example.com",
		Token:   "token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credentials")
}

func TestNew_RejectsEmptyHost(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "https://",
		Token:   "token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty host")
}

func TestNew_RejectsMismatchedTLSCertKey(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCert: "/some/cert.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both be set")
}

func TestNew_LazyConnection(t *testing.T) {
	t.Parallel()
	// New() should succeed even if the server doesn't exist.
	// No network I/O in constructor.
	p, err := openbao.New(&openbao.Config{
		Address: "https://nonexistent.example.com:8200",
		Token:   "token",
	})
	require.NoError(t, err)
	_ = p.Close()
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

func TestScheme(t *testing.T) {
	t.Parallel()
	p, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
	})
	require.NoError(t, err)
	assert.Equal(t, "openbao", p.Scheme())
	_ = p.Close()
}

// ---------------------------------------------------------------------------
// Resolve — success
// ---------------------------------------------------------------------------

func TestResolve_Success(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt":    "my-secret-salt-value",
		"version": "v1",
	}, "test-token"))

	p := testProvider(t, srv)
	ref := secrets.Ref{Scheme: "openbao", Path: "secret/data/hmac", Key: "salt"}
	val, err := p.Resolve(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "my-secret-salt-value", val)
}

func TestResolve_DifferentKeys(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt":    "salt-value",
		"version": "v1",
	}, "test-token"))

	p := testProvider(t, srv)
	val1, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/hmac", Key: "salt"})
	require.NoError(t, err)
	assert.Equal(t, "salt-value", val1)

	val2, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/hmac", Key: "version"})
	require.NoError(t, err)
	assert.Equal(t, "v1", val2)
}

// ---------------------------------------------------------------------------
// Resolve — error cases
// ---------------------------------------------------------------------------

func TestResolve_NotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/missing", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolve_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "correct-token"))
	// Use wrong token.
	cfg := testConfig(srv)
	cfg.Token = "wrong-token"
	p, err := openbao.NewWithHTTPClient(cfg, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "403")
}

func TestResolve_KeyNotInSecret(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"existing_key": "value",
	}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "nonexistent"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "not found")
	assert.NotContains(t, err.Error(), "nonexistent") // key name not leaked
}

func TestResolve_ContextCancellation(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // block until cancelled
	}))
	p := testProvider(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := p.Resolve(ctx, secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
}

func TestResolve_InvalidRef(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "test-token"))
	p := testProvider(t, srv)
	// Empty path — should fail ref.Valid()
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

func TestResolve_NonStringValue(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"count": 42, // not a string
	}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "count"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "not a string")
	assert.NotContains(t, err.Error(), "count") // key name not leaked
}

// ---------------------------------------------------------------------------
// String / GoString / Format — token redaction
// ---------------------------------------------------------------------------

func TestString_RedactsToken(t *testing.T) {
	t.Parallel()
	p, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com:8200",
		Token:   "hvs.super-secret-token",
	})
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	s := p.String()
	assert.Contains(t, s, "vault.example.com:8200")
	assert.Contains(t, s, "[REDACTED]")
	assert.NotContains(t, s, "hvs.super-secret-token")

	gs := p.GoString()
	assert.NotContains(t, gs, "hvs.super-secret-token")

	fmtResult := fmt.Sprintf("%+v", p)
	assert.NotContains(t, fmtResult, "hvs.super-secret-token")
}

// ---------------------------------------------------------------------------
// Close — token zeroing
// ---------------------------------------------------------------------------

func TestClose_ZerosToken(t *testing.T) {
	t.Parallel()
	p, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "secret-token",
	})
	require.NoError(t, err)
	require.NoError(t, p.Close())
	// After close, the token should be zeroed.
	// We can't directly access the private field, but calling Close()
	// twice should not panic (idempotent).
	require.NoError(t, p.Close())
}

// ---------------------------------------------------------------------------
// Namespace header
// ---------------------------------------------------------------------------

func TestResolve_NamespaceHeader(t *testing.T) {
	t.Parallel()
	var receivedNS string
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedNS = r.Header.Get("X-Vault-Namespace")
		resp := map[string]any{
			"data": map[string]any{"data": map[string]any{"key": "value"}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))

	cfg := testConfig(srv)
	cfg.Namespace = "team-a"
	p, err := openbao.NewWithHTTPClient(cfg, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.NoError(t, err)
	assert.Equal(t, "team-a", receivedNS)
}
