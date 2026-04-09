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

package vault_test

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
	"github.com/axonops/go-audit/secrets/vault"
)

// Compile-time check.
var _ secrets.Provider = (*vault.Provider)(nil)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func kvV2Handler(data map[string]any, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
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

func testProvider(t *testing.T, srv *httptest.Server) *vault.Provider {
	t.Helper()
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address:            srv.URL,
		Token:              "test-token",
		AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ---------------------------------------------------------------------------
// New — validation
// ---------------------------------------------------------------------------

func TestNew_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "http://vault.example.com", Token: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestNew_RequiresAddress(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Token: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address")
}

func TestNew_RequiresToken(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://vault.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestNew_RejectsEmbeddedCredentials(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://user:pass@vault.example.com", Token: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credentials")
}

func TestNew_RejectsEmptyHost(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://", Token: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty host")
}

func TestNew_RejectsMismatchedTLSCertKey(t *testing.T) {
	t.Parallel()
	_, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "t", TLSCert: "/some/cert.pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both be set")
}

func TestNew_LazyConnection(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://nonexistent.example.com:8200", Token: "t"})
	require.NoError(t, err)
	_ = p.Close()
}

func TestScheme(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "t"})
	require.NoError(t, err)
	assert.Equal(t, "vault", p.Scheme())
	_ = p.Close()
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

func TestResolve_Success(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"salt": "my-secret-salt"}, "test-token"))
	p := testProvider(t, srv)
	val, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "salt"})
	require.NoError(t, err)
	assert.Equal(t, "my-secret-salt", val)
}

func TestResolve_NotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/missing", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolve_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "correct-token"))
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address: srv.URL, Token: "wrong-token", AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "403")
}

func TestResolve_KeyNotInSecret(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"existing": "value"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "nonexistent"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.NotContains(t, err.Error(), "nonexistent")
}

func TestResolve_InvalidRef(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

func TestResolve_ContextCancellation(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	p := testProvider(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Resolve(ctx, secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
}

func TestResolve_NamespaceHeader(t *testing.T) {
	t.Parallel()
	var receivedNS string
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedNS = r.Header.Get("X-Vault-Namespace")
		resp := map[string]any{"data": map[string]any{"data": map[string]any{"key": "value"}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	p, err := vault.NewWithHTTPClient(&vault.Config{
		Address: srv.URL, Token: "test-token", Namespace: "team-b", AllowPrivateRanges: true,
	}, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "key"})
	require.NoError(t, err)
	assert.Equal(t, "team-b", receivedNS)
}

// ---------------------------------------------------------------------------
// String / GoString / Format — token redaction
// ---------------------------------------------------------------------------

func TestString_RedactsToken(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com:8200", Token: "hvs.super-secret"})
	require.NoError(t, err)
	defer func() { _ = p.Close() }()

	s := p.String()
	assert.Contains(t, s, "vault.example.com:8200")
	assert.Contains(t, s, "[REDACTED]")
	assert.NotContains(t, s, "hvs.super-secret")

	assert.NotContains(t, p.GoString(), "hvs.super-secret")
	assert.NotContains(t, fmt.Sprintf("%+v", p), "hvs.super-secret")
}

func TestClose_ZerosToken_Idempotent(t *testing.T) {
	t.Parallel()
	p, err := vault.New(&vault.Config{Address: "https://vault.example.com", Token: "secret-token"})
	require.NoError(t, err)
	// Close should zero token and be idempotent.
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
}

func TestResolve_DifferentKeys(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt": "salt-value", "version": "v1",
	}, "test-token"))
	p := testProvider(t, srv)

	v1, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "salt"})
	require.NoError(t, err)
	assert.Equal(t, "salt-value", v1)

	v2, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/hmac", Key: "version"})
	require.NoError(t, err)
	assert.Equal(t, "v1", v2)
}

func TestResolve_NonStringValue(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"count": 42}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "vault", Path: "secret/data/test", Key: "count"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "not a string")
	assert.NotContains(t, err.Error(), "count")
}
