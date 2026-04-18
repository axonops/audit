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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/openbao"
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
	assert.Contains(t, err.Error(), "non-string")
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

// ---------------------------------------------------------------------------
// ResolvePath — gap 6: direct unit tests for the BatchProvider method
// ---------------------------------------------------------------------------

func TestResolvePath_Success(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"salt":    "my-secret-salt",
		"version": "v1",
	}, "test-token"))
	p := testProvider(t, srv)

	got, err := p.ResolvePath(context.Background(), "secret/data/hmac")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"salt": "my-secret-salt", "version": "v1"}, got)
}

func TestResolvePath_NotFound(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	p := testProvider(t, srv)

	_, err := p.ResolvePath(context.Background(), "secret/data/missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

func TestResolvePath_AuthFailure(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "value"}, "correct-token"))
	cfg := testConfig(srv)
	cfg.Token = "wrong-token"
	p, err := openbao.NewWithHTTPClient(cfg, srv.Client())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.ResolvePath(context.Background(), "secret/data/test")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "403")
}

func TestResolvePath_ReturnsAllKeys(t *testing.T) {
	t.Parallel()
	// Verify that ResolvePath returns the complete key set, not just one key.
	srv := newTestServer(t, kvV2Handler(map[string]any{
		"alpha": "a",
		"beta":  "b",
		"gamma": "c",
	}, "test-token"))
	p := testProvider(t, srv)

	got, err := p.ResolvePath(context.Background(), "secret/data/multi")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"alpha": "a", "beta": "b", "gamma": "c"}, got)
}

// ---------------------------------------------------------------------------
// Gap 2: url.Error unwrapping — secret path must not appear in error message
// ---------------------------------------------------------------------------

func TestFetchPath_URLErrorUnwrapped_PathNotLeaked(t *testing.T) {
	t.Parallel()
	// Use a server that immediately closes the connection so the HTTP
	// client returns a *url.Error wrapping a net.OpError. The unwrapping
	// code in fetchPath must strip the *url.Error so the vault path
	// embedded in the request URL does not appear in the final error.
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection and close it immediately to force a
		// transport-level error that the net/http client wraps in url.Error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	p := testProvider(t, srv)

	const secretPath = "very/secret/path/that/must/not/leak"
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao",
		Path:   secretPath,
		Key:    "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	// The secret path must not appear in the error message.
	assert.NotContains(t, err.Error(), secretPath,
		"vault path must not leak through url.Error into error message")
	// The full URL (with path) must not appear either.
	assert.NotContains(t, err.Error(), srv.URL+"/v1/"+secretPath,
		"full request URL must not leak into error message")
}

// ---------------------------------------------------------------------------
// Gap 3: SSRF protection — metadata endpoint blocked without AllowPrivateRanges
// ---------------------------------------------------------------------------

func TestNew_SSRFDialControl_BlocksMetadataEndpoint(t *testing.T) {
	t.Parallel()
	// Build a provider pointing at the cloud metadata IP. AllowPrivateRanges
	// is NOT set, so the dial control must block the connection attempt.
	// New() itself succeeds (lazy connection), but the first Resolve call
	// must fail with an SSRF error — not a vault auth error.
	p, err := openbao.New(&openbao.Config{
		Address: "https://169.254.169.254",
		Token:   "test-token",
		// AllowPrivateRanges: false (default)
	})
	require.NoError(t, err, "New() must succeed — lazy connection")
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao",
		Path:   "latest/meta-data/iam/security-credentials/role",
		Key:    "SecretAccessKey",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	// The underlying error must mention the blocked address, not a TLS or
	// auth failure — confirming the SSRF control fired, not a server error.
	assert.Contains(t, err.Error(), "blocked",
		"error must indicate SSRF dial control blocked the connection")
}

func TestNew_SSRFDialControl_BlocksLoopbackWithoutFlag(t *testing.T) {
	t.Parallel()
	// Loopback is blocked unless AllowPrivateRanges is set.
	// Build a real TLS server on loopback, then create a provider WITHOUT
	// AllowPrivateRanges — Resolve must fail at dial time, not at TLS.
	srv := httptest.NewTLSServer(kvV2Handler(map[string]any{"key": "value"}, "test-token"))
	t.Cleanup(srv.Close)

	// srv.URL is https://127.0.0.1:PORT — loopback, should be blocked.
	p, err := openbao.New(&openbao.Config{
		Address: srv.URL,
		Token:   "test-token",
		// AllowPrivateRanges: false — loopback must be blocked
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	_, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao",
		Path:   "secret/data/test",
		Key:    "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "blocked")
}

// ---------------------------------------------------------------------------
// Gap 4: Unexpected HTTP status codes (500, 429)
// ---------------------------------------------------------------------------

func TestResolve_InternalServerError_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "500")
}

func TestResolve_TooManyRequests_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "429")
}

func TestResolve_ServiceUnavailable_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "503")
}

// ---------------------------------------------------------------------------
// Gap 5: Nil/empty data field — soft-deleted KV v2 secrets
// ---------------------------------------------------------------------------

func TestResolve_NullDataField_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	// KV v2 soft-delete returns {"data": {"data": null}} — the outer
	// data wrapper exists but the inner data map is null. This is the
	// canonical "soft-deleted secret" response.
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := `{"data": {"data": null}}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resp)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/deleted", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "no data")
}

func TestResolve_NullOuterData_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	// The entire outer "data" wrapper is null: {"data": null}.
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := `{"data": null}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resp)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/deleted", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
	assert.Contains(t, err.Error(), "no data")
}

// ---------------------------------------------------------------------------
// Gap 8: Malformed JSON response
// ---------------------------------------------------------------------------

func TestResolve_MalformedJSON_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"data": {"data": {not valid json`)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "parse response")
}

func TestResolve_EmptyBody_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Empty body — json.Unmarshal will fail.
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
}

// ---------------------------------------------------------------------------
// Gap 9: Oversized response body
// ---------------------------------------------------------------------------

func TestResolve_OversizedResponse_WrapsResolveFailed(t *testing.T) {
	t.Parallel()
	// maxResponseSize is 1 MiB. Sending 1 MiB + 1 byte must trigger the
	// size check and return ErrSecretResolveFailed.
	const maxResponseSize = 1 << 20 // mirrors the package constant
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Write a response that exceeds the limit. Content does not need
		// to be valid JSON — the size check runs before parsing.
		payload := make([]byte, maxResponseSize+2)
		for i := range payload {
			payload[i] = 'x'
		}
		_, _ = w.Write(payload)
	}))
	p := testProvider(t, srv)

	_, err := p.Resolve(context.Background(), secrets.Ref{Scheme: "openbao", Path: "secret/data/test", Key: "key"})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "exceeds")
}

// ---------------------------------------------------------------------------
// buildTLSConfig tests (via New with TLS options)
// ---------------------------------------------------------------------------

func TestNew_CustomCA_ValidPEM(t *testing.T) {
	t.Parallel()
	// Generate a self-signed CA cert for testing.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	generateTestCA(t, caPath)

	p, err := openbao.New(&openbao.Config{
		Address:            "https://vault.example.com",
		Token:              "token",
		TLSCA:              caPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	_ = p.Close()
}

func TestNew_CustomCA_FileNotFound(t *testing.T) {
	t.Parallel()
	_, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCA:   "/nonexistent/ca.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca certificate")
}

func TestNew_CustomCA_InvalidPEM(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not a PEM"), 0o600))

	_, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCA:   caPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse ca")
}

func TestNew_mTLS_ValidCertAndKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	generateTestCertAndKey(t, certPath, keyPath)

	p, err := openbao.New(&openbao.Config{
		Address:            "https://vault.example.com",
		Token:              "token",
		TLSCert:            certPath,
		TLSKey:             keyPath,
		AllowPrivateRanges: true,
	})
	require.NoError(t, err)
	_ = p.Close()
}

func TestNew_mTLS_InvalidCertPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client-key.pem")
	generateTestCertAndKey(t, filepath.Join(dir, "unused.pem"), keyPath)

	_, err := openbao.New(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
		TLSCert: "/nonexistent/client.pem",
		TLSKey:  keyPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client certificate")
}

func TestNewWithHTTPClient_NilConfig(t *testing.T) {
	t.Parallel()
	_, err := openbao.NewWithHTTPClient(nil, http.DefaultClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewWithHTTPClient_NilClient(t *testing.T) {
	t.Parallel()
	_, err := openbao.NewWithHTTPClient(&openbao.Config{
		Address: "https://vault.example.com",
		Token:   "token",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestNewWithHTTPClient_RequiresHTTPS(t *testing.T) {
	t.Parallel()
	_, err := openbao.NewWithHTTPClient(&openbao.Config{
		Address: "http://vault.example.com",
		Token:   "token",
	}, http.DefaultClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestResolve_RedirectBlocked(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, "https://evil.example.com", http.StatusMovedPermanently)
	}))
	p := testProvider(t, srv)
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: "openbao", Path: "secret/data/test", Key: "key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
}

func TestResolvePath_TraversalRejected(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, kvV2Handler(map[string]any{"key": "val"}, "test-token"))
	p := testProvider(t, srv)
	_, err := p.ResolvePath(context.Background(), "secret/../etc/passwd")
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrMalformedRef)
}

// ---------------------------------------------------------------------------
// TLS test helpers
// ---------------------------------------------------------------------------

func generateTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func generateTestCertAndKey(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cf, err := os.Create(certPath)
	require.NoError(t, err)
	defer func() { _ = cf.Close() }()
	require.NoError(t, pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	kf, err := os.Create(keyPath)
	require.NoError(t, err)
	defer func() { _ = kf.Close() }()
	require.NoError(t, pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// TestConfig_String_RedactsCredentials verifies openbao.Config String,
// GoString, and Format never leak the Token, and strip the Address to
// scheme+host. Closes #475 openbao coverage.
func TestConfig_String_RedactsCredentials(t *testing.T) {
	t.Parallel()
	cfg := openbao.Config{
		Address:   "https://bao.example.com/v1/secret/data/path?query=LEAK-QUERY",
		Token:     "LEAK-TOKEN-VALUE",
		Namespace: "my-ns",
	}
	// Each formatter exercises a different fmt code path:
	// %v hits String via Format, %+v same, %#v via GoString.
	outs := []string{
		cfg.String(),
		cfg.GoString(),
	}
	// Use format strings via a local rather than hardcoded verbs so
	// gocritic doesn't flag redundantSprint when the literal equals cfg.String().
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		outs = append(outs, fmt.Sprintf(verb, cfg))
	}
	for _, out := range outs {
		assert.NotContains(t, out, "LEAK-TOKEN-VALUE",
			"Token must never appear in any format verb")
		assert.NotContains(t, out, "LEAK-QUERY",
			"URL query must be stripped")
		assert.NotContains(t, out, "/v1/secret",
			"URL path must be stripped")
		assert.NotContains(t, out, "my-ns",
			"Namespace value must not leak (only its presence)")
		assert.Contains(t, out, "https://bao.example.com",
			"scheme+host must appear")
		assert.Contains(t, out, "[REDACTED]",
			"token presence must be indicated")
	}
}

// TestConfig_String_TokenUnsetShowsUnsetMarker verifies that an empty
// Token prints "unset" rather than "[REDACTED]".
func TestConfig_String_TokenUnsetShowsUnsetMarker(t *testing.T) {
	t.Parallel()
	cfg := openbao.Config{
		Address: "https://bao.example.com",
	}
	out := cfg.String()
	assert.Contains(t, out, "token=unset")
	assert.NotContains(t, out, "[REDACTED]")
}
