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

package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/secrets"
)

// maxResponseSize is the maximum response body size accepted from the
// Vault server. Prevents memory exhaustion from a compromised server.
const maxResponseSize = 1 << 20 // 1 MiB

// errRedirectBlocked is returned by the redirect policy.
var errRedirectBlocked = errors.New("vault: redirects are blocked")

// Config holds connection parameters for a HashiCorp Vault provider.
type Config struct { //nolint:govet // readability over alignment
	// Address is the Vault server URL. Required. Must use HTTPS.
	// Typically sourced from the VAULT_ADDR environment variable.
	Address string

	// Token is the authentication token. Required.
	// Typically sourced from the VAULT_TOKEN environment variable.
	Token string

	// Namespace is the Vault namespace prefix. Optional.
	// Set via X-Vault-Namespace header on every request.
	Namespace string

	// TLSCA is the path to a custom CA certificate PEM file for
	// verifying the Vault server's TLS certificate.
	TLSCA string

	// TLSCert is the path to a client certificate for mTLS
	// authentication.
	TLSCert string

	// TLSKey is the path to the client private key for mTLS
	// authentication.
	TLSKey string

	// TLSPolicy controls TLS version and cipher suite selection.
	// Nil defaults to TLS 1.3 only.
	TLSPolicy *audit.TLSPolicy

	// AllowPrivateRanges permits connections to RFC 1918 private
	// addresses and loopback. Required for local development where
	// Vault runs on 127.0.0.1. Cloud metadata endpoints remain
	// blocked. Default: false.
	AllowPrivateRanges bool
}

// Provider resolves secret references from a HashiCorp Vault KV v2
// engine. Construction validates the address and builds an SSRF-safe
// HTTP client but performs no network I/O. The first [Resolve] call
// initiates the connection.
type Provider struct { //nolint:govet // readability over alignment
	client *http.Client
	addr   string // full base URL
	host   string // host:port for String() output
	token  []byte // stored as bytes for zeroing in Close()
	ns     string // X-Vault-Namespace header; empty = no namespace
}

// New creates a HashiCorp Vault provider from the given configuration.
// Validates the address (HTTPS required), builds the TLS config and
// HTTP client, but performs no network I/O.
func New(cfg *Config) (*Provider, error) {
	// Validate address.
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address is required")
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid address: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("vault: address must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("vault: address has empty host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("vault: address must not contain embedded credentials")
	}

	// Validate token.
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault: token is required")
	}

	// Build TLS config.
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Build SSRF dial control.
	var ssrfOpts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		ssrfOpts = append(ssrfOpts, audit.AllowPrivateRanges())
	}

	// Build HTTP client.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: audit.NewSSRFDialControl(ssrfOpts...),
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	return &Provider{
		client: client,
		addr:   cfg.Address,
		host:   u.Host,
		token:  []byte(cfg.Token),
		ns:     cfg.Namespace,
	}, nil
}

// NewWithHTTPClient creates a Vault provider using the provided HTTP
// client instead of building one from the Config's TLS settings.
// This is primarily for testing with [net/http/httptest] servers.
// The Config.Address and Config.Token are still validated.
func NewWithHTTPClient(cfg *Config, client *http.Client) (*Provider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address is required")
	}
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid address: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("vault: address must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("vault: address has empty host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("vault: address must not contain embedded credentials")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault: token is required")
	}
	return &Provider{
		client: client,
		addr:   cfg.Address,
		host:   u.Host,
		token:  []byte(cfg.Token),
		ns:     cfg.Namespace,
	}, nil
}

// Scheme returns "vault".
func (p *Provider) Scheme() string { return "vault" }

// Resolve fetches the secret value for the given reference from the
// Vault KV v2 engine.
func (p *Provider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) { //nolint:gocyclo,cyclop // linear HTTP request pipeline
	if err := ref.Valid(); err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}

	// Build request: GET /v1/{path}
	reqURL := p.addr + "/v1/" + ref.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("%w: build request: %w", secrets.ErrSecretResolveFailed, err)
	}
	req.Header.Set("X-Vault-Token", string(p.token))
	if p.ns != "" {
		req.Header.Set("X-Vault-Namespace", p.ns)
	}

	// Execute request.
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", secrets.ErrSecretResolveFailed, err)
	}
	defer func() {
		// Drain and close body. Small limit sufficient since
		// keep-alives are disabled (hygiene only).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()

	// Check status code.
	switch resp.StatusCode {
	case http.StatusOK:
		// success — parse below
	case http.StatusNotFound:
		return "", fmt.Errorf("%w: path returned 404", secrets.ErrSecretNotFound)
	case http.StatusForbidden:
		return "", fmt.Errorf("%w: authentication failed (403)", secrets.ErrSecretResolveFailed)
	default:
		return "", fmt.Errorf("%w: unexpected status %d", secrets.ErrSecretResolveFailed, resp.StatusCode)
	}

	// Parse response body (KV v2 format: {"data": {"data": {...}}}).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("%w: read response: %w", secrets.ErrSecretResolveFailed, err)
	}
	if len(body) > maxResponseSize {
		return "", fmt.Errorf("%w: response exceeds %d bytes", secrets.ErrSecretResolveFailed, maxResponseSize)
	}

	var kvResp kvResponse
	if err := json.Unmarshal(body, &kvResp); err != nil {
		return "", fmt.Errorf("%w: parse response: %w", secrets.ErrSecretResolveFailed, err)
	}

	if kvResp.Data == nil || kvResp.Data.Data == nil {
		return "", fmt.Errorf("%w: response has no data", secrets.ErrSecretNotFound)
	}

	val, ok := kvResp.Data.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: requested key not found in secret", secrets.ErrSecretNotFound)
	}

	strVal, isStr := val.(string)
	if !isStr {
		return "", fmt.Errorf("%w: secret value is not a string", secrets.ErrSecretResolveFailed)
	}

	return strVal, nil
}

// Close releases resources held by the provider and zeroes the
// authentication token from memory (best-effort; Go GC may retain
// copies). Close is idempotent.
func (p *Provider) Close() error {
	for i := range p.token {
		p.token[i] = 0
	}
	p.client.CloseIdleConnections()
	return nil
}

// String returns a safe representation with the token redacted.
func (p *Provider) String() string {
	return fmt.Sprintf("vault{host: %s, token: [REDACTED]}", p.host)
}

// GoString implements [fmt.GoStringer] to prevent token leakage via %#v.
func (p *Provider) GoString() string { return p.String() }

// Format implements [fmt.Formatter] to prevent token leakage via %+v.
func (p *Provider) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, p.String())
}

// kvResponse is the KV v2 response structure.
type kvResponse struct {
	Data *kvData `json:"data"`
}

type kvData struct {
	Data map[string]any `json:"data"`
}

// buildTLSConfig creates a TLS configuration from the provider config.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg, _ := cfg.TLSPolicy.Apply(nil)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("vault: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else if cfg.TLSCert != "" || cfg.TLSKey != "" {
		return nil, fmt.Errorf("vault: tls_cert and tls_key must both be set or both empty")
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("vault: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("vault: parse ca certificate: invalid PEM")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
