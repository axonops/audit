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

package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/axonops/audit"
)

// Default values for [Config] fields.
const (
	// DefaultBatchSize is the default maximum events per batch.
	DefaultBatchSize = 100

	// DefaultFlushInterval is the default maximum time between
	// batch flushes.
	DefaultFlushInterval = 5 * time.Second

	// DefaultTimeout is the default HTTP request timeout.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRetries is the default retry count for 5xx/429.
	DefaultMaxRetries = 3

	// DefaultBufferSize is the default internal buffer capacity.
	DefaultBufferSize = 10_000

	// MaxBatchSize is the upper bound for BatchSize.
	MaxBatchSize = 10_000

	// MaxBufferSize is the upper bound for BufferSize.
	MaxBufferSize = 1_000_000

	// MaxMaxRetries is the upper bound for MaxRetries.
	MaxMaxRetries = 20
)

// Config holds configuration for [Output].
type Config struct { //nolint:govet // fieldalignment: pointer field TLSPolicy extends scan region by 8 bytes; readability preferred
	// URL is the HTTP endpoint to POST batched events to.
	// REQUIRED. MUST be https:// unless [AllowInsecureHTTP] is true.
	URL string

	// Headers are custom HTTP headers added to every request.
	// Common use: "Authorization: Bearer <token>" or
	// "Authorization: Splunk <token>". Header values containing
	// "auth", "key", "secret", or "token" (case-insensitive) are
	// redacted in log output. Header names must not contain CRLF.
	Headers map[string]string

	// TLSCA is the path to a custom CA certificate for the webhook
	// endpoint. When empty, the system root CA pool is used.
	TLSCA string

	// TLSCert is the path to a client certificate for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSCert string

	// TLSKey is the path to the client private key for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSKey string

	// TLSPolicy controls TLS version and cipher suite policy. When nil,
	// the default policy (TLS 1.3 only) is used. See [audit.TLSPolicy] for
	// details on enabling TLS 1.2 fallback.
	TLSPolicy *audit.TLSPolicy

	// FlushInterval is the maximum time between batch flushes.
	// The timer resets after every flush (batch-size or timer
	// triggered). Zero defaults to [DefaultFlushInterval] (5s).
	FlushInterval time.Duration

	// Timeout is the HTTP request timeout covering the full
	// request/response lifecycle including body read.
	// Zero defaults to [DefaultTimeout] (10s).
	Timeout time.Duration

	// BatchSize is the maximum events per HTTP request.
	// Zero defaults to [DefaultBatchSize] (100).
	// Values above [MaxBatchSize] (10,000) are rejected.
	BatchSize int

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [Metrics.RecordWebhookDrop] is called.
	// Zero defaults to [DefaultBufferSize] (10,000).
	// Values above [MaxBufferSize] (1,000,000) are rejected.
	BufferSize int

	// MaxRetries is the retry count for 5xx and 429 responses.
	// Zero defaults to [DefaultMaxRetries] (3).
	// Values above [MaxMaxRetries] (20) are rejected.
	MaxRetries int

	// AllowInsecureHTTP permits http:// URLs. Default: false.
	// MUST NOT be set to true in production. Plaintext HTTP exposes
	// credentials in request headers (including Authorization tokens)
	// to network observers. Use only for local development and testing.
	AllowInsecureHTTP bool

	// AllowPrivateRanges disables SSRF protection for private and
	// loopback IP ranges. Default: false. Enable for webhooks on
	// private networks. Cloud metadata (169.254.169.254) remains
	// blocked regardless.
	AllowPrivateRanges bool
}

// String returns a human-readable representation of the config with
// sensitive header values redacted. This prevents credential leakage
// when configs are accidentally logged via %v or %+v.
func (c Config) String() string {
	hdrs := len(c.Headers)
	return fmt.Sprintf("WebhookConfig{url=%q, headers=%d, batch_size=%d, timeout=%s}",
		c.URL, hdrs, c.BatchSize, c.Timeout)
}

// GoString returns the same redacted representation as [Config.String].
// This prevents credential leakage when configs are formatted via %#v.
func (c Config) GoString() string { return c.String() } //nolint:gocritic // hugeParam: value receiver required by fmt.GoStringer

// Format writes the redacted representation to the formatter.
// This prevents credential leakage via %+v and all other format verbs.
func (c Config) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.String()) } //nolint:gocritic // hugeParam: value receiver required by fmt.Formatter

// validateWebhookConfig checks the config for correctness, applying
// defaults where needed.
func validateWebhookConfig(cfg *Config) error {
	if cfg.URL == "" {
		return fmt.Errorf("%w: webhook url must not be empty", audit.ErrConfigInvalid)
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: webhook url invalid: %w", audit.ErrConfigInvalid, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: webhook url scheme must be http or https (got %q)", audit.ErrConfigInvalid, u.Scheme)
	}

	if !cfg.AllowInsecureHTTP && u.Scheme != "https" {
		return fmt.Errorf("%w: webhook url must be https (got %q); set AllowInsecureHTTP for testing", audit.ErrConfigInvalid, u.Scheme)
	}

	// Reject URLs with embedded credentials — they would leak in logs.
	if u.User != nil {
		return fmt.Errorf("%w: webhook url must not contain credentials; use Headers for auth", audit.ErrConfigInvalid)
	}

	if err := validateWebhookHeaders(cfg.Headers); err != nil {
		return err
	}

	if err := validateWebhookTLSFiles(cfg); err != nil {
		return err
	}

	applyWebhookDefaults(cfg)
	return validateWebhookLimits(cfg)
}

// validateWebhookTLSFiles checks TLS cert/key pairing and file existence.
func validateWebhookTLSFiles(cfg *Config) error {
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("%w: webhook tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}
	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("%w: webhook tls file %q: %w", audit.ErrConfigInvalid, path, err)
			}
			if fi.IsDir() {
				return fmt.Errorf("%w: webhook tls file %q is a directory", audit.ErrConfigInvalid, path)
			}
		}
	}
	return nil
}

// validateWebhookHeaders checks header names and values for CRLF injection.
func validateWebhookHeaders(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("%w: webhook header name %q contains invalid characters", audit.ErrConfigInvalid, k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: webhook header value for %q contains invalid characters", audit.ErrConfigInvalid, k)
		}
	}
	return nil
}

// applyWebhookDefaults fills zero-valued fields with documented defaults.
// For the programmatic API, zero means "not set". Negative values from
// the YAML path (sentinel for explicit zero) pass through to validation.
func applyWebhookDefaults(cfg *Config) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultBufferSize
	}
}

// validateWebhookLimits checks bounds on numeric fields.
func validateWebhookLimits(cfg *Config) error {
	if cfg.BatchSize < 1 {
		return fmt.Errorf("%w: webhook batch_size must be at least 1 (got %d)",
			audit.ErrConfigInvalid, cfg.BatchSize)
	}
	if cfg.MaxRetries < 1 {
		return fmt.Errorf("%w: webhook max_retries must be at least 1 (got %d); this is the total number of delivery attempts",
			audit.ErrConfigInvalid, cfg.MaxRetries)
	}
	if cfg.BufferSize < 1 {
		return fmt.Errorf("%w: webhook buffer_size must be at least 1 (got %d)",
			audit.ErrConfigInvalid, cfg.BufferSize)
	}
	if cfg.BatchSize > MaxBatchSize {
		return fmt.Errorf("%w: webhook batch_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BatchSize, MaxBatchSize)
	}
	if cfg.BufferSize > MaxBufferSize {
		return fmt.Errorf("%w: webhook buffer_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BufferSize, MaxBufferSize)
	}
	if cfg.MaxRetries > MaxMaxRetries {
		return fmt.Errorf("%w: webhook max_retries %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxRetries, MaxMaxRetries)
	}
	if cfg.FlushInterval < 0 {
		return fmt.Errorf("%w: webhook flush_interval must not be negative (got %v)",
			audit.ErrConfigInvalid, cfg.FlushInterval)
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("%w: webhook timeout must not be negative (got %v)",
			audit.ErrConfigInvalid, cfg.Timeout)
	}
	return nil
}

// buildWebhookTLSConfig creates a TLS configuration for webhook
// connections using the [audit.TLSPolicy] from the config (defaulting to
// TLS 1.3 only when nil). InsecureSkipVerify is never set.
func buildWebhookTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg, warnings := cfg.TLSPolicy.Apply(nil)
	for _, w := range warnings {
		// Log only scheme+host to avoid leaking query-parameter tokens.
		u, _ := url.Parse(cfg.URL)
		sanitised := u.Scheme + "://" + u.Host
		slog.Warn(w, "output", "webhook", "url", sanitised)
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("audit: webhook tls: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("audit: webhook tls: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("audit: webhook tls: parse ca certificate: invalid pem block")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
