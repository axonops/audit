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

package audit

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

// Default values for [WebhookConfig] fields.
const (
	// DefaultWebhookBatchSize is the default maximum events per batch.
	DefaultWebhookBatchSize = 100

	// DefaultWebhookFlushInterval is the default maximum time between
	// batch flushes.
	DefaultWebhookFlushInterval = 5 * time.Second

	// DefaultWebhookTimeout is the default HTTP request timeout.
	DefaultWebhookTimeout = 10 * time.Second

	// DefaultWebhookMaxRetries is the default retry count for 5xx/429.
	DefaultWebhookMaxRetries = 3

	// DefaultWebhookBufferSize is the default internal buffer capacity.
	DefaultWebhookBufferSize = 10_000

	// MaxWebhookBatchSize is the upper bound for BatchSize.
	MaxWebhookBatchSize = 10_000

	// MaxWebhookBufferSize is the upper bound for BufferSize.
	MaxWebhookBufferSize = 1_000_000

	// MaxWebhookMaxRetries is the upper bound for MaxRetries.
	MaxWebhookMaxRetries = 20
)

// WebhookConfig holds configuration for [WebhookOutput].
type WebhookConfig struct { //nolint:govet // fieldalignment: pointer field TLSPolicy extends scan region by 8 bytes; readability preferred
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
	// the default policy (TLS 1.3 only) is used. See [TLSPolicy] for
	// details on enabling TLS 1.2 fallback.
	TLSPolicy *TLSPolicy

	// FlushInterval is the maximum time between batch flushes.
	// The timer resets after every flush (batch-size or timer
	// triggered). Zero defaults to [DefaultWebhookFlushInterval] (5s).
	FlushInterval time.Duration

	// Timeout is the HTTP request timeout covering the full
	// request/response lifecycle including body read.
	// Zero defaults to [DefaultWebhookTimeout] (10s).
	Timeout time.Duration

	// BatchSize is the maximum events per HTTP request.
	// Zero defaults to [DefaultWebhookBatchSize] (100).
	// Values above [MaxWebhookBatchSize] (10,000) are rejected.
	BatchSize int

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [WebhookMetrics.RecordWebhookDrop] is called.
	// Zero defaults to [DefaultWebhookBufferSize] (10,000).
	// Values above [MaxWebhookBufferSize] (1,000,000) are rejected.
	BufferSize int

	// MaxRetries is the retry count for 5xx and 429 responses.
	// Zero defaults to [DefaultWebhookMaxRetries] (3).
	// Values above [MaxWebhookMaxRetries] (20) are rejected.
	MaxRetries int

	// AllowInsecureHTTP permits http:// URLs. Default: false.
	// For development and testing only.
	AllowInsecureHTTP bool

	// AllowPrivateRanges disables SSRF protection for private and
	// loopback IP ranges. Default: false. Enable for webhooks on
	// private networks. Cloud metadata (169.254.169.254) remains
	// blocked regardless.
	AllowPrivateRanges bool
}

// validateWebhookConfig checks the config for correctness, applying
// defaults where needed.
func validateWebhookConfig(cfg *WebhookConfig) error {
	if cfg.URL == "" {
		return fmt.Errorf("audit: webhook url must not be empty")
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("audit: webhook url invalid: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("audit: webhook url scheme must be http or https (got %q)", u.Scheme)
	}

	if !cfg.AllowInsecureHTTP && u.Scheme != "https" {
		return fmt.Errorf("audit: webhook url must be https (got %q); set AllowInsecureHTTP for testing", u.Scheme)
	}

	// Reject URLs with embedded credentials — they would leak in logs.
	if u.User != nil {
		return fmt.Errorf("audit: webhook url must not contain credentials; use Headers for auth")
	}

	if err := validateWebhookHeaders(cfg.Headers); err != nil {
		return err
	}

	// TLS cert/key pairing.
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("audit: webhook tls_cert and tls_key must both be set or both empty")
	}

	applyWebhookDefaults(cfg)
	return validateWebhookLimits(cfg)
}

// validateWebhookHeaders checks header names and values for CRLF injection.
func validateWebhookHeaders(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("audit: webhook header name %q contains invalid characters", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("audit: webhook header value for %q contains invalid characters", k)
		}
	}
	return nil
}

// applyWebhookDefaults fills zero-valued fields with documented defaults.
func applyWebhookDefaults(cfg *WebhookConfig) {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultWebhookBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultWebhookFlushInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultWebhookMaxRetries
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultWebhookBufferSize
	}
}

// validateWebhookLimits checks upper bounds on numeric fields.
func validateWebhookLimits(cfg *WebhookConfig) error {
	if cfg.BatchSize > MaxWebhookBatchSize {
		return fmt.Errorf("%w: webhook batch_size %d exceeds maximum %d",
			ErrConfigInvalid, cfg.BatchSize, MaxWebhookBatchSize)
	}
	if cfg.BufferSize > MaxWebhookBufferSize {
		return fmt.Errorf("%w: webhook buffer_size %d exceeds maximum %d",
			ErrConfigInvalid, cfg.BufferSize, MaxWebhookBufferSize)
	}
	if cfg.MaxRetries > MaxWebhookMaxRetries {
		return fmt.Errorf("%w: webhook max_retries %d exceeds maximum %d",
			ErrConfigInvalid, cfg.MaxRetries, MaxWebhookMaxRetries)
	}
	return nil
}

// buildWebhookTLSConfig creates a TLS configuration for webhook
// connections using the [TLSPolicy] from the config (defaulting to
// TLS 1.3 only when nil). InsecureSkipVerify is never set.
func buildWebhookTLSConfig(cfg *WebhookConfig) (*tls.Config, error) {
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
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("reading ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse ca certificate")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
