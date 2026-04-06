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

package loki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	audit "github.com/axonops/go-audit"
)

// Default values for [Config] fields.
const (
	DefaultBatchSize     = 100
	DefaultMaxBatchBytes = 1 << 20 // 1 MiB
	DefaultFlushInterval = 5 * time.Second
	DefaultTimeout       = 10 * time.Second
	DefaultMaxRetries    = 3
	DefaultBufferSize    = 10_000
)

// Upper bounds for [Config] fields.
const (
	MaxBatchSize     = 10_000
	MaxMaxBatchBytes = 10 << 20 // 10 MiB
	MaxFlushInterval = 5 * time.Minute
	MaxTimeout       = 5 * time.Minute
	MaxMaxRetries    = 20
	MaxBufferSize    = 1_000_000
)

// Lower bounds for [Config] fields.
const (
	MinMaxBatchBytes = 1024
	MinFlushInterval = 100 * time.Millisecond
	MinTimeout       = 1 * time.Second
	MinBufferSize    = 100
)

// Metrics is an optional interface for recording Loki output
// operational metrics. Pass nil to disable metrics collection.
type Metrics interface {
	// RecordLokiDrop is called when an event is dropped (buffer full
	// or retries exhausted).
	RecordLokiDrop()

	// RecordLokiFlush is called after each successful push to Loki.
	RecordLokiFlush(batchSize int, dur time.Duration)

	// RecordLokiRetry is called when a push is retried after a 429
	// or 5xx response.
	RecordLokiRetry(statusCode int, attempt int)

	// RecordLokiError is called when a push fails with a non-retryable
	// error (4xx except 429) or after all retries are exhausted.
	RecordLokiError(statusCode int)
}

// validLabelName matches Loki's label name requirement.
var validLabelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// BasicAuth holds HTTP basic authentication credentials.
type BasicAuth struct {
	Username string
	Password string
}

// LabelConfig controls which fields become Loki stream labels.
type LabelConfig struct {
	// Static labels are constant across all events from this output.
	// Keys must match [a-zA-Z_][a-zA-Z0-9_]* (Loki requirement).
	Static map[string]string

	// Dynamic controls which per-event fields become labels.
	// Zero value means all dynamic labels are included.
	Dynamic DynamicLabels
}

// DynamicLabels toggles which per-event fields become Loki stream
// labels. All fields default to included (zero value = include).
// Set Exclude* to true to remove a field from labels.
type DynamicLabels struct {
	ExcludeAppName       bool
	ExcludeHost          bool
	ExcludeTimezone      bool
	ExcludePID           bool
	ExcludeEventType     bool
	ExcludeEventCategory bool
	ExcludeSeverity      bool
}

// Config holds configuration for the Loki [Output].
type Config struct { //nolint:govet // fieldalignment: readability preferred
	// URL is the full Loki push API endpoint, including path.
	// Example: "https://loki:3100/loki/api/v1/push"
	// REQUIRED; must be https unless AllowInsecureHTTP is true.
	URL string

	// BasicAuth configures HTTP basic authentication. Mutually
	// exclusive with BearerToken.
	BasicAuth *BasicAuth

	// BearerToken sets the Authorization: Bearer header. Mutually
	// exclusive with BasicAuth.
	BearerToken string

	// TenantID sets the X-Scope-OrgID header for Loki multi-tenancy.
	TenantID string

	// Headers are additional HTTP headers sent with every push request.
	Headers map[string]string

	// Labels controls stream label configuration.
	Labels LabelConfig

	// TLS configuration.
	TLSCA     string
	TLSCert   string
	TLSKey    string
	TLSPolicy *audit.TLSPolicy

	// Batching.
	BatchSize     int           // Max events per push (default 100, max 10000)
	MaxBatchBytes int           // Max uncompressed bytes per push (default 1MB, max 10MB)
	FlushInterval time.Duration // Max time between pushes (default 5s)
	BufferSize    int           // Internal event buffer capacity (default 10000)
	Timeout       time.Duration // HTTP request timeout (default 10s)
	MaxRetries    int           // Retry count for 429/5xx (default 3, max 20)

	// Compress enables gzip compression of push requests. The YAML
	// factory defaults to true when the gzip key is omitted; the Go
	// zero value is false for programmatic construction.
	Compress bool

	// AllowInsecureHTTP permits http:// URLs. MUST NOT be true in
	// production.
	AllowInsecureHTTP bool

	// AllowPrivateRanges permits connections to RFC 1918 private
	// addresses. Intended for testing and private deployments.
	AllowPrivateRanges bool
}

// String returns a safe representation of the config without credentials.
// Value receiver ensures both Config and *Config are protected.
func (c Config) String() string {
	auth := "none"
	if c.BasicAuth != nil {
		auth = "basic_auth"
	} else if c.BearerToken != "" {
		auth = "bearer_token"
	}
	return fmt.Sprintf("LokiConfig{url=%q, auth=%s, compress=%t, batch_size=%d}",
		c.URL, auth, c.Compress, c.BatchSize)
}

// Format implements [fmt.Formatter] to prevent credential leakage via
// all format verbs including %+v and %#v. Value receiver ensures both
// Config and *Config are protected.
func (c Config) Format(f fmt.State, _ rune) { //nolint:gocritic // hugeParam: value receiver required to intercept fmt verbs on Config values
	_, _ = fmt.Fprint(f, c.String())
}

// String returns a redacted representation to prevent credential leakage.
func (ba BasicAuth) String() string { return "BasicAuth{REDACTED}" }

// GoString implements [fmt.GoStringer] to prevent credential leakage via %#v.
func (ba BasicAuth) GoString() string { return "BasicAuth{REDACTED}" }

// validateLokiConfig validates the config and applies defaults.
// It modifies cfg in place (applying defaults) and returns an error
// if any field is invalid.
func validateLokiConfig(cfg *Config) error {
	if err := validateLokiURL(cfg); err != nil {
		return err
	}

	if cfg.BasicAuth != nil && cfg.BearerToken != "" {
		return fmt.Errorf("%w: loki: basic_auth and bearer_token are mutually exclusive", audit.ErrConfigInvalid)
	}

	if cfg.BasicAuth != nil && cfg.BasicAuth.Username == "" {
		return fmt.Errorf("%w: loki: basic_auth.username must not be empty", audit.ErrConfigInvalid)
	}

	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("%w: loki: tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}

	if err := validateStaticLabels(cfg.Labels.Static); err != nil {
		return err
	}

	applyLokiDefaults(cfg)

	if err := validateLokiBounds(cfg); err != nil {
		return err
	}

	return validateHeaders(cfg.Headers)
}

// validateLokiURL checks the URL field for presence, scheme, and credentials.
func validateLokiURL(cfg *Config) error {
	if cfg.URL == "" {
		return fmt.Errorf("%w: loki: url must not be empty", audit.ErrConfigInvalid)
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: loki: invalid url: %w", audit.ErrConfigInvalid, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: loki: url scheme must be http or https, got %q", audit.ErrConfigInvalid, u.Scheme)
	}

	if u.Scheme == "http" && !cfg.AllowInsecureHTTP {
		return fmt.Errorf("%w: loki: url must be https (got %q); set allow_insecure_http for testing", audit.ErrConfigInvalid, u.Scheme)
	}

	if u.User != nil {
		return fmt.Errorf("%w: loki: url must not contain credentials; use basic_auth for authentication", audit.ErrConfigInvalid)
	}

	return nil
}

// validateStaticLabels checks that all static label names match the Loki
// label name pattern and have non-empty values without control characters.
func validateStaticLabels(labels map[string]string) error {
	for name, val := range labels {
		if !validLabelName.MatchString(name) {
			return fmt.Errorf("%w: loki: static label name %q is invalid: must match [a-zA-Z_][a-zA-Z0-9_]*", audit.ErrConfigInvalid, name)
		}
		if val == "" {
			return fmt.Errorf("%w: loki: static label %q has empty value", audit.ErrConfigInvalid, name)
		}
		if containsControlChar(val) {
			return fmt.Errorf("%w: loki: static label %q value contains control characters", audit.ErrConfigInvalid, name)
		}
	}
	return nil
}

// containsControlChar reports whether s contains any ASCII control
// character (bytes 0x00-0x1F).
func containsControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

// applyLokiDefaults fills zero-value fields with documented defaults.
// For the programmatic API, zero means "not set". Negative values from
// the YAML path (sentinel for explicit zero) pass through to validation.
func applyLokiDefaults(cfg *Config) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.MaxBatchBytes == 0 {
		cfg.MaxBatchBytes = DefaultMaxBatchBytes
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

// validateLokiBounds checks that all numeric/duration fields are within
// documented bounds. Must be called after applyLokiDefaults.
func validateLokiBounds(cfg *Config) error {
	if err := checkIntBound("batch_size", cfg.BatchSize, 1, MaxBatchSize); err != nil {
		return err
	}
	if err := checkIntBound("max_batch_bytes", cfg.MaxBatchBytes, MinMaxBatchBytes, MaxMaxBatchBytes); err != nil {
		return err
	}
	if err := checkDurBound("flush_interval", cfg.FlushInterval, MinFlushInterval, MaxFlushInterval); err != nil {
		return err
	}
	if err := checkDurBound("timeout", cfg.Timeout, MinTimeout, MaxTimeout); err != nil {
		return err
	}
	if err := checkIntBound("max_retries", cfg.MaxRetries, 1, MaxMaxRetries); err != nil {
		return err
	}
	return checkIntBound("buffer_size", cfg.BufferSize, MinBufferSize, MaxBufferSize)
}

func checkIntBound(name string, val, lo, hi int) error {
	if val < lo || val > hi {
		return fmt.Errorf("%w: loki: %s %d out of range [%d, %d]", audit.ErrConfigInvalid, name, val, lo, hi)
	}
	return nil
}

func checkDurBound(name string, val, lo, hi time.Duration) error {
	if val < lo || val > hi {
		return fmt.Errorf("%w: loki: %s %s out of range [%s, %s]", audit.ErrConfigInvalid, name, val, lo, hi)
	}
	return nil
}

// restrictedHeaders are header names managed by the library. Consumers
// must use the dedicated Config fields (BasicAuth, BearerToken, TenantID)
// instead of setting these via the Headers map.
var restrictedHeaders = map[string]struct{}{
	"authorization":    {},
	"x-scope-orgid":    {},
	"content-type":     {},
	"content-encoding": {},
	"host":             {},
}

// validateHeaders checks for CRLF injection and restricted header names.
func validateHeaders(headers map[string]string) error {
	for k, v := range headers {
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: loki: header %q contains CR/LF", audit.ErrConfigInvalid, k)
		}
		if _, blocked := restrictedHeaders[strings.ToLower(k)]; blocked {
			return fmt.Errorf("%w: loki: header %q is managed by the library; use the dedicated config field", audit.ErrConfigInvalid, k)
		}
	}
	return nil
}

// buildLokiTLSConfig creates a TLS configuration from the Loki config.
// Warnings from TLS policy application are returned for the caller to log.
func buildLokiTLSConfig(cfg *Config) (*tls.Config, []string, error) {
	var tlsCfg *tls.Config
	var warnings []string
	if cfg.TLSPolicy != nil {
		tlsCfg, warnings = cfg.TLSPolicy.Apply(nil)
	}

	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, nil, fmt.Errorf("audit: loki: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caPEM, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, nil, fmt.Errorf("audit: loki: read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("audit: loki: CA certificate contains no valid PEM blocks")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, warnings, nil
}
