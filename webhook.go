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

// The webhook output uses a two-buffer architecture:
//
//	Logger drain goroutine
//	  → WebhookOutput.Write(data) — non-blocking copy+enqueue
//	    → batch goroutine reads from channel
//	      → accumulates events, flushes on size/timer/close
//	      → HTTP POST as NDJSON with retry
//
// The internal channel decouples the Logger's drain loop from HTTP
// latency. If the channel is full, events are dropped (non-blocking)
// and [Metrics.RecordWebhookDrop] is recorded.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/go-audit/internal/ssrf"
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
type WebhookConfig struct {
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
	// new events are dropped and [Metrics.RecordWebhookDrop] is called.
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

// errRedirectBlocked is returned by the http.Client's CheckRedirect
// function. It is checked in doPost to classify redirect errors as
// non-retryable.
var errRedirectBlocked = errors.New("audit: webhook redirects are not followed")

// WebhookOutput sends batched audit events to an HTTP endpoint with
// retry, SSRF prevention, and graceful shutdown.
//
// See the package-level architecture comment for the two-buffer design.
// Events are formatted as line-delimited JSON (application/x-ndjson).
//
// # Retry
//
// On HTTP 5xx or 429, the batch is retried with exponential backoff
// and jitter (100ms to 5s). On 4xx (other than 429), the batch is
// dropped immediately. On retry exhaustion, the batch is dropped and
// [Metrics.RecordWebhookDrop] is called for each event.
//
// # SSRF Prevention
//
// The HTTP client uses [internal/ssrf.NewDialControl] to block
// connections to private, loopback, link-local, and cloud metadata
// addresses. Redirects are rejected entirely. Keep-alives are disabled
// to force fresh DNS resolution per request, preventing DNS rebinding.
//
// # At-Least-Once Semantics
//
// Retries may cause duplicate delivery if the server processes a batch
// but returns 5xx due to a timeout. Receivers SHOULD be idempotent.
//
// WebhookOutput is safe for concurrent use.
type WebhookOutput struct {
	client     *http.Client
	url        string
	headers    map[string]string // immutable after construction
	metrics    Metrics
	ch         chan []byte // internal async buffer
	cancel     context.CancelFunc
	done       chan struct{} // closed when batch goroutine exits
	batchSize  int
	maxRetries int
	flushIvl   time.Duration
	timeout    time.Duration
	closed     atomic.Bool
	mu         sync.Mutex
}

// NewWebhookOutput creates a new [WebhookOutput] from the given config.
// It validates the config, builds an SSRF-safe HTTP client, and starts
// the background batch goroutine. The metrics parameter is optional
// (may be nil).
func NewWebhookOutput(cfg *WebhookConfig, metrics Metrics) (*WebhookOutput, error) {
	if err := validateWebhookConfig(cfg); err != nil {
		return nil, err
	}

	tlsCfg, err := buildWebhookTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("audit: webhook tls: %w", err)
	}

	var ssrfOpts []ssrf.Option
	if cfg.AllowPrivateRanges {
		ssrfOpts = append(ssrfOpts, ssrf.AllowPrivateRanges())
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: ssrf.NewDialControl(ssrfOpts...),
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true, // force fresh dial per request (DNS rebinding)
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		// Zero redirects — redirects reopen the SSRF surface.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	// Copy headers to prevent caller mutation.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &WebhookOutput{
		client:     client,
		url:        cfg.URL,
		headers:    headers,
		metrics:    metrics,
		ch:         make(chan []byte, cfg.BufferSize),
		cancel:     cancel,
		done:       make(chan struct{}),
		batchSize:  cfg.BatchSize,
		maxRetries: cfg.MaxRetries,
		flushIvl:   cfg.FlushInterval,
		timeout:    cfg.Timeout,
	}

	go w.batchLoop(ctx)
	return w, nil
}

// Write enqueues a serialised audit event for batched delivery. The
// data is copied before enqueuing. If the internal buffer is full,
// the event is dropped and [Metrics.RecordWebhookDrop] is called.
// Write never blocks the caller.
func (w *WebhookOutput) Write(data []byte) error {
	if w.closed.Load() {
		return ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case w.ch <- cp:
		return nil
	default:
		slog.Warn("audit: webhook buffer full, dropping event",
			"buffer_size", cap(w.ch))
		if w.metrics != nil {
			w.metrics.RecordWebhookDrop()
		}
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the batch goroutine to drain and flush, then waits
// for completion. In-flight HTTP retries are cancelled via context.
// Close is idempotent.
func (w *WebhookOutput) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed.Load() {
		return nil
	}
	w.closed.Store(true)

	// Cancel the context to stop the batch loop and abort in-flight
	// HTTP requests. The batch goroutine will drain remaining events
	// and do a final flush with a fresh short-deadline context.
	w.cancel()

	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
		slog.Error("audit: webhook batch goroutine did not exit after cancel")
	}

	w.client.CloseIdleConnections()
	return nil
}

// Name returns the human-readable identifier for this output.
func (w *WebhookOutput) Name() string {
	if u, err := url.Parse(w.url); err == nil {
		return "webhook:" + u.Host
	}
	return "webhook"
}

// batchLoop is the background goroutine that accumulates events and
// flushes batches on size, timer, or shutdown. Placeholder — full
// implementation in Commit 4.
func (w *WebhookOutput) batchLoop(ctx context.Context) {
	defer close(w.done)

	batch := make([][]byte, 0, w.batchSize)
	timer := time.NewTimer(w.flushIvl)
	defer timer.Stop()

	for {
		select {
		case data := <-w.ch:
			batch = append(batch, data)
			if len(batch) >= w.batchSize {
				// flush placeholder — implemented in Commit 5
				batch = batch[:0]
				resetWebhookTimer(timer, w.flushIvl)
			}

		case <-timer.C:
			if len(batch) > 0 {
				// flush placeholder — implemented in Commit 5
				batch = batch[:0]
			}
			resetWebhookTimer(timer, w.flushIvl)

		case <-ctx.Done():
			// Drain remaining events from the channel.
			for {
				select {
				case data := <-w.ch:
					batch = append(batch, data)
				default:
					goto drained
				}
			}
		drained:
			// Final flush placeholder — implemented in Commit 5
			_ = batch
			return
		}
	}
}

// resetWebhookTimer safely resets a timer, draining the channel first
// if the timer has already fired.
func resetWebhookTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// buildWebhookTLSConfig creates a TLS configuration for webhook
// connections. TLS 1.3 is the minimum. InsecureSkipVerify is never set.
func buildWebhookTLSConfig(cfg *WebhookConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
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

	// Validate header names for CRLF injection.
	for k := range cfg.Headers {
		if strings.ContainsAny(k, "\r\n") {
			return fmt.Errorf("audit: webhook header name %q contains invalid characters", k)
		}
	}

	// TLS cert/key pairing.
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("audit: webhook tls_cert and tls_key must both be set or both empty")
	}

	applyWebhookDefaults(cfg)
	return validateWebhookLimits(cfg)
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
