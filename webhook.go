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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/go-audit/internal/ssrf"
)

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
	metrics    Metrics
	done       chan struct{}
	headers    map[string]string
	ch         chan []byte
	cancel     context.CancelFunc
	client     *http.Client
	url        string
	batchSize  int
	maxRetries int
	flushIvl   time.Duration
	timeout    time.Duration
	mu         sync.Mutex
	closed     atomic.Bool
}

// NewWebhookOutput creates a new [WebhookOutput] from the given config.
// It validates the config, builds an SSRF-safe HTTP client, and starts
// the background batch goroutine. The metrics parameter is optional
// (may be nil).
func NewWebhookOutput(cfg *WebhookConfig, metrics Metrics) (*WebhookOutput, error) {
	// Copy config so validation/defaults don't mutate the caller's struct.
	cfgCopy := *cfg
	cfg = &cfgCopy

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
// flushes batches on size, timer, or shutdown.
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
				w.flush(ctx, batch)
				batch = batch[:0]
				resetWebhookTimer(timer, w.flushIvl)
			}

		case <-timer.C:
			if len(batch) > 0 {
				w.flush(ctx, batch)
				batch = batch[:0]
			}
			resetWebhookTimer(timer, w.flushIvl)

		case <-ctx.Done():
			w.drainAndFlush(batch)
			return
		}
	}
}

// drainAndFlush reads remaining events from the channel and does a
// final flush with a fresh context.
func (w *WebhookOutput) drainAndFlush(batch [][]byte) {
	for {
		select {
		case data := <-w.ch:
			batch = append(batch, data)
		default:
			if len(batch) > 0 {
				w.flushFinal(batch)
			}
			return
		}
	}
}

// flush sends a batch via HTTP POST with retry.
func (w *WebhookOutput) flush(ctx context.Context, batch [][]byte) {
	w.doPostWithRetry(ctx, batch)
}

// flushFinal sends a final batch during shutdown with a fresh
// short-deadline context (the main context is already cancelled).
func (w *WebhookOutput) flushFinal(batch [][]byte) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()
	w.doPostWithRetry(ctx, batch)
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
