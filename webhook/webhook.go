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

// The webhook output uses a two-buffer architecture:
//
//	Logger drain goroutine
//	  → Output.Write(data) — non-blocking copy+enqueue
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

	audit "github.com/axonops/go-audit"
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// Compile-time assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DeliveryReporter = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
)

// Metrics is an optional interface for webhook-specific
// instrumentation. Pass an implementation to [New] to
// collect batch-level telemetry. Pass nil to disable.
type Metrics interface {
	// RecordWebhookDrop records that an event was dropped because the
	// webhook output's internal buffer was full.
	RecordWebhookDrop()

	// RecordWebhookFlush records a webhook batch flush with the number
	// of events in the batch and the flush duration.
	RecordWebhookFlush(batchSize int, dur time.Duration)
}

// errRedirectBlocked is returned by the http.Client's CheckRedirect
// function. It is checked in doPost to classify redirect errors as
// non-retryable.
var errRedirectBlocked = errors.New("audit: webhook redirects are not followed")

// Output sends batched audit events to an HTTP endpoint with
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
// The HTTP client uses [audit.NewSSRFDialControl] to block
// connections to private, loopback, link-local, and cloud metadata
// addresses. Redirects are rejected entirely. Keep-alives are disabled
// to force fresh DNS resolution per request, preventing DNS rebinding.
//
// # At-Least-Once Semantics
//
// Retries may cause duplicate delivery if the server processes a batch
// but returns 5xx due to a timeout. Receivers SHOULD be idempotent.
//
// Output is safe for concurrent use.
type Output struct {
	metrics        audit.Metrics
	webhookMetrics Metrics
	done           chan struct{}
	closeCh        chan struct{} // signals batchLoop to drain and exit
	headers        map[string]string
	ch             chan []byte
	cancel         context.CancelFunc
	client         *http.Client
	url            string
	name           string // cached from url.Parse at construction
	batchSize      int
	maxRetries     int
	flushIvl       time.Duration
	timeout        time.Duration
	mu             sync.Mutex
	closed         atomic.Bool
	drops          dropLimiter // rate-limits buffer-full slog.Warn
}

// New creates a new [Output] from the given config.
// It validates the config, builds an SSRF-safe HTTP client, and starts
// the background batch goroutine. Both metrics parameters are optional
// (may be nil).
func New(cfg *Config, metrics audit.Metrics, webhookMetrics Metrics) (*Output, error) {
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

	var ssrfOpts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		ssrfOpts = append(ssrfOpts, audit.AllowPrivateRanges())
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: audit.NewSSRFDialControl(ssrfOpts...),
		}).DialContext,
		TLSClientConfig:     tlsCfg,
		DisableKeepAlives:   true, // force fresh dial per request (DNS rebinding)
		TLSHandshakeTimeout: 10 * time.Second,
		// Half the client timeout: detect slow-to-respond servers
		// early, leaving room for body transfer within the overall
		// http.Client.Timeout. Zero result for very small timeouts
		// is harmless: http.Client.Timeout still enforces the
		// overall deadline.
		ResponseHeaderTimeout: cfg.Timeout / 2,
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

	w := &Output{
		client:         client,
		url:            cfg.URL,
		name:           webhookName(cfg.URL),
		headers:        headers,
		metrics:        metrics,
		webhookMetrics: webhookMetrics,
		ch:             make(chan []byte, cfg.BufferSize),
		closeCh:        make(chan struct{}),
		cancel:         cancel,
		done:           make(chan struct{}),
		batchSize:      cfg.BatchSize,
		maxRetries:     cfg.MaxRetries,
		flushIvl:       cfg.FlushInterval,
		timeout:        cfg.Timeout,
	}

	go w.batchLoop(ctx)
	return w, nil
}

// Write enqueues a serialised audit event for batched delivery. The
// data is copied before enqueuing. If the internal buffer is full,
// the event is dropped and [Metrics.RecordWebhookDrop] is called.
// Write never blocks the caller.
func (w *Output) Write(data []byte) error {
	if w.closed.Load() {
		return audit.ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case w.ch <- cp:
		return nil
	default:
		w.drops.record(dropWarnInterval, func(dropped int64) {
			slog.Warn("audit: webhook buffer full, events dropped",
				"dropped", dropped,
				"buffer_size", cap(w.ch))
		})
		if w.webhookMetrics != nil {
			w.webhookMetrics.RecordWebhookDrop()
		}
		if w.metrics != nil {
			w.metrics.RecordEvent(w.Name(), "error")
		}
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the batch goroutine to drain and flush, then waits
// for completion. In-flight HTTP requests complete using the live
// context before the context is cancelled. Close is idempotent.
func (w *Output) Close() error {
	// Dual mechanism: mutex serialises the full Close sequence (signal,
	// wait, cancel, cleanup). Atomic provides fast-path rejection in
	// Write() without acquiring the mutex on every call.
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal the batch loop to drain and exit. The batch loop will
	// flush any pending events using the LIVE context (not cancelled),
	// ensuring in-flight HTTP POSTs complete successfully.
	close(w.closeCh)

	// Shutdown timeout: 2x HTTP timeout (worst-case in-flight +
	// final flush) plus 5s buffer for backoff and channel drain.
	shutdownTimeout := 2*w.timeout + 5*time.Second
	select {
	case <-w.done:
	case <-time.After(shutdownTimeout):
		slog.Error("audit: webhook batch goroutine did not exit",
			"timeout", shutdownTimeout)
	}

	// Cancel the context AFTER the batch loop exits to clean up any
	// resources tied to it, then close idle HTTP connections.
	w.cancel()
	w.client.CloseIdleConnections()
	return nil
}

// ReportsDelivery returns true, indicating that Output reports
// its own delivery metrics from the batch goroutine after actual HTTP
// delivery, not from the Write enqueue path.
func (w *Output) ReportsDelivery() bool { return true }

// Name returns the human-readable identifier for this output.
// The name is cached at construction time to avoid per-call url.Parse.
func (w *Output) Name() string {
	return w.name
}

// DestinationKey returns the webhook URL with query parameters and
// fragment stripped, enabling duplicate destination detection via
// [audit.DestinationKeyer]. Query parameters are stripped to avoid
// leaking auth tokens in error messages if two outputs collide.
func (w *Output) DestinationKey() string {
	u, err := url.Parse(w.url)
	if err != nil {
		return w.url
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// webhookName parses the URL and returns "webhook:<host>" or "webhook"
// if parsing fails.
func webhookName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return "webhook:" + u.Host
	}
	return "webhook"
}

// batchLoop is the background goroutine that accumulates events and
// flushes batches on size, timer, or shutdown.
func (w *Output) batchLoop(ctx context.Context) {
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

		case <-w.closeCh:
			// Go's select picks randomly among ready cases. If both
			// closeCh and w.ch are ready, data may be read first —
			// drainAndFlush handles any remaining channel items.
			w.drainAndFlush(ctx, batch)
			return
		}
	}
}

// drainAndFlush reads remaining events from the channel and does a
// final flush using the live (not-yet-cancelled) context. This ensures
// in-flight HTTP requests complete successfully during shutdown.
func (w *Output) drainAndFlush(ctx context.Context, batch [][]byte) {
	for {
		select {
		case data := <-w.ch:
			batch = append(batch, data)
		default:
			if len(batch) > 0 {
				w.flush(ctx, batch)
			}
			return
		}
	}
}

// flush sends a batch via HTTP POST with retry.
func (w *Output) flush(ctx context.Context, batch [][]byte) {
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
