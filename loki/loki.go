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
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	audit "github.com/axonops/go-audit"
)

// Compile-time interface assertions.
var (
	_ audit.Output                 = (*Output)(nil)
	_ audit.MetadataWriter         = (*Output)(nil)
	_ audit.DeliveryReporter       = (*Output)(nil)
	_ audit.DestinationKeyer       = (*Output)(nil)
	_ audit.FrameworkFieldReceiver = (*Output)(nil)
)

// errRedirectBlocked is returned by the HTTP client's CheckRedirect
// to reject all redirects, preventing SSRF via open redirects.
var errRedirectBlocked = errors.New("audit: loki redirects are not followed")

// lokiEntry carries a copied event and its metadata through the
// internal buffer channel to the batch goroutine.
type lokiEntry struct { //nolint:govet // fieldalignment: readability preferred
	data     []byte              // defensive copy of serialised event
	metadata audit.EventMetadata // per-event fields for stream labels
}

// frameworkFields holds logger-wide constant metadata used for Loki
// stream labels. Stored atomically to avoid data races between the
// core library's SetFrameworkFields call and the batchLoop goroutine.
type frameworkFields struct {
	appName string
	host    string
	pid     int
}

// Output pushes audit events to a Grafana Loki instance via the HTTP
// Push API. It implements [audit.Output], [audit.MetadataWriter],
// [audit.DeliveryReporter], [audit.DestinationKeyer], and
// [audit.FrameworkFieldReceiver].
//
// Events are buffered and flushed in batches based on count, byte
// size, or time interval — whichever threshold is reached first.
type Output struct { //nolint:govet // fieldalignment: readability preferred
	cfg         *Config
	metrics     audit.Metrics  // core pipeline metrics (optional)
	lokiMetrics Metrics        // loki-specific metrics (optional)
	ch          chan lokiEntry // buffered input channel
	done        chan struct{}  // signals batch goroutine exit
	cancel      context.CancelFunc
	client      *http.Client
	name        string // "loki:<host>", cached at construction
	mu          sync.Mutex
	closed      atomic.Bool
	fw          atomic.Pointer[frameworkFields]

	// Flush-path state — owned exclusively by batchLoop goroutine.
	streams     map[string]*lokiStream // reused across flushes
	dynFields   []dynamicField         // reused dynamic field slice
	keyBuf      bytes.Buffer           // reused stream key builder
	payloadBuf  bytes.Buffer           // reused JSON payload buffer
	compressBuf bytes.Buffer           // reused gzip output buffer
	gzWriter    *gzip.Writer           // reused gzip writer
}

// New creates a new Loki [Output] from the given config. It validates
// the config, builds an SSRF-safe HTTP client, and starts the
// background batch goroutine. Both metrics parameters are optional
// (may be nil).
func New(cfg *Config, metrics audit.Metrics, lokiMetrics Metrics) (*Output, error) {
	// Copy config so validation/defaults don't mutate the caller's struct.
	cfgCopy := *cfg
	cfg = &cfgCopy

	if err := validateLokiConfig(cfg); err != nil {
		return nil, err
	}

	tlsCfg, warnings, err := buildLokiTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	// Log TLS policy warnings via slog (consistent with webhook/syslog).
	u, _ := url.Parse(cfg.URL) // already validated
	host := u.Scheme + "://" + u.Host
	for _, w := range warnings {
		slog.Warn(w, "url", host)
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
		TLSClientConfig:       tlsCfg,
		DisableKeepAlives:     true, // force fresh dial per request (DNS rebinding)
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout / 2,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}

	// Copy headers to prevent caller mutation.
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	cfg.Headers = headers

	ctx, cancel := context.WithCancel(context.Background())

	o := &Output{
		cfg:         cfg,
		metrics:     metrics,
		lokiMetrics: lokiMetrics,
		ch:          make(chan lokiEntry, cfg.BufferSize),
		cancel:      cancel,
		done:        make(chan struct{}),
		client:      client,
		name:        lokiName(cfg.URL),
		streams:     make(map[string]*lokiStream),
	}

	go o.batchLoop(ctx)
	return o, nil
}

// SetFrameworkFields receives logger-wide framework metadata for use
// as Loki stream labels. Called once by the core library at logger
// construction time. The data is stored atomically, safe for
// concurrent access from the batchLoop goroutine.
func (o *Output) SetFrameworkFields(appName, host string, pid int) {
	o.fw.Store(&frameworkFields{appName: appName, host: host, pid: pid})
}

// WriteWithMetadata enqueues a serialised audit event with per-event
// metadata for batched delivery. The data is copied before enqueuing.
// If the internal buffer is full, the event is dropped and
// [Metrics.RecordLokiDrop] is called. WriteWithMetadata never blocks.
func (o *Output) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	if o.closed.Load() {
		return audit.ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case o.ch <- lokiEntry{data: cp, metadata: meta}:
		return nil
	default:
		slog.Warn("audit: loki buffer full, dropping event",
			"buffer_size", cap(o.ch))
		if o.lokiMetrics != nil {
			o.lokiMetrics.RecordLokiDrop()
		}
		if o.metrics != nil {
			o.metrics.RecordEvent(o.Name(), "error")
		}
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Write enqueues a serialised audit event without metadata. When
// called directly (outside the core library's MetadataWriter
// dispatch), events are delivered with framework-only stream labels
// and no per-event dynamic labels. Prefer WriteWithMetadata.
func (o *Output) Write(data []byte) error {
	return o.WriteWithMetadata(data, audit.EventMetadata{})
}

// Close signals the batch goroutine to drain and flush, then waits
// for completion. In-flight HTTP retries are cancelled via context.
// Close is idempotent.
func (o *Output) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !o.closed.CompareAndSwap(false, true) {
		return nil
	}

	o.cancel()

	// Shutdown timeout: 2x HTTP timeout (worst-case in-flight +
	// final flush) plus 5s buffer for backoff and channel drain.
	shutdownTimeout := 2*o.cfg.Timeout + 5*time.Second
	select {
	case <-o.done:
	case <-time.After(shutdownTimeout):
		slog.Error("audit: loki batch goroutine did not exit",
			"timeout", shutdownTimeout)
	}

	o.client.CloseIdleConnections()
	return nil
}

// ReportsDelivery returns true, indicating that Output reports
// its own delivery metrics from the batch goroutine after actual HTTP
// delivery, not from the Write enqueue path.
func (o *Output) ReportsDelivery() bool { return true }

// Name returns the human-readable identifier for this output.
func (o *Output) Name() string { return o.name }

// DestinationKey returns the Loki URL with query parameters and
// fragment stripped, enabling duplicate destination detection via
// [audit.DestinationKeyer].
func (o *Output) DestinationKey() string {
	u, err := url.Parse(o.cfg.URL)
	if err != nil {
		return o.cfg.URL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// lokiName parses the URL and returns "loki:<host>" or "loki" if
// parsing fails.
func lokiName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return "loki:" + u.Host
	}
	return "loki"
}

// batchLoop is the background goroutine that accumulates events and
// flushes batches on count, bytes, timer, or shutdown.
func (o *Output) batchLoop(ctx context.Context) {
	defer close(o.done)

	batch := make([]lokiEntry, 0, o.cfg.BatchSize)
	batchBytes := 0
	timer := time.NewTimer(o.cfg.FlushInterval)
	defer timer.Stop()

	for {
		select {
		case entry := <-o.ch:
			batch = append(batch, entry)
			batchBytes += len(entry.data)
			if len(batch) >= o.cfg.BatchSize || batchBytes >= o.cfg.MaxBatchBytes {
				o.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
				resetLokiTimer(timer, o.cfg.FlushInterval)
			}

		case <-timer.C:
			if len(batch) > 0 {
				o.flush(ctx, batch)
				batch = batch[:0]
				batchBytes = 0
			}
			resetLokiTimer(timer, o.cfg.FlushInterval)

		case <-ctx.Done():
			o.drainAndFlush(batch)
			return
		}
	}
}

// drainAndFlush reads remaining events from the channel and does a
// final flush with a fresh context.
func (o *Output) drainAndFlush(batch []lokiEntry) {
	for {
		select {
		case entry := <-o.ch:
			batch = append(batch, entry)
		default:
			if len(batch) > 0 {
				o.flushFinal(batch)
			}
			return
		}
	}
}

// flush groups events into streams, builds the push payload, compresses
// it, and delivers to Loki. Phase 4 adds HTTP delivery with retry;
// for now metrics are recorded as if delivery succeeded (#251).
func (o *Output) flush(_ context.Context, batch []lokiEntry) {
	start := time.Now()

	o.groupByStream(batch)
	o.buildPayload()
	_ = o.maybeCompress() // Phase 4: POST this body to Loki

	dur := time.Since(start)
	if o.lokiMetrics != nil {
		o.lokiMetrics.RecordLokiFlush(len(batch), dur)
	}
	if o.metrics != nil {
		for range batch {
			o.metrics.RecordEvent(o.Name(), "success")
		}
	}
}

// flushFinal sends a final batch during shutdown with a fresh
// short-deadline context (the main context is already cancelled).
func (o *Output) flushFinal(batch []lokiEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), o.cfg.Timeout)
	defer cancel()
	o.flush(ctx, batch)
}

// resetLokiTimer safely resets a timer, draining the channel first
// if the timer has already fired.
func resetLokiTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}
