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

package syslog

// srslog (github.com/axonops/srslog) is the AxonOps fork of the srslog
// library, providing RFC 5424 formatting, TCP/UDP/TLS transport, and
// thread-safe writes. Forked from github.com/gravwell/srslog for tagged
// release support and supply chain control (see #147).

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/srslog"
)

// Compile-time assertions.
var (
	_ audit.Output                = (*Output)(nil)
	_ audit.DestinationKeyer      = (*Output)(nil)
	_ audit.MetadataWriter        = (*Output)(nil)
	_ audit.DeliveryReporter      = (*Output)(nil)
	_ audit.OutputMetricsReceiver = (*Output)(nil)
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// syslogSeverities maps audit severity (0-10) to srslog severity.
// Indexed by audit severity. The mapping follows RFC 5424 severity
// semantics where lower syslog values are more critical:
//
//   - Audit 10 → LOG_CRIT (2): critical security events
//   - Audit 8-9 → LOG_ERR (3): high-severity events
//   - Audit 6-7 → LOG_WARNING (4): medium-severity events
//   - Audit 4-5 → LOG_NOTICE (5): normal operational events
//   - Audit 1-3 → LOG_INFO (6): low-severity informational events
//   - Audit 0 → LOG_DEBUG (7): debug/trace events
//
// LOG_EMERG (0) and LOG_ALERT (1) are intentionally excluded — they
// are reserved for system-level emergencies (kernel panics, imminent
// hardware failure) and can trigger console broadcasts and pager
// alerts on many syslog receivers. An audit library should never emit
// these severities.
var syslogSeverities = [11]srslog.Priority{
	srslog.LOG_DEBUG,   // audit 0
	srslog.LOG_INFO,    // audit 1
	srslog.LOG_INFO,    // audit 2
	srslog.LOG_INFO,    // audit 3
	srslog.LOG_NOTICE,  // audit 4
	srslog.LOG_NOTICE,  // audit 5
	srslog.LOG_WARNING, // audit 6
	srslog.LOG_WARNING, // audit 7
	srslog.LOG_ERR,     // audit 8
	srslog.LOG_ERR,     // audit 9
	srslog.LOG_CRIT,    // audit 10
}

// mapSeverity converts an audit event severity (0–10) to an srslog
// priority constant using the mapping in syslogSeverities. Values
// outside [0, 10] silently fall back to LOG_INFO (syslog severity 6).
// The taxonomy enforces the 0–10 range at registration time, so
// out-of-range values indicate a programming error in a custom [Output]
// that bypasses the auditor and calls this function directly.
func mapSeverity(auditSeverity int) srslog.Priority {
	if auditSeverity < 0 || auditSeverity > 10 {
		return srslog.LOG_INFO
	}
	return syslogSeverities[auditSeverity]
}

// Metrics is an optional interface for syslog-specific
// instrumentation. Pass an implementation to [New] to
// collect reconnection telemetry. Pass nil to disable.
//
// When using the unified [audit.OutputMetrics] via
// [audit.OutputMetricsReceiver], the syslog output auto-detects
// whether the OutputMetrics value also implements this interface
// via type assertion.
type Metrics interface {
	// RecordSyslogReconnect records a syslog reconnection attempt.
	// success indicates whether the reconnection succeeded. The
	// address is the configured host:port. Implementations SHOULD
	// NOT use address as an unbounded metric label.
	RecordSyslogReconnect(address string, success bool)
}

// syslogEntry carries a copied event and its priority through the
// internal buffer channel to the writeLoop goroutine.
type syslogEntry struct {
	data     []byte
	priority srslog.Priority
}

// Output writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit
// payload (JSON or CEF) as the message body.
//
// Write enqueues events into an internal buffered channel and returns
// immediately. A background goroutine reads from the channel and
// performs the actual syslog write with reconnection handling.
//
// # Reconnection
//
// On connection failure, the background goroutine attempts bounded
// exponential backoff reconnection (100ms to 30s with jitter, up to
// [Config.MaxRetries] attempts). If all retries are exhausted, the
// event is dropped and an error metric is recorded. The goroutine
// continues processing subsequent events.
//
// # UDP limitations
//
// UDP syslog is fire-and-forget. Write over UDP rarely returns an
// error even if no server is listening. RFC 5424 recommends receivers
// support messages up to 2048 bytes on UDP; larger payloads may be
// silently truncated or dropped by the OS. Consumers with large audit
// events SHOULD use TCP or TCP+TLS.
//
// # TLS certificates
//
// TLS certificate files are loaded once at construction time and are
// NOT hot-reloaded. If a certificate expires and is rotated on disk,
// the output continues using the old certificate until the process is
// restarted.
//
// Output is safe for concurrent use.
type Output struct {
	writer        *srslog.Writer
	tlsCfg        *tls.Config                         // cached for reconnection; nil for non-TLS
	syslogMetrics atomic.Pointer[Metrics]             // extension: RecordSyslogReconnect (may be nil)
	outputMetrics atomic.Pointer[audit.OutputMetrics] // unified per-output metrics (may be nil)
	logger        atomic.Pointer[slog.Logger]         // diagnostic logger; swapped atomically post-construction (#474)
	ch            chan syslogEntry                    // async buffer
	closeCh       chan struct{}                       // signals writeLoop to drain and exit
	done          chan struct{}                       // closed when writeLoop exits
	name          string                              // cached Name() result
	address       string
	network       string
	appName       string
	hostname      string
	writeCount    uint64      // drain-side event counter for RecordQueueDepth sampling
	drops         dropLimiter // rate-limits buffer-full drop warnings
	closed        atomic.Bool
	mu            sync.Mutex      // protects Close sequence
	facility      srslog.Priority // facility bits only (no severity)
	failures      int             // consecutive failure count (writeLoop-only)
	maxRetry      int
}

// SetDiagnosticLogger receives the library's diagnostic logger.
//
// Safe for concurrent use with the background write goroutine and any
// active [Output.Write] caller — the logger field is an
// [atomic.Pointer] so readers always see a fully-published value.
func (s *Output) SetDiagnosticLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	s.logger.Store(l)
}

// New creates a new [Output] from the given config.
// It validates the config, establishes the initial connection, and
// starts the background writeLoop goroutine.
// The syslogMetrics parameter is optional (may be nil).
//
// Optional [Option] arguments tune construction-time behaviour. Pass
// [WithDiagnosticLogger] to route TLS-policy warnings (emitted before
// the auditor's diagnostic logger is propagated post-construction) to
// a custom logger.
func New(cfg *Config, syslogMetrics Metrics, opts ...Option) (*Output, error) {
	o := resolveOptions(opts)

	if err := validateSyslogConfig(cfg); err != nil {
		return nil, err
	}

	priority, err := parseFacility(cfg.Facility)
	if err != nil {
		return nil, fmt.Errorf("audit: syslog facility %q: %w", cfg.Facility, err)
	}

	// Use explicit hostname from config if provided; otherwise fall
	// back to os.Hostname(). Failure is non-fatal; an empty hostname
	// is acceptable in the RFC 5424 header (NILVALUE "-" per §6.2.4).
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	var tlsCfg *tls.Config
	if cfg.Network == "tcp+tls" {
		tlsCfg, err = buildSyslogTLSConfig(cfg, o.logger)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls config: %w", err)
		}
	}

	maxRetry := cfg.MaxRetries
	if maxRetry <= 0 {
		maxRetry = DefaultMaxRetries
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}

	s := &Output{
		tlsCfg:   tlsCfg,
		ch:       make(chan syslogEntry, bufSize),
		closeCh:  make(chan struct{}),
		done:     make(chan struct{}),
		name:     "syslog:" + cfg.Address,
		address:  cfg.Address,
		network:  cfg.Network,
		appName:  cfg.AppName,
		hostname: hostname,
		facility: priority, // parseFacility returns facility bits only
		maxRetry: maxRetry,
	}
	// Publish the initial logger BEFORE starting the write goroutine.
	// resolveOptions already replaced nil with slog.Default.
	s.logger.Store(o.logger)
	if syslogMetrics != nil {
		s.syslogMetrics.Store(&syslogMetrics)
	}

	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("audit: syslog dial %s://%s: %w",
			cfg.Network, cfg.Address, err)
	}

	go s.writeLoop()
	return s, nil
}

// Write enqueues a serialised audit event for async delivery to the
// syslog server with the default severity (LOG_INFO). The data is
// copied before enqueuing. If the internal buffer is full, the event
// is dropped. Write never blocks the caller.
func (s *Output) Write(data []byte) error {
	return s.enqueue(data, s.facility|srslog.LOG_INFO)
}

// WriteWithMetadata enqueues a serialised audit event for async
// delivery with the syslog severity derived from the audit event's
// severity field.
func (s *Output) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	return s.enqueue(data, s.facility|mapSeverity(meta.Severity))
}

// enqueue copies data and sends it to the writeLoop via the buffered
// channel. If the channel is full, the event is dropped with metrics.
func (s *Output) enqueue(data []byte, priority srslog.Priority) error {
	if s.closed.Load() {
		return audit.ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case s.ch <- syslogEntry{data: cp, priority: priority}:
		return nil
	default:
		s.drops.record(dropWarnInterval, func(dropped int64) {
			s.logger.Load().Warn("audit: output syslog: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(s.ch))
		})
		if omp := s.outputMetrics.Load(); omp != nil {
			(*omp).RecordDrop()
		}
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the background goroutine to drain and flush, then
// waits for completion and closes the syslog connection. Close is
// idempotent and safe for concurrent use.
func (s *Output) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal writeLoop to drain remaining events and exit.
	close(s.closeCh)

	// Wait for writeLoop to finish draining.
	shutdownTimeout := 10 * time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-s.done:
	case <-timer.C:
		remaining := len(s.ch)
		s.logger.Load().Error("audit: output syslog: shutdown timeout, events lost",
			"timeout", shutdownTimeout,
			"events_lost", remaining)
	}

	// Close the srslog.Writer AFTER the writeLoop exits.
	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			return fmt.Errorf("audit: syslog close: %w", err)
		}
	}
	return nil
}

// ReportsDelivery returns true, indicating that Output reports its
// own delivery metrics from the background writeLoop after actual
// syslog delivery, not from the Write enqueue path.
func (s *Output) ReportsDelivery() bool { return true }

// SetOutputMetrics receives the per-output metrics instance.
func (s *Output) SetOutputMetrics(m audit.OutputMetrics) {
	s.outputMetrics.Store(&m)
	// Check if the OutputMetrics also implements the syslog-specific
	// Metrics extension interface for reconnection recording.
	if sm, ok := m.(Metrics); ok {
		s.syslogMetrics.Store(&sm)
	}
}

// Name returns the human-readable identifier for this output.
func (s *Output) Name() string {
	return s.name
}

// DestinationKey returns the syslog server address, enabling
// duplicate destination detection via [audit.DestinationKeyer].
func (s *Output) DestinationKey() string {
	return s.address
}

// connect establishes a connection to the syslog server.
func (s *Output) connect() error {
	var w *srslog.Writer
	var err error

	defaultPriority := s.facility | srslog.LOG_INFO
	if s.tlsCfg != nil {
		w, err = srslog.DialWithTLSConfig(
			"tcp+tls", s.address, defaultPriority, s.appName, s.tlsCfg)
	} else {
		w, err = srslog.Dial(s.network, s.address, defaultPriority, s.appName)
	}
	if err != nil {
		return fmt.Errorf("audit: syslog connect %s://%s: %w", s.network, s.address, err)
	}

	w.SetFormatter(srslog.RFC5424Formatter)
	// RFC 5425 octet-counting framing is TCP-only; UDP (RFC 5426)
	// uses one-message-per-datagram with no framing prefix.
	if s.network != "udp" {
		w.SetFramer(srslog.RFC5425MessageLengthFramer)
	}
	w.SetHostname(s.hostname)
	s.writer = w
	return nil
}

// writeLoop is the background goroutine that reads events from the
// channel and writes them to the syslog server. It runs until closeCh
// is closed, then drains remaining events before returning.
func (s *Output) writeLoop() {
	defer close(s.done)

	for {
		select {
		case entry := <-s.ch:
			s.writeEntry(entry)
		case <-s.closeCh:
			s.drainRemaining()
			return
		}
	}
}

// errSyslogNotConnected is returned when the syslog writer is nil
// (previous reconnect failed). Pre-allocated to avoid per-event alloc.
var errSyslogNotConnected = errors.New("audit: syslog writer not connected")

// writeEntry writes a single event to the syslog server with panic
// recovery and reconnection handling.
func (s *Output) writeEntry(entry syslogEntry) { //nolint:gocyclo,cyclop // event write with recovery and reconnection
	// Load metrics once per event for consistent snapshot.
	var om audit.OutputMetrics
	if omp := s.outputMetrics.Load(); omp != nil {
		om = *omp
	}

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			s.logger.Load().Error("audit: output syslog: panic recovered",
				"panic", r,
				"stack", string(buf[:n]))
			if om != nil {
				om.RecordError()
			}
		}
	}()

	// Sample queue depth every 64 events.
	s.writeCount++
	if om != nil && s.writeCount&63 == 0 {
		om.RecordQueueDepth(len(s.ch), cap(s.ch))
	}

	var start time.Time
	if om != nil {
		start = time.Now()
	}

	// Attempt write. If the writer is nil (previous reconnect failed),
	// treat as a write failure.
	var writeErr error
	if s.writer == nil {
		writeErr = errSyslogNotConnected
	} else if _, err := s.writer.WriteWithPriority(entry.priority, entry.data); err != nil {
		writeErr = err
	}

	if writeErr == nil {
		s.failures = 0
		if om != nil {
			om.RecordFlush(1, time.Since(start))
		}
		return
	}

	// Write failed — attempt reconnection with backoff.
	s.handleWriteFailure(entry, writeErr, om)
}

// handleWriteFailure attempts reconnection with bounded exponential
// backoff. Called from writeLoop (single goroutine — no mutex needed).
// On success, retries the original write. On exhaustion, drops the
// event.
func (s *Output) handleWriteFailure(entry syslogEntry, writeErr error, om audit.OutputMetrics) { //nolint:gocyclo,cyclop // reconnection with backoff
	s.failures++

	if s.failures > s.maxRetry {
		s.logger.Load().Error("audit: output syslog: retries exhausted, dropping event",
			"address", s.address,
			"failures", s.failures,
			"last_error", writeErr)
		if om != nil {
			om.RecordError()
		}
		return
	}

	// Close the old writer before reconnecting.
	if s.writer != nil {
		closeWriterForReconnect(s.writer.Close, s.logger.Load(), s.address)
		s.writer = nil
	}

	backoff := backoffDuration(s.failures)
	s.logger.Load().Warn("audit: output syslog: reconnecting",
		"address", s.address,
		"attempt", s.failures,
		"backoff", backoff)

	if om != nil {
		om.RecordRetry(s.failures)
	}

	// Sleep with closeCh interrupt — no mutex to release since the
	// writeLoop goroutine owns the connection exclusively.
	timer := time.NewTimer(backoff)
	select {
	case <-timer.C:
	case <-s.closeCh:
		timer.Stop()
		// Shutting down — don't reconnect, just drop.
		return
	}
	timer.Stop()

	// Load syslog extension metrics for reconnect recording.
	var sm Metrics
	if smp := s.syslogMetrics.Load(); smp != nil {
		sm = *smp
	}

	if err := s.connect(); err != nil {
		s.logger.Load().Error("audit: output syslog: reconnect failed",
			"address", s.address,
			"attempt", s.failures,
			"error", err)
		if sm != nil {
			sm.RecordSyslogReconnect(s.address, false)
		}
		return
	}

	s.logger.Load().Info("audit: syslog reconnected", "address", s.address)
	if sm != nil {
		sm.RecordSyslogReconnect(s.address, true)
	}

	// Retry the write on the new connection.
	if _, err := s.writer.WriteWithPriority(entry.priority, entry.data); err != nil {
		s.logger.Load().Error("audit: output syslog: delivery failed after reconnect",
			"error", err)
		if om != nil {
			om.RecordError()
		}
		return
	}

	s.failures = 0
	if om != nil {
		om.RecordFlush(1, 0) // duration not meaningful after reconnect
	}
}

// drainRemaining reads all remaining events from the channel after
// closeCh fires and writes them. No reconnection during drain — if
// the connection is broken, remaining events are dropped.
func (s *Output) drainRemaining() {
	for {
		select {
		case entry := <-s.ch:
			s.drainOne(entry)
		default:
			return
		}
	}
}

// drainOne writes a single event during drain with panic recovery
// and metrics recording. No reconnection is attempted — if the write
// fails, the event is dropped.
func (s *Output) drainOne(entry syslogEntry) {
	var om audit.OutputMetrics
	if omp := s.outputMetrics.Load(); omp != nil {
		om = *omp
	}

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			s.logger.Load().Error("audit: output syslog: panic recovered during drain",
				"panic", r,
				"stack", string(buf[:n]))
			if om != nil {
				om.RecordError()
			}
		}
	}()

	if s.writer == nil {
		return
	}

	var start time.Time
	if om != nil {
		start = time.Now()
	}
	if _, err := s.writer.WriteWithPriority(entry.priority, entry.data); err != nil {
		s.logger.Load().Error("audit: output syslog: delivery failed during drain",
			"error", err)
		if om != nil {
			om.RecordError()
		}
	} else if om != nil {
		om.RecordFlush(1, time.Since(start))
	}
}
