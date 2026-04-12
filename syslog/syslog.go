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
	"fmt"
	"os"
	"sync"

	"github.com/axonops/audit"
	"github.com/axonops/srslog"
)

// Compile-time assertion: Output satisfies audit.Output and
// audit.MetadataWriter (for per-event severity mapping).
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
	_ audit.MetadataWriter   = (*Output)(nil)
)

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
// that bypasses the logger and calls this function directly.
func mapSeverity(auditSeverity int) srslog.Priority {
	if auditSeverity < 0 || auditSeverity > 10 {
		return srslog.LOG_INFO
	}
	return syslogSeverities[auditSeverity]
}

// Metrics is an optional interface for syslog-specific
// instrumentation. Pass an implementation to [New] to
// collect reconnection telemetry. Pass nil to disable.
type Metrics interface {
	// RecordSyslogReconnect records a syslog reconnection attempt.
	// success indicates whether the reconnection succeeded. The
	// address is the configured host:port. Implementations SHOULD
	// NOT use address as an unbounded metric label.
	RecordSyslogReconnect(address string, success bool)
}

// Output writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit
// payload (JSON or CEF) as the message body.
//
// # Reconnection
//
// On connection failure, [Output] attempts bounded exponential
// backoff reconnection (100ms to 30s with jitter, up to
// [Config.MaxRetries] attempts). Reconnection happens within
// [Write]: the mutex is released during the backoff sleep so [Close]
// can interrupt it. On reconnection, the old srslog.Writer is closed
// and a fresh connection is dialled — this avoids conflicting with
// srslog's own internal retry-on-write behaviour. The event that
// triggered the reconnection is retried once on the new connection.
// If all retries are exhausted, the event is lost and an error is
// returned.
//
// # UDP limitations
//
// UDP syslog is fire-and-forget. [Write] over UDP rarely returns an
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
// restarted. This differs from the schema registry which supports
// certificate auto-reload.
//
// Output is safe for concurrent use.
type Output struct {
	writer        *srslog.Writer
	tlsCfg        *tls.Config // cached for reconnection; nil for non-TLS
	syslogMetrics Metrics     // optional; nil disables syslog-specific metrics
	closeCh       chan struct{}
	address       string
	network       string
	appName       string
	hostname      string
	mu            sync.Mutex
	facility      srslog.Priority // facility bits only (no severity)
	failures      int             // consecutive failure count
	maxRetry      int
	closed        bool
}

// New creates a new [Output] from the given config.
// It validates the config and establishes the initial connection.
// The syslogMetrics parameter is optional (may be nil).
func New(cfg *Config, syslogMetrics Metrics) (*Output, error) {
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
	// Note: both hostname and ProcID (set by srslog via os.Getpid())
	// are cached at construction time and not updated if the process
	// forks or the hostname changes during the process lifetime.
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	var tlsCfg *tls.Config
	if cfg.Network == "tcp+tls" {
		tlsCfg, err = buildSyslogTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls config: %w", err)
		}
	}

	maxRetry := cfg.MaxRetries
	if maxRetry <= 0 {
		maxRetry = DefaultMaxRetries
	}

	s := &Output{
		tlsCfg:        tlsCfg,
		syslogMetrics: syslogMetrics,
		closeCh:       make(chan struct{}),
		address:       cfg.Address,
		network:       cfg.Network,
		appName:       cfg.AppName,
		hostname:      hostname,
		facility:      priority, // parseFacility returns facility bits only
		maxRetry:      maxRetry,
	}

	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("audit: syslog dial %s://%s: %w",
			cfg.Network, cfg.Address, err)
	}

	return s, nil
}

// Write sends a serialised audit event to the syslog server with the
// default severity (LOG_INFO). For per-event severity mapping based on
// the audit event's severity field, the logger calls
// [WriteWithMetadata] instead. On connection failure, Write attempts
// reconnection with bounded exponential backoff. Write returns
// [audit.ErrOutputClosed] if the output has been closed.
func (s *Output) Write(data []byte) error {
	return s.writeWithPriority(data, s.facility|srslog.LOG_INFO)
}

// WriteWithMetadata sends a serialised audit event to the syslog
// server with the syslog severity derived from the audit event's
// severity field. The mapping follows RFC 5424 severity semantics:
// audit severity 10 → LOG_CRIT, 8-9 → LOG_ERR, 6-7 → LOG_WARNING,
// 4-5 → LOG_NOTICE, 1-3 → LOG_INFO, 0 → LOG_DEBUG. See the
// package-level syslogSeverities table for the complete mapping.
func (s *Output) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	return s.writeWithPriority(data, s.facility|mapSeverity(meta.Severity))
}

// writeWithPriority is the internal write path shared by [Write] and
// [WriteWithMetadata]. It sends data to the syslog server with the
// given priority (facility | severity) and handles reconnection on
// failure.
func (s *Output) writeWithPriority(data []byte, priority srslog.Priority) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		return audit.ErrOutputClosed
	}

	// writer may be nil if a previous reconnect attempt failed and left
	// the connection in a broken state. Treat a nil writer as a write
	// failure so handleWriteFailure can attempt reconnection or report
	// max-retries-exceeded.
	var writeAttemptErr error
	if s.writer == nil {
		writeAttemptErr = fmt.Errorf("audit: syslog writer not connected")
	} else if _, err := s.writer.WriteWithPriority(priority, data); err != nil {
		writeAttemptErr = err
	}

	if writeAttemptErr != nil {
		reconnected, writeErr := s.handleWriteFailure(data, priority, writeAttemptErr)
		s.mu.Unlock()
		if reconnected != nil && s.syslogMetrics != nil {
			s.syslogMetrics.RecordSyslogReconnect(s.address, *reconnected)
		}
		return writeErr
	}

	s.failures = 0
	s.mu.Unlock()
	return nil
}

// Close closes the syslog connection. Close is idempotent and safe
// for concurrent use.
func (s *Output) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh) // interrupt any in-progress backoff

	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			return fmt.Errorf("audit: syslog close: %w", err)
		}
	}
	return nil
}

// Name returns the human-readable identifier for this output.
func (s *Output) Name() string {
	return "syslog:" + s.address
}

// DestinationKey returns the syslog server address, enabling
// duplicate destination detection via [audit.DestinationKeyer].
func (s *Output) DestinationKey() string {
	return s.address
}

// connect establishes a connection to the syslog server. The default
// priority passed to srslog.Dial is facility|LOG_INFO, which is used
// by srslog internally for Write() calls. Per-event severity is
// applied via WriteWithPriority in writeWithPriority.
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

// handleWriteFailure attempts reconnection with bounded exponential
// backoff. Called with s.mu held; returns with s.mu still held.
// Releases the mutex during the backoff sleep so Close() is not blocked.
// The second return value is non-nil when a reconnection was attempted:
// *true for success, *false for failure. The caller uses this to invoke
// [Metrics.RecordSyslogReconnect] outside the mutex. The priority
// parameter ensures the retry uses the same facility+severity as the
// original write attempt.
// defaults where needed.
// to TLS 1.3 only when nil). InsecureSkipVerify is never set.
// This is an immutable lookup table populated at init time.
