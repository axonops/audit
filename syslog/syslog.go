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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	audit "github.com/axonops/go-audit"
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

// mapSeverity converts an audit event severity (0-10) to an srslog
// severity constant. Out-of-range values fall back to LOG_INFO.
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

// Default values for [Config] fields.
const (
	// DefaultAppName is the default application name in the
	// syslog header when [Config.AppName] is empty.
	DefaultAppName = "audit"

	// DefaultFacility is the default syslog facility when
	// [Config.Facility] is empty.
	DefaultFacility = "local0"

	// DefaultMaxRetries is the default number of reconnection
	// attempts before giving up.
	DefaultMaxRetries = 10

	// MaxMaxRetries is the upper bound for MaxRetries. Values above
	// this are rejected to prevent unbounded retry loops.
	MaxMaxRetries = 20

	// syslogBaseBackoff is the initial backoff duration for reconnection.
	syslogBaseBackoff = 100 * time.Millisecond

	// syslogMaxBackoff is the maximum backoff duration for reconnection.
	syslogMaxBackoff = 30 * time.Second
)

// Config holds configuration for [Output].
type Config struct {
	// Network is the transport protocol: "tcp", "udp", or "tcp+tls".
	// Empty defaults to "tcp". Note: UDP syslog may silently truncate
	// or drop messages larger than ~2048 bytes (RFC 5424 §6.1).
	// Use TCP or TCP+TLS for reliable delivery of large audit events.
	Network string

	// Address is the syslog server address in host:port format.
	// REQUIRED; an empty address causes [New] to return
	// an error.
	Address string

	// AppName is the application name in the syslog header.
	// Empty defaults to [DefaultAppName] ("audit").
	AppName string

	// Facility is the syslog facility name. Supported values:
	// kern, user, mail, daemon, auth, syslog, lpr, news, uucp,
	// cron, authpriv, ftp, local0 through local7.
	// Empty defaults to [DefaultFacility] ("local0").
	// Unknown values cause [New] to return an error.
	Facility string

	// TLSCert is the path to the client certificate for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSCert string

	// TLSKey is the path to the client private key for mTLS.
	// Both TLSCert and TLSKey must be set for client authentication.
	TLSKey string

	// TLSCA is the path to the CA certificate for server verification.
	// When set, the server's certificate is verified against this CA.
	TLSCA string

	// TLSPolicy controls TLS version and cipher suite policy. When nil,
	// the default policy (TLS 1.3 only) is used. See [audit.TLSPolicy]
	// for details on enabling TLS 1.2 fallback.
	TLSPolicy *audit.TLSPolicy

	// Hostname overrides the hostname in the syslog RFC 5424 header.
	// When empty, [os.Hostname] is used at construction time. Set this
	// to match the logger-wide host value from [audit.WithHost].
	Hostname string

	// MaxRetries is the maximum number of consecutive reconnection
	// attempts before giving up. Zero defaults to
	// [DefaultMaxRetries] (10).
	MaxRetries int
}

// Output writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit
// payload (JSON or CEF) as the message body. The payload is placed in
// the MSG portion of the RFC 5424 message, not in structured data
// elements, so no SD escaping is required.
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
func (s *Output) handleWriteFailure(data []byte, priority srslog.Priority, writeErr error) (*bool, error) {
	s.failures++

	if s.failures > s.maxRetry {
		slog.Error("audit: syslog max retries exceeded",
			"address", s.address,
			"failures", s.failures,
			"last_error", writeErr)
		return nil, fmt.Errorf("audit: syslog write after %d failures: %w",
			s.failures, writeErr)
	}

	// Close the old writer before reconnecting.
	if s.writer != nil {
		_ = s.writer.Close()
		s.writer = nil
	}

	backoff := backoffDuration(s.failures)
	slog.Warn("audit: syslog reconnecting",
		"address", s.address,
		"attempt", s.failures,
		"backoff", backoff)

	// Release the mutex during backoff so Close() can proceed.
	s.mu.Unlock()
	select {
	case <-time.After(backoff):
	case <-s.closeCh:
		s.mu.Lock()
		return nil, fmt.Errorf("audit: syslog closed during reconnect: %w", writeErr)
	}
	s.mu.Lock()

	// Check if we were closed while sleeping.
	if s.closed {
		return nil, audit.ErrOutputClosed
	}

	if err := s.connect(); err != nil {
		slog.Error("audit: syslog reconnect failed",
			"address", s.address,
			"attempt", s.failures,
			"error", err)
		reconnected := false
		return &reconnected, fmt.Errorf("audit: syslog reconnect: %w", err)
	}

	slog.Info("audit: syslog reconnected", "address", s.address)
	reconnected := true

	// Retry the write on the new connection with the original priority.
	if _, err := s.writer.WriteWithPriority(priority, data); err != nil {
		return &reconnected, fmt.Errorf("audit: syslog write after reconnect: %w", err)
	}

	s.failures = 0
	return &reconnected, nil
}

// backoffDuration returns the backoff duration for the given attempt
// number using bounded exponential backoff with jitter
// (100ms * 2^attempt * [0.5, 1.0], capped at 30s). Jitter prevents
// thundering herd when multiple clients reconnect simultaneously.
func backoffDuration(attempt int) time.Duration {
	exp := math.Min(float64(attempt-1), 20) // clamp exponent to avoid overflow
	d := syslogBaseBackoff * time.Duration(math.Pow(2, exp))
	if d > syslogMaxBackoff {
		d = syslogMaxBackoff
	}
	// Add jitter: multiply by [0.5, 1.0) using crypto/rand.
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0 // [0.5, 1.0)
		d = time.Duration(float64(d) * jitter)
	}
	return d
}

// validateSyslogConfig checks the config for correctness, applying
// defaults where needed.
func validateSyslogConfig(cfg *Config) error {
	if cfg.Address == "" {
		return fmt.Errorf("%w: syslog address must not be empty", audit.ErrConfigInvalid)
	}

	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	switch cfg.Network {
	case "tcp", "udp", "tcp+tls":
		// valid
	default:
		return fmt.Errorf("%w: syslog network %q must be tcp, udp, or tcp+tls", audit.ErrConfigInvalid, cfg.Network)
	}

	if cfg.AppName == "" {
		cfg.AppName = DefaultAppName
	}
	if cfg.Facility == "" {
		cfg.Facility = DefaultFacility
	}

	if cfg.MaxRetries > MaxMaxRetries {
		return fmt.Errorf("%w: syslog max_retries %d exceeds maximum %d", audit.ErrConfigInvalid, cfg.MaxRetries, MaxMaxRetries)
	}

	if err := validateSyslogHostname(cfg.Hostname); err != nil {
		return err
	}

	return validateSyslogTLSFiles(cfg)
}

// validateSyslogHostname checks that the hostname conforms to RFC 5424
// PRINTUSASCII (bytes 33-126) and does not exceed 255 bytes.
func validateSyslogHostname(hostname string) error {
	if hostname == "" {
		return nil // empty is acceptable (NILVALUE "-")
	}
	if len(hostname) > 255 {
		return fmt.Errorf("%w: syslog hostname exceeds RFC 5424 maximum of 255 bytes", audit.ErrConfigInvalid)
	}
	for i := 0; i < len(hostname); i++ {
		b := hostname[i]
		if b < 33 || b > 126 {
			return fmt.Errorf("%w: syslog hostname contains invalid byte 0x%02x at offset %d", audit.ErrConfigInvalid, b, i)
		}
	}
	return nil
}

// validateSyslogTLSFiles checks TLS cert/key pairing and file existence.
func validateSyslogTLSFiles(cfg *Config) error {
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("%w: syslog tls_cert and tls_key must both be set or both empty", audit.ErrConfigInvalid)
	}

	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("%w: syslog tls file %q: %w", audit.ErrConfigInvalid, path, err)
			}
			if fi.IsDir() {
				return fmt.Errorf("%w: syslog tls file %q is a directory", audit.ErrConfigInvalid, path)
			}
		}
	}

	return nil
}

// buildSyslogTLSConfig creates a TLS configuration for syslog
// connections using the [audit.TLSPolicy] from the config (defaulting
// to TLS 1.3 only when nil). InsecureSkipVerify is never set.
func buildSyslogTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg, warnings := cfg.TLSPolicy.Apply(nil)
	for _, w := range warnings {
		slog.Warn(w, "output", "syslog", "address", cfg.Address)
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("audit: syslog tls: parse ca certificate: invalid pem block")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// syslogFacilities maps facility name strings to srslog.Priority values.
// This is an immutable lookup table populated at init time.
var syslogFacilities = map[string]srslog.Priority{
	"kern":     srslog.LOG_KERN,
	"user":     srslog.LOG_USER,
	"mail":     srslog.LOG_MAIL,
	"daemon":   srslog.LOG_DAEMON,
	"auth":     srslog.LOG_AUTH,
	"syslog":   srslog.LOG_SYSLOG,
	"lpr":      srslog.LOG_LPR,
	"news":     srslog.LOG_NEWS,
	"uucp":     srslog.LOG_UUCP,
	"cron":     srslog.LOG_CRON,
	"authpriv": srslog.LOG_AUTHPRIV,
	"ftp":      srslog.LOG_FTP,
	"local0":   srslog.LOG_LOCAL0,
	"local1":   srslog.LOG_LOCAL1,
	"local2":   srslog.LOG_LOCAL2,
	"local3":   srslog.LOG_LOCAL3,
	"local4":   srslog.LOG_LOCAL4,
	"local5":   srslog.LOG_LOCAL5,
	"local6":   srslog.LOG_LOCAL6,
	"local7":   srslog.LOG_LOCAL7,
}

// parseFacility converts a facility name string to a srslog.Priority.
// Unknown facility names return an error.
func parseFacility(name string) (srslog.Priority, error) {
	p, ok := syslogFacilities[name]
	if !ok {
		return 0, fmt.Errorf("%w: unknown syslog facility %q", audit.ErrConfigInvalid, name)
	}
	return p, nil
}
