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

// srslog (github.com/gravwell/srslog) is used for syslog transport.
// It is a maintained fork of github.com/RackSec/srslog which provides
// RFC 5424 formatting, TCP/UDP/TLS transport, and thread-safe writes.
// The library accepts *tls.Config so we control TLS version and certs.

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
	"github.com/gravwell/srslog"
)

// Compile-time assertion: Output satisfies audit.Output.
var _ audit.Output = (*Output)(nil)

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

	// syslogBaseBackoff is the initial backoff duration for reconnection.
	syslogBaseBackoff = 100 * time.Millisecond

	// syslogMaxBackoff is the maximum backoff duration for reconnection.
	syslogMaxBackoff = 30 * time.Second
)

// Config holds configuration for [Output].
type Config struct { //nolint:govet // fieldalignment: pointer field TLSPolicy extends scan region by 8 bytes; readability preferred
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
	priority      srslog.Priority
	failures      int // consecutive failure count
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

	// Hostname failure is non-fatal; an empty hostname is acceptable
	// in the RFC 5424 header (NILVALUE "-" per §6.2.4).
	// Note: both hostname and ProcID (set by srslog via os.Getpid())
	// are cached at construction time and not updated if the process
	// forks or the hostname changes during the process lifetime.
	hostname, _ := os.Hostname()

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
		priority:      priority | srslog.LOG_INFO,
		maxRetry:      maxRetry,
	}

	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("audit: syslog dial %s://%s: %w",
			cfg.Network, cfg.Address, err)
	}

	return s, nil
}

// Write sends a serialised audit event to the syslog server. On
// connection failure, Write attempts reconnection with bounded
// exponential backoff. Write returns [audit.ErrOutputClosed] if the
// output has been closed.
func (s *Output) Write(data []byte) error {
	s.mu.Lock()

	if s.closed {
		s.mu.Unlock()
		return audit.ErrOutputClosed
	}

	if _, err := s.writer.Write(data); err != nil {
		reconnected, writeErr := s.handleWriteFailure(data, err)
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

// connect establishes a connection to the syslog server.
func (s *Output) connect() error {
	var w *srslog.Writer
	var err error

	if s.tlsCfg != nil {
		w, err = srslog.DialWithTLSConfig(
			"tcp+tls", s.address, s.priority, s.appName, s.tlsCfg)
	} else {
		w, err = srslog.Dial(s.network, s.address, s.priority, s.appName)
	}
	if err != nil {
		return fmt.Errorf("audit: syslog connect %s://%s: %w", s.network, s.address, err)
	}

	w.SetFormatter(srslog.RFC5424Formatter)
	w.SetFramer(srslog.RFC5425MessageLengthFramer)
	w.SetHostname(s.hostname)
	s.writer = w
	return nil
}

// handleWriteFailure attempts reconnection with bounded exponential
// backoff. Called with s.mu held; returns with s.mu still held.
// Releases the mutex during the backoff sleep so Close() is not blocked.
// The second return value is non-nil when a reconnection was attempted:
// *true for success, *false for failure. The caller uses this to invoke
// [Metrics.RecordSyslogReconnect] outside the mutex.
func (s *Output) handleWriteFailure(data []byte, writeErr error) (*bool, error) {
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

	// Retry the write on the new connection.
	if _, err := s.writer.Write(data); err != nil {
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
		return fmt.Errorf("audit: syslog address must not be empty")
	}

	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	switch cfg.Network {
	case "tcp", "udp", "tcp+tls":
		// valid
	default:
		return fmt.Errorf("audit: syslog network %q must be tcp, udp, or tcp+tls", cfg.Network)
	}

	if cfg.AppName == "" {
		cfg.AppName = DefaultAppName
	}
	if cfg.Facility == "" {
		cfg.Facility = DefaultFacility
	}

	return validateSyslogTLSFiles(cfg)
}

// validateSyslogTLSFiles checks TLS cert/key pairing and file existence.
func validateSyslogTLSFiles(cfg *Config) error {
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("audit: syslog tls_cert and tls_key must both be set or both empty")
	}

	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			fi, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("audit: syslog tls file %q: %w", path, err)
			}
			if fi.IsDir() {
				return fmt.Errorf("audit: syslog tls file %q is a directory", path)
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
		return 0, fmt.Errorf("audit: unknown syslog facility %q", name)
	}
	return p, nil
}
