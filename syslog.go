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

// srslog (github.com/gravwell/srslog) is used for syslog transport.
// It is a maintained fork of github.com/RackSec/srslog which provides
// RFC 5424 formatting, TCP/UDP/TLS transport, and thread-safe writes.
// The library accepts *tls.Config so we control TLS version and certs.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/gravwell/srslog"
)

// Default values for [SyslogConfig] fields.
const (
	// DefaultSyslogAppName is the default application name in the
	// syslog header when [SyslogConfig.AppName] is empty.
	DefaultSyslogAppName = "audit"

	// DefaultSyslogFacility is the default syslog facility when
	// [SyslogConfig.Facility] is empty.
	DefaultSyslogFacility = "local0"

	// DefaultSyslogMaxRetries is the default number of reconnection
	// attempts before giving up.
	DefaultSyslogMaxRetries = 10

	// syslogBaseBackoff is the initial backoff duration for reconnection.
	syslogBaseBackoff = 100 * time.Millisecond

	// syslogMaxBackoff is the maximum backoff duration for reconnection.
	syslogMaxBackoff = 30 * time.Second
)

// SyslogConfig holds configuration for [SyslogOutput].
type SyslogConfig struct {
	// Network is the transport protocol: "tcp", "udp", or "tcp+tls".
	// Empty defaults to "tcp".
	Network string

	// Address is the syslog server address in host:port format.
	// REQUIRED; an empty address causes [NewSyslogOutput] to return
	// an error.
	Address string

	// AppName is the application name in the syslog header.
	// Empty defaults to [DefaultSyslogAppName] ("audit").
	AppName string

	// Facility is the syslog facility name. Supported values:
	// kern, user, mail, daemon, auth, syslog, lpr, news, uucp,
	// cron, authpriv, ftp, local0 through local7.
	// Empty defaults to [DefaultSyslogFacility] ("local0").
	// Unknown values cause [NewSyslogOutput] to return an error.
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

	// MaxRetries is the maximum number of consecutive reconnection
	// attempts before giving up. Zero defaults to
	// [DefaultSyslogMaxRetries] (10).
	MaxRetries int
}

// SyslogOutput writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit
// payload (JSON or CEF) as the message body.
//
// On connection failure, [SyslogOutput] attempts bounded exponential
// backoff reconnection (100ms to 30s, up to [SyslogConfig.MaxRetries]
// attempts). Reconnection happens synchronously within [Write] since
// the [Output] interface guarantees single-caller access from the
// drain goroutine.
//
// SyslogOutput is safe for concurrent use.
type SyslogOutput struct {
	writer   *srslog.Writer
	tlsCfg   *tls.Config // cached for reconnection; nil for non-TLS
	address  string
	network  string
	appName  string
	hostname string
	mu       sync.Mutex
	priority srslog.Priority
	failures int // consecutive failure count
	maxRetry int
	closed   bool
}

// NewSyslogOutput creates a new [SyslogOutput] from the given config.
// It validates the config and establishes the initial connection.
func NewSyslogOutput(cfg SyslogConfig) (*SyslogOutput, error) {
	if err := validateSyslogConfig(&cfg); err != nil {
		return nil, err
	}

	priority, err := parseFacility(cfg.Facility)
	if err != nil {
		return nil, fmt.Errorf("audit: syslog facility %q: %w", cfg.Facility, err)
	}

	hostname, _ := os.Hostname()

	var tlsCfg *tls.Config
	if cfg.Network == "tcp+tls" {
		tlsCfg, err = buildSyslogTLSConfig(&cfg)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls config: %w", err)
		}
	}

	maxRetry := cfg.MaxRetries
	if maxRetry <= 0 {
		maxRetry = DefaultSyslogMaxRetries
	}

	s := &SyslogOutput{
		tlsCfg:   tlsCfg,
		address:  cfg.Address,
		network:  cfg.Network,
		appName:  cfg.AppName,
		hostname: hostname,
		priority: priority | srslog.LOG_INFO,
		maxRetry: maxRetry,
	}

	if err := s.connect(); err != nil {
		return nil, fmt.Errorf("audit: syslog dial %s://%s: %w",
			cfg.Network, cfg.Address, err)
	}

	return s, nil
}

// Write sends a serialised audit event to the syslog server. On
// connection failure, Write attempts reconnection with bounded
// exponential backoff. Write returns [ErrOutputClosed] if the output
// has been closed.
func (s *SyslogOutput) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrOutputClosed
	}

	if _, err := s.writer.Write(data); err != nil {
		return s.handleWriteFailure(data, err)
	}

	s.failures = 0
	return nil
}

// Close closes the syslog connection. Close is idempotent and safe
// for concurrent use.
func (s *SyslogOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			return fmt.Errorf("audit: syslog close: %w", err)
		}
	}
	return nil
}

// Name returns the human-readable identifier for this output.
func (s *SyslogOutput) Name() string {
	return "syslog:" + s.address
}

// connect establishes a connection to the syslog server.
func (s *SyslogOutput) connect() error {
	var w *srslog.Writer
	var err error

	if s.tlsCfg != nil {
		w, err = srslog.DialWithTLSConfig(
			"tcp+tls", s.address, s.priority, s.appName, s.tlsCfg)
	} else {
		w, err = srslog.Dial(s.network, s.address, s.priority, s.appName)
	}
	if err != nil {
		return err
	}

	w.SetFormatter(srslog.RFC5424Formatter)
	w.SetFramer(srslog.RFC5425MessageLengthFramer)
	w.SetHostname(s.hostname)
	s.writer = w
	return nil
}

// handleWriteFailure attempts reconnection with bounded exponential
// backoff. Called with s.mu held.
func (s *SyslogOutput) handleWriteFailure(data []byte, writeErr error) error {
	s.failures++

	if s.failures > s.maxRetry {
		slog.Error("audit: syslog max retries exceeded",
			"address", s.address,
			"failures", s.failures,
			"last_error", writeErr)
		return fmt.Errorf("audit: syslog write after %d failures: %w",
			s.failures, writeErr)
	}

	// Close the old writer and attempt reconnection.
	if s.writer != nil {
		_ = s.writer.Close()
		s.writer = nil
	}

	backoff := BackoffDuration(s.failures)
	slog.Warn("audit: syslog reconnecting",
		"address", s.address,
		"attempt", s.failures,
		"backoff", backoff)

	time.Sleep(backoff)

	if err := s.connect(); err != nil {
		slog.Error("audit: syslog reconnect failed",
			"address", s.address,
			"attempt", s.failures,
			"error", err)
		return fmt.Errorf("audit: syslog reconnect: %w", err)
	}

	slog.Info("audit: syslog reconnected", "address", s.address)

	// Retry the write on the new connection.
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("audit: syslog write after reconnect: %w", err)
	}

	s.failures = 0
	return nil
}

// BackoffDuration returns the backoff duration for the given attempt
// number using bounded exponential backoff (100ms * 2^attempt, capped
// at 30s).
func BackoffDuration(attempt int) time.Duration {
	d := syslogBaseBackoff * time.Duration(math.Pow(2, float64(attempt-1)))
	if d > syslogMaxBackoff {
		d = syslogMaxBackoff
	}
	return d
}

// validateSyslogConfig checks the config for correctness, applying
// defaults where needed.
func validateSyslogConfig(cfg *SyslogConfig) error {
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
		cfg.AppName = DefaultSyslogAppName
	}
	if cfg.Facility == "" {
		cfg.Facility = DefaultSyslogFacility
	}

	// TLS cert/key pairing.
	if (cfg.TLSCert != "") != (cfg.TLSKey != "") {
		return fmt.Errorf("audit: syslog tls_cert and tls_key must both be set or both empty")
	}

	// File existence checks for TLS.
	for _, path := range []string{cfg.TLSCert, cfg.TLSKey, cfg.TLSCA} {
		if path != "" {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("audit: syslog tls file %q: %w", path, err)
			}
		}
	}

	return nil
}

// buildSyslogTLSConfig creates a TLS configuration for syslog
// connections. TLS 1.3 is the minimum supported version.
// InsecureSkipVerify is always false.
func buildSyslogTLSConfig(cfg *SyslogConfig) (*tls.Config, error) {
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

// parseFacility converts a facility name string to a srslog.Priority.
// Unknown facility names return an error.
func parseFacility(name string) (srslog.Priority, error) {
	facilities := map[string]srslog.Priority{
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

	p, ok := facilities[name]
	if !ok {
		return 0, fmt.Errorf("audit: unknown syslog facility %q", name)
	}
	return p, nil
}
