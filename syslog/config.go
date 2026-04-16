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

import (
	"fmt"
	"os"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/srslog"
)

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

	// DefaultBufferSize is the default async buffer capacity for the
	// syslog output. Matches the default for all other async outputs.
	DefaultBufferSize = 10_000

	// MaxOutputBufferSize is the maximum allowed per-output async
	// buffer capacity.
	MaxOutputBufferSize = 100_000

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
	// to match the auditor-wide host value from [audit.WithHost].
	Hostname string

	// MaxRetries is the maximum number of consecutive reconnection
	// attempts before giving up. Zero defaults to
	// [DefaultMaxRetries] (10).
	MaxRetries int

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [audit.OutputMetrics.RecordDrop] is
	// called. Zero defaults to [DefaultBufferSize] (10,000). Values
	// above [MaxOutputBufferSize] (100,000) cause [New] to return an
	// error wrapping [audit.ErrConfigInvalid].
	BufferSize int
}

// String returns a human-readable representation of the config with
// TLS key paths redacted. This prevents credential path leakage
// when configs are accidentally logged via %v or %+v.
func (c Config) String() string {
	tlsMode := "none"
	if c.TLSCert != "" {
		tlsMode = "mtls"
	} else if c.TLSCA != "" {
		tlsMode = "tls"
	}
	return fmt.Sprintf("SyslogConfig{network=%s, address=%s, tls=%s, facility=%s}",
		c.Network, c.Address, tlsMode, c.Facility)
}

// GoString returns the same redacted representation as [Config.String].
// This prevents TLS key path leakage when configs are formatted via %#v.
func (c Config) GoString() string { return c.String() } //nolint:gocritic // hugeParam: value receiver required by fmt.GoStringer

// Format writes the redacted representation to the formatter.
// This prevents TLS key path leakage via %+v and all other format verbs.
func (c Config) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, c.String()) } //nolint:gocritic // hugeParam: value receiver required by fmt.Formatter

// Output writes serialised audit events to a syslog server over
// TCP, UDP, or TCP+TLS (including mTLS). Events are formatted as
// RFC 5424 structured syslog messages with the pre-serialised audit

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

	if cfg.BufferSize > MaxOutputBufferSize {
		return fmt.Errorf("%w: syslog buffer_size %d exceeds maximum %d", audit.ErrConfigInvalid, cfg.BufferSize, MaxOutputBufferSize)
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
