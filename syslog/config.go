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

	// DefaultBatchSize is the default number of events accumulated
	// before a flush is triggered. Matches [loki.DefaultBatchSize].
	DefaultBatchSize = 100

	// MaxBatchSize is the upper bound for BatchSize. Values above
	// this cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	MaxBatchSize = 10_000

	// DefaultFlushInterval is the default maximum time between
	// flushes. Matches [loki.DefaultFlushInterval].
	DefaultFlushInterval = 5 * time.Second

	// MinFlushInterval is the lower bound for FlushInterval. Values
	// below this cause [New] to return an error — a sub-millisecond
	// interval would busy-spin the writeLoop.
	MinFlushInterval = 1 * time.Millisecond

	// MaxFlushInterval is the upper bound for FlushInterval.
	MaxFlushInterval = 1 * time.Hour

	// DefaultMaxBatchBytes is the default maximum accumulated batch
	// size in bytes before a flush is triggered. 1 MiB matches
	// [loki.DefaultMaxBatchBytes]. Events exceeding this threshold
	// alone trigger an immediate flush (the event is sent in its own
	// batch; it is never dropped).
	DefaultMaxBatchBytes = 1 << 20 // 1 MiB

	// MinMaxBatchBytes is the lower bound for MaxBatchBytes.
	MinMaxBatchBytes = 1 << 10 // 1 KiB

	// MaxMaxBatchBytes is the upper bound for MaxBatchBytes. Capped
	// at 10 MiB to match [loki.MaxMaxBatchBytes]; real-world syslog
	// receivers (syslog-ng, rsyslog) typically reject single messages
	// over 64 KiB, but batches of many smaller messages can legitimately
	// reach several MiB.
	MaxMaxBatchBytes = 10 << 20 // 10 MiB

	// DefaultMaxEventBytes is the default per-event size cap at
	// [Output.Write] entry. Events with data longer than this are
	// rejected with [audit.ErrEventTooLarge] (#688) — a defence
	// against consumer-controlled memory pressure. 1 MiB matches
	// the cap used by loki and webhook.
	DefaultMaxEventBytes = 1 << 20 // 1 MiB

	// MinMaxEventBytes is the lower bound for MaxEventBytes.
	MinMaxEventBytes = 1 << 10 // 1 KiB

	// MaxMaxEventBytes is the upper bound for MaxEventBytes.
	MaxMaxEventBytes = 10 << 20 // 10 MiB

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

	// BatchSize is the number of events accumulated in the write
	// loop before triggering a flush to the syslog server. Zero
	// defaults to [DefaultBatchSize] (100). Values above
	// [MaxBatchSize] (10,000) cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid]. Set to 1 to disable
	// batching (every event flushes immediately — effectively
	// restoring pre-#599 per-event write behaviour).
	//
	// Matches the conventions established by [loki.Config.BatchSize]
	// and [github.com/axonops/audit/webhook.Config.BatchSize] so an
	// operator tuning multi-output deployments sees the same knob
	// across all batching outputs.
	BatchSize int

	// FlushInterval is the maximum time between flushes, regardless
	// of whether the batch has reached [Config.BatchSize]. Zero
	// defaults to [DefaultFlushInterval] (5 s). Values below
	// [MinFlushInterval] (1 ms) or above [MaxFlushInterval] (1 h)
	// cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	//
	// With the 5 s default, a single-event-per-5s audit trickle can
	// see up to 5 s of delivery latency. Consumers needing lower
	// latency should lower FlushInterval or set [Config.BatchSize]
	// to 1.
	FlushInterval time.Duration

	// MaxBatchBytes is the maximum accumulated payload size (sum of
	// event data lengths) before a flush is triggered, independent
	// of [Config.BatchSize]. Zero defaults to [DefaultMaxBatchBytes]
	// (1 MiB). Values below [MinMaxBatchBytes] (1 KiB) or above
	// [MaxMaxBatchBytes] (10 MiB) cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	//
	// A single event exceeding MaxBatchBytes is flushed alone — it is
	// never dropped. Events are never split across frames; RFC 5425
	// octet-counting framing is preserved per message.
	MaxBatchBytes int

	// MaxEventBytes is the maximum byte length accepted by
	// [Output.Write] for a single event. Events exceeding this cap
	// are rejected with [audit.ErrEventTooLarge] wrapping
	// [audit.ErrValidation] and [audit.OutputMetrics.RecordDrop] is
	// called. Zero defaults to [DefaultMaxEventBytes] (1 MiB).
	// Values below [MinMaxEventBytes] (1 KiB) or above
	// [MaxMaxEventBytes] (10 MiB) cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	//
	// Introduced by #688 as a defence against consumer-controlled
	// memory pressure: a single oversized event in a batching path
	// can be held in the async channel, the batch slice, and the
	// retry buffer simultaneously. A default 10 000-slot buffer
	// carrying 10 MiB events could pin ~100 GiB before backpressure
	// triggers.
	MaxEventBytes int
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

// validateSyslogConfig is a top-level linear validator: each if /
// switch maps 1-1 to a documented Config field constraint. Extracting
// helpers per group (network, facility, retries, buffer) would hide
// what is already an easy-to-read sequence of guard clauses, so the
// cyclop threshold is relaxed here.
//
//nolint:cyclop // linear guard sequence; see comment above.
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

	if err := validateSyslogBatchingConfig(cfg); err != nil {
		return err
	}

	if err := validateSyslogHostname(cfg.Hostname); err != nil {
		return err
	}

	return validateSyslogTLSFiles(cfg)
}

// validateSyslogBatchingConfig normalises zero values to defaults and
// rejects out-of-range batching knobs (#599). Mutates cfg in place
// so constructors read the resolved values.
func validateSyslogBatchingConfig(cfg *Config) error {
	if err := validateBatchSize(cfg); err != nil {
		return err
	}
	if err := validateFlushInterval(cfg); err != nil {
		return err
	}
	if err := validateMaxBatchBytes(cfg); err != nil {
		return err
	}
	return validateMaxEventBytes(cfg)
}

func validateMaxEventBytes(cfg *Config) error {
	if cfg.MaxEventBytes < 0 {
		return fmt.Errorf("%w: syslog max_event_bytes %d must be >= 0", audit.ErrConfigInvalid, cfg.MaxEventBytes)
	}
	if cfg.MaxEventBytes == 0 {
		cfg.MaxEventBytes = DefaultMaxEventBytes
	}
	if cfg.MaxEventBytes < MinMaxEventBytes {
		return fmt.Errorf("%w: syslog max_event_bytes %d below minimum %d", audit.ErrConfigInvalid, cfg.MaxEventBytes, MinMaxEventBytes)
	}
	if cfg.MaxEventBytes > MaxMaxEventBytes {
		return fmt.Errorf("%w: syslog max_event_bytes %d exceeds maximum %d", audit.ErrConfigInvalid, cfg.MaxEventBytes, MaxMaxEventBytes)
	}
	return nil
}

func validateBatchSize(cfg *Config) error {
	if cfg.BatchSize < 0 {
		return fmt.Errorf("%w: syslog batch_size %d must be >= 0", audit.ErrConfigInvalid, cfg.BatchSize)
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.BatchSize > MaxBatchSize {
		return fmt.Errorf("%w: syslog batch_size %d exceeds maximum %d", audit.ErrConfigInvalid, cfg.BatchSize, MaxBatchSize)
	}
	return nil
}

func validateFlushInterval(cfg *Config) error {
	if cfg.FlushInterval < 0 {
		return fmt.Errorf("%w: syslog flush_interval %s must be >= 0", audit.ErrConfigInvalid, cfg.FlushInterval)
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.FlushInterval < MinFlushInterval {
		return fmt.Errorf("%w: syslog flush_interval %s below minimum %s", audit.ErrConfigInvalid, cfg.FlushInterval, MinFlushInterval)
	}
	if cfg.FlushInterval > MaxFlushInterval {
		return fmt.Errorf("%w: syslog flush_interval %s exceeds maximum %s", audit.ErrConfigInvalid, cfg.FlushInterval, MaxFlushInterval)
	}
	return nil
}

func validateMaxBatchBytes(cfg *Config) error {
	if cfg.MaxBatchBytes < 0 {
		return fmt.Errorf("%w: syslog max_batch_bytes %d must be >= 0", audit.ErrConfigInvalid, cfg.MaxBatchBytes)
	}
	if cfg.MaxBatchBytes == 0 {
		cfg.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if cfg.MaxBatchBytes < MinMaxBatchBytes {
		return fmt.Errorf("%w: syslog max_batch_bytes %d below minimum %d", audit.ErrConfigInvalid, cfg.MaxBatchBytes, MinMaxBatchBytes)
	}
	if cfg.MaxBatchBytes > MaxMaxBatchBytes {
		return fmt.Errorf("%w: syslog max_batch_bytes %d exceeds maximum %d", audit.ErrConfigInvalid, cfg.MaxBatchBytes, MaxMaxBatchBytes)
	}
	return nil
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
