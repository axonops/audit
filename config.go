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

import (
	"fmt"
	"time"
)

// ValidationMode controls how [Auditor.AuditEvent] handles unknown fields
// (fields not listed in the event's Required or Optional lists).
type ValidationMode string

const (
	// ValidationStrict rejects unknown fields with an error; it is the
	// default when [Config.ValidationMode] is empty.
	ValidationStrict ValidationMode = "strict"

	// ValidationWarn logs a warning for unknown fields via [log/slog]
	// but accepts the event.
	ValidationWarn ValidationMode = "warn"

	// ValidationPermissive silently accepts unknown fields.
	ValidationPermissive ValidationMode = "permissive"

	// DefaultQueueSize is the default async intake queue capacity.
	DefaultQueueSize = 10_000

	// MaxQueueSize is the maximum allowed async intake queue capacity.
	// Values above this limit cause [New] to return an error
	// wrapping [ErrConfigInvalid].
	MaxQueueSize = 1_000_000

	// DefaultShutdownTimeout is the default graceful shutdown deadline.
	DefaultShutdownTimeout = 5 * time.Second

	// MaxShutdownTimeout is the maximum allowed graceful shutdown deadline.
	// Values above this limit cause [New] to return an error
	// wrapping [ErrConfigInvalid]. Setting ShutdownTimeout too low on a
	// high-throughput system causes events to be lost at shutdown.
	MaxShutdownTimeout = 60 * time.Second
)

// Config holds tuning parameters for the audit [Auditor]. The zero
// value is a valid configuration: buffer=10,000, shutdown=5s,
// validation=strict, omit_empty=false. Pass individual fields via
// [WithQueueSize], [WithShutdownTimeout], [WithValidationMode], or
// [WithOmitEmpty], or pass the whole struct via [WithConfig].
type Config struct {
	// ValidationMode controls how unknown fields are handled.
	// One of [ValidationStrict], [ValidationWarn], or
	// [ValidationPermissive]. Empty defaults to [ValidationStrict].
	ValidationMode ValidationMode

	// ShutdownTimeout is the maximum time [Auditor.Close] waits for
	// pending events to flush. Zero means [DefaultShutdownTimeout] (5s).
	// Values above [MaxShutdownTimeout] (60s) cause [New] to
	// return an error. Setting this too low on a high-throughput
	// system will cause events to be lost at shutdown.
	ShutdownTimeout time.Duration

	// version is the config schema version. Defaults to 1 via
	// [Config.applyDefaults]. Unexported because consumers should
	// never need to set it — there is only one version.
	version int

	// QueueSize is the async intake queue capacity. Zero means
	// [DefaultQueueSize] (10,000). Values above [MaxQueueSize]
	// (1,000,000) cause [New] to return an error.
	QueueSize int

	// OmitEmpty controls whether empty/nil/zero-value fields are
	// included in serialised output. When true, only non-zero fields
	// are serialised. When false (the zero value), all registered
	// fields are present. Consumers operating under compliance regimes
	// that require all registered fields SHOULD leave this as false.
	OmitEmpty bool
}

// applyDefaults fills zero-valued fields with their documented defaults.
func (c *Config) applyDefaults() {
	if c.version == 0 {
		c.version = 1
	}
	if c.QueueSize <= 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = DefaultShutdownTimeout
	}
	if c.ValidationMode == "" {
		c.ValidationMode = ValidationStrict
	}
}

// validateConfig applies defaults to zero-valued fields, then checks the
// config for correctness. It mutates c (via [Config.applyDefaults]) before
// validation. Returns an error wrapping [ErrConfigInvalid] on failure.
// Version checks are handled by [migrateConfig] which runs after this.
func validateConfig(c *Config) error {
	c.applyDefaults()

	if c.QueueSize > MaxQueueSize {
		return fmt.Errorf("%w: queue_size %d exceeds maximum %d",
			ErrConfigInvalid, c.QueueSize, MaxQueueSize)
	}

	if c.ShutdownTimeout > MaxShutdownTimeout {
		return fmt.Errorf("%w: shutdown_timeout %s exceeds maximum %s",
			ErrConfigInvalid, c.ShutdownTimeout, MaxShutdownTimeout)
	}

	switch c.ValidationMode {
	case ValidationStrict, ValidationWarn, ValidationPermissive:
		// valid
	default:
		return fmt.Errorf("%w: invalid validation mode %q, must be one of: strict, warn, permissive",
			ErrConfigInvalid, c.ValidationMode)
	}

	return nil
}
