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
	// default when no [WithValidationMode] option is supplied.
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

// config holds tuning parameters for the audit [Auditor]. Internal
// pipeline struct populated by option functions ([WithQueueSize],
// [WithShutdownTimeout], [WithValidationMode], [WithOmitEmpty]).
// The zero value is a valid configuration: queue=10,000, shutdown=5s,
// validation=strict, omit_empty=false. Not part of the public API —
// consumers configure auditors exclusively via functional options.
// See docs/adr/0003-config-pattern.md (#579).
type config struct {
	// ValidationMode controls how unknown fields are handled.
	ValidationMode ValidationMode

	// ShutdownTimeout is the maximum time [Auditor.Close] waits for
	// pending events to flush.
	ShutdownTimeout time.Duration

	// QueueSize is the async intake queue capacity.
	QueueSize int

	// OmitEmpty controls whether empty/nil/zero-value fields are
	// included in serialised output.
	OmitEmpty bool
}

// applyDefaults fills zero-valued fields with their documented defaults.
func (c *config) applyDefaults() {
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
// config for correctness. It mutates c (via [config.applyDefaults]) before
// validation. Returns an error wrapping [ErrConfigInvalid] on failure.
func validateConfig(c *config) error {
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
