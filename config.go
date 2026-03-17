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
	"errors"
	"fmt"
	"time"
)

const (
	// ValidationStrict rejects unknown fields with an error.
	// This is the default validation mode.
	ValidationStrict = "strict"

	// ValidationWarn logs a warning for unknown fields but accepts them.
	ValidationWarn = "warn"

	// ValidationPermissive silently accepts unknown fields.
	ValidationPermissive = "permissive"

	// DefaultBufferSize is the default async channel capacity.
	DefaultBufferSize = 10_000

	// MaxBufferSize is the maximum allowed async channel capacity.
	// This prevents accidental memory exhaustion from misconfiguration.
	MaxBufferSize = 1_000_000

	// DefaultDrainTimeout is the default graceful shutdown deadline.
	DefaultDrainTimeout = 5 * time.Second

	// MaxDrainTimeout is the maximum allowed graceful shutdown deadline.
	MaxDrainTimeout = 60 * time.Second
)

// ErrConfigInvalid is the sentinel error wrapped by configuration
// validation failures.
var ErrConfigInvalid = errors.New("audit: config validation failed")

// Config holds configuration for the audit [Logger].
type Config struct {
	// Version is the config schema version. REQUIRED. MUST be > 0;
	// the zero value causes [NewLogger] to return an error.
	Version int

	// Enabled controls whether audit logging is active. When false
	// (the zero value), [NewLogger] returns a no-op logger that
	// discards all events.
	Enabled bool

	// BufferSize is the async channel capacity. Zero means
	// [DefaultBufferSize] (10,000). Values above [MaxBufferSize]
	// (1,000,000) cause [NewLogger] to return an error.
	BufferSize int

	// DrainTimeout is the maximum time [Logger.Close] waits for
	// pending events to flush. Zero means [DefaultDrainTimeout] (5s).
	// Values above [MaxDrainTimeout] (60s) cause [NewLogger] to
	// return an error. Setting this too low on a high-throughput
	// system will cause events to be lost at shutdown.
	DrainTimeout time.Duration

	// OmitEmpty controls whether empty/nil/zero-value fields are
	// included in serialised output. When true, only non-zero fields
	// are serialised. When false, all registered fields are present
	// (some compliance regimes require this).
	OmitEmpty bool

	// ValidationMode controls how unknown fields are handled.
	// One of [ValidationStrict], [ValidationWarn], or
	// [ValidationPermissive]. Empty defaults to [ValidationStrict].
	ValidationMode string
}

// applyDefaults fills zero-valued fields with their documented defaults.
func (c *Config) applyDefaults() {
	if c.BufferSize <= 0 {
		c.BufferSize = DefaultBufferSize
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = DefaultDrainTimeout
	}
	if c.ValidationMode == "" {
		c.ValidationMode = ValidationStrict
	}
}

// validateConfig checks the config for correctness. It returns an error
// wrapping [ErrConfigInvalid] on failure. Version checks are handled by
// [migrateConfig] which runs before this function.
func validateConfig(c *Config) error {
	c.applyDefaults()

	if c.BufferSize > MaxBufferSize {
		return fmt.Errorf("%w: buffer_size %d exceeds maximum %d",
			ErrConfigInvalid, c.BufferSize, MaxBufferSize)
	}

	if c.DrainTimeout > MaxDrainTimeout {
		return fmt.Errorf("%w: drain_timeout %s exceeds maximum %s",
			ErrConfigInvalid, c.DrainTimeout, MaxDrainTimeout)
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
