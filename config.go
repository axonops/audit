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

// ValidationMode controls how [Logger.Audit] handles unknown fields
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

	// DefaultBufferSize is the default async channel capacity.
	DefaultBufferSize = 10_000

	// MaxBufferSize is the maximum allowed async channel capacity.
	// Values above this limit cause [NewLogger] to return an error
	// wrapping [ErrConfigInvalid].
	MaxBufferSize = 1_000_000

	// DefaultDrainTimeout is the default graceful shutdown deadline.
	DefaultDrainTimeout = 5 * time.Second

	// MaxDrainTimeout is the maximum allowed graceful shutdown deadline.
	// Values above this limit cause [NewLogger] to return an error
	// wrapping [ErrConfigInvalid]. Setting DrainTimeout too low on a
	// high-throughput system causes events to be lost at shutdown.
	MaxDrainTimeout = 60 * time.Second
)

// ErrConfigInvalid is the sentinel error wrapped by configuration
// validation failures.
var ErrConfigInvalid = errors.New("audit: config validation failed")

// Config holds configuration for the audit [Logger].
type Config struct {
	// ValidationMode controls how unknown fields are handled.
	// One of [ValidationStrict], [ValidationWarn], or
	// [ValidationPermissive]. Empty defaults to [ValidationStrict].
	ValidationMode ValidationMode

	// DrainTimeout is the maximum time [Logger.Close] waits for
	// pending events to flush. Zero means [DefaultDrainTimeout] (5s).
	// Values above [MaxDrainTimeout] (60s) cause [NewLogger] to
	// return an error. Setting this too low on a high-throughput
	// system will cause events to be lost at shutdown.
	DrainTimeout time.Duration

	// Version is the config schema version. MUST be > 0; the zero
	// value causes [NewLogger] to return an error wrapping
	// [ErrConfigInvalid]. Set to 1 for all current consumers; this
	// field enables forward-compatible migrations when the config
	// schema changes in future library versions.
	Version int

	// BufferSize is the async channel capacity. Zero means
	// [DefaultBufferSize] (10,000). Values above [MaxBufferSize]
	// (1,000,000) cause [NewLogger] to return an error.
	BufferSize int

	// Enabled controls whether audit logging is active. When false
	// (the zero value), [NewLogger] returns a no-op logger that
	// discards all events.
	Enabled bool

	// OmitEmpty controls whether empty/nil/zero-value fields are
	// included in serialised output. When true, only non-zero fields
	// are serialised. When false (the zero value), all registered
	// fields are present. Consumers operating under compliance regimes
	// that require all registered fields SHOULD leave this as false.
	OmitEmpty bool
}

// OutputsConfig defines all output destinations for the logger. Primary
// outputs (Stdout, File) are single instances with default names.
// Additional named instances are configured via the Extra slice.
type OutputsConfig struct {
	// Stdout configures the primary stdout output. Ignored if nil.
	Stdout *StdoutConfig

	// File configures the primary file output. Ignored if nil.
	File *FileConfig

	// Extra defines additional named output instances. Each entry
	// creates a separate output with its own [EventRoute] and
	// formatter. Names MUST be unique across all outputs (including
	// the primary ones). Duplicate names cause [BuildOutputs] to
	// return an error.
	Extra []NamedOutputConfig
}

// NamedOutputConfig defines an additional named output instance. Use
// this to configure multiple outputs of the same type (e.g. two file
// outputs writing to different paths with different event routes).
type NamedOutputConfig struct {
	// Name is a unique human-readable identifier for this output,
	// used in metrics labels and log messages. REQUIRED; empty name
	// causes [BuildOutputs] to return an error.
	Name string

	// Type is the output type: "stdout" or "file". It MUST match
	// the populated config pointer below. Mismatched type/config
	// causes [BuildOutputs] to return an error.
	Type string

	// Route restricts which events are delivered to this output.
	// An empty route delivers all globally-enabled events.
	Route EventRoute

	// Stdout is the config for a stdout-type output. Populated when
	// Type is "stdout".
	Stdout *StdoutConfig

	// File is the config for a file-type output. Populated when
	// Type is "file".
	File *FileConfig
}

// BuildOutputs constructs [Output] instances and [Option] values from
// an [OutputsConfig]. The returned options should be passed to
// [NewLogger]. BuildOutputs validates output names for uniqueness and
// type/config consistency.
func BuildOutputs(cfg OutputsConfig) ([]Option, error) {
	var opts []Option
	names := make(map[string]bool)

	if cfg.Stdout != nil {
		out, err := NewStdoutOutput(*cfg.Stdout)
		if err != nil {
			return nil, fmt.Errorf("audit: stdout output: %w", err)
		}
		name := out.Name()
		names[name] = true
		opts = append(opts, WithNamedOutput(out, EventRoute{}, nil))
	}

	if cfg.File != nil {
		out, err := NewFileOutput(*cfg.File)
		if err != nil {
			return nil, fmt.Errorf("audit: file output: %w", err)
		}
		name := out.Name()
		names[name] = true
		opts = append(opts, WithNamedOutput(out, EventRoute{}, nil))
	}

	for i, nc := range cfg.Extra {
		if nc.Name == "" {
			return nil, fmt.Errorf("audit: Extra[%d]: name must not be empty", i)
		}
		if names[nc.Name] {
			return nil, fmt.Errorf("audit: duplicate output name %q", nc.Name)
		}
		names[nc.Name] = true

		out, err := buildNamedOutput(nc)
		if err != nil {
			return nil, fmt.Errorf("audit: output %q: %w", nc.Name, err)
		}
		opts = append(opts, WithNamedOutput(out, nc.Route, nil))
	}

	return opts, nil
}

// buildNamedOutput constructs an Output from a NamedOutputConfig.
func buildNamedOutput(nc NamedOutputConfig) (Output, error) {
	switch nc.Type {
	case "stdout":
		if nc.Stdout == nil {
			return nil, fmt.Errorf("type %q requires Stdout config", nc.Type)
		}
		return NewStdoutOutput(*nc.Stdout)
	case "file":
		if nc.File == nil {
			return nil, fmt.Errorf("type %q requires File config", nc.Type)
		}
		return newNamedFileOutput(nc.Name, *nc.File)
	default:
		return nil, fmt.Errorf("unknown output type %q", nc.Type)
	}
}

// namedOutput wraps an Output to override its Name.
type namedOutput struct {
	Output
	name string
}

func (n *namedOutput) Name() string { return n.name }

// newNamedFileOutput creates a FileOutput and wraps it with a custom name.
func newNamedFileOutput(name string, cfg FileConfig) (Output, error) {
	out, err := NewFileOutput(cfg)
	if err != nil {
		return nil, err
	}
	return &namedOutput{Output: out, name: name}, nil
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
