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

package file

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file/internal/rotate"
)

// Compile-time assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
)

const (
	// MaxSizeMB is the maximum allowed value for [Config.MaxSizeMB].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxSizeMB = 10_240 // 10 GB

	// MaxBackups is the maximum allowed value for [Config.MaxBackups].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxBackups = 100

	// MaxAgeDays is the maximum allowed value for [Config.MaxAgeDays].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxAgeDays = 365
)

// Metrics is an optional interface for file-output-specific
// instrumentation. Pass an implementation to [New] to
// collect rotation telemetry. Pass nil to disable.
type Metrics interface {
	// RecordFileRotation records that the file output rotated its
	// active log file. The path argument is the absolute filesystem
	// path of the file that was rotated. Implementations SHOULD NOT
	// use this value as an unbounded metric label — it may expose
	// infrastructure topology and cause cardinality explosion.
	RecordFileRotation(path string)
}

// Config holds configuration for [Output].
//
//nolint:govet // field order: logical grouping (required, then optional, then pointer)
type Config struct {
	// Path is the filesystem path for the audit log file. REQUIRED.
	// Relative paths are resolved to absolute at construction time.
	// The parent directory must exist when [New] is called.
	Path string

	// Permissions is the octal file mode string (e.g. "0600") applied
	// to created files. Empty defaults to "0600" (owner read/write).
	// Values granting group or world write access produce a slog
	// warning. Values above 0o777 cause [New] to return an error;
	// this error does not wrap [audit.ErrConfigInvalid].
	Permissions string

	// MaxSizeMB is the maximum size in megabytes of a single log file
	// before rotation. Zero defaults to 100. Values above [MaxSizeMB]
	// (10,240 = 10 GB) cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	MaxSizeMB int

	// MaxBackups is the maximum number of rotated backup files to
	// retain. Zero defaults to 5. Values above [MaxBackups] (100)
	// cause [New] to return an error wrapping [audit.ErrConfigInvalid].
	MaxBackups int

	// MaxAgeDays is the maximum age in days of rotated backup files
	// before deletion. Zero defaults to 30. Values above [MaxAgeDays]
	// (365) cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	MaxAgeDays int

	// Compress enables gzip compression of rotated backup files.
	// When nil, defaults to true.
	Compress *bool
}

// Output writes serialised audit events to a file with automatic
// size-based rotation. It supports backup retention, age-based cleanup,
// and optional gzip compression.
//
// Output is safe for concurrent use, including concurrent calls
// to [Output.Write] and [Output.Close].
type Output struct {
	writer *rotate.Writer
	path   string
	mu     sync.RWMutex
	closed bool
}

// resolvePath normalises the path to an absolute form, resolving
// symlinks in the parent directory when possible. Falls back to
// filepath.Abs if symlink resolution fails (e.g. parent doesn't exist).
func resolvePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err == nil {
		return filepath.Join(resolved, filepath.Base(path)), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("audit: file output path: %w", err)
	}
	return abs, nil
}

// New creates a new [Output] from the given config.
// It validates the path, permissions, and parent directory existence.
// The fileMetrics parameter is optional (may be nil).
//
// Unlike other output constructors (syslog, webhook, loki) which take
// *Config, New takes Config by value. This is intentional: file Config
// has no pointer fields, so the value copy prevents caller mutation
// without requiring an explicit defensive copy inside New.
func New(cfg Config, fileMetrics Metrics) (*Output, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: file output path must not be empty")
	}
	var err error
	cfg.Path, err = resolvePath(cfg.Path)
	if err != nil {
		return nil, err
	}

	// Check parent directory exists early to provide a clear "audit:" error
	// message. rotate.New performs the same check but with a "rotate:" prefix.
	parentDir := filepath.Dir(cfg.Path)
	if _, statErr := os.Lstat(parentDir); statErr != nil {
		return nil, fmt.Errorf("audit: file output parent directory %q: %w", parentDir, statErr)
	}

	perm, err := parsePermissions(cfg.Permissions)
	if err != nil {
		return nil, fmt.Errorf("audit: file output permissions %q: %w", cfg.Permissions, err)
	}

	// Warn if permissions grant group or world access to audit data.
	if perm&0o077 != 0 {
		slog.Warn("audit: file output permissions grant group/world access",
			"path", cfg.Path,
			"permissions", fmt.Sprintf("%04o", perm))
	}

	applyFileDefaults(&cfg)
	if validErr := validateFileLimits(&cfg); validErr != nil {
		return nil, validErr
	}

	compress := true
	if cfg.Compress != nil {
		compress = *cfg.Compress
	}

	logPath := cfg.Path // capture for closure
	rotCfg := rotate.Config{
		MaxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
		MaxAge:     time.Duration(cfg.MaxAgeDays) * 24 * time.Hour,
		Mode:       perm,
		MaxBackups: cfg.MaxBackups,
		Compress:   compress,
		OnError: func(err error) {
			slog.Warn("audit: file output background error",
				"path", logPath, "error", err)
		},
	}
	if fileMetrics != nil {
		rotCfg.OnRotate = func(path string) {
			fileMetrics.RecordFileRotation(path)
		}
	}
	rw, err := rotate.New(cfg.Path, rotCfg)
	if err != nil {
		return nil, fmt.Errorf("audit: file output: %w", err)
	}

	return &Output{writer: rw, path: cfg.Path}, nil
}

// Write sends a serialised audit event to the file. Write returns
// [audit.ErrOutputClosed] if the output has been closed. Write is safe for
// concurrent use.
func (f *Output) Write(data []byte) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return audit.ErrOutputClosed
	}
	if _, err := f.writer.Write(data); err != nil {
		return fmt.Errorf("audit: file output write: %w", err)
	}
	return nil
}

// Close closes the underlying file writer and marks the output as
// closed. Close is idempotent and safe for concurrent use with
// [Output.Write].
func (f *Output) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if err := f.writer.Close(); err != nil {
		return fmt.Errorf("audit: file output close: %w", err)
	}
	return nil
}

// Name returns the human-readable identifier for this output.
func (f *Output) Name() string {
	return "file:" + f.path
}

// DestinationKey returns the absolute filesystem path,
// enabling duplicate destination detection via [audit.DestinationKeyer].
func (f *Output) DestinationKey() string {
	return f.path
}

// parsePermissions parses an octal permission string. An empty string
// defaults to 0600.
func parsePermissions(s string) (os.FileMode, error) {
	if s == "" {
		return 0o600, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal: %w", err)
	}
	mode := os.FileMode(v)
	if mode > 0o777 {
		return 0, fmt.Errorf("value %04o exceeds maximum 0777", mode)
	}
	return mode, nil
}

// applyFileDefaults fills zero-valued rotation fields with defaults.
func applyFileDefaults(cfg *Config) {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}
}

// validateFileLimits checks that rotation fields do not exceed their
// upper bounds.
func validateFileLimits(cfg *Config) error {
	if cfg.MaxSizeMB > MaxSizeMB {
		return fmt.Errorf("%w: max_size_mb %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxSizeMB, MaxSizeMB)
	}
	if cfg.MaxBackups > MaxBackups {
		return fmt.Errorf("%w: max_backups %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxBackups, MaxBackups)
	}
	if cfg.MaxAgeDays > MaxAgeDays {
		return fmt.Errorf("%w: max_age_days %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxAgeDays, MaxAgeDays)
	}
	return nil
}
