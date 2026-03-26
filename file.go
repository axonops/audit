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
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// FileConfig holds configuration for [FileOutput].
type FileConfig struct {
	// Path is the file path for the audit log. REQUIRED; an empty path
	// causes [NewFileOutput] to return an error.
	Path string

	// Permissions is the file mode for the audit log file, specified as
	// an octal string (e.g. "0600"). Empty defaults to "0600".
	Permissions string

	// Compress controls whether rotated log files are compressed with
	// gzip. Nil defaults to true.
	Compress *bool

	// MaxSizeMB is the maximum size in megabytes before the log file
	// is rotated. Zero defaults to 100.
	MaxSizeMB int

	// MaxBackups is the maximum number of old log files to retain.
	// Zero defaults to 5.
	MaxBackups int

	// MaxAgeDays is the maximum number of days to retain old log files.
	// Zero defaults to 30.
	MaxAgeDays int
}

// FileOutput writes serialised audit events to a file with automatic
// rotation via lumberjack. It supports size-based rotation, backup
// retention, age-based cleanup, and optional gzip compression.
//
// FileOutput is safe for concurrent use, including concurrent calls
// to [FileOutput.Write] and [FileOutput.Close].
type FileOutput struct {
	logger *lumberjack.Logger
	mu     sync.RWMutex
	path   string
	closed bool
}

// NewFileOutput creates a new [FileOutput] from the given config.
// It validates the path, permissions, and parent directory existence.
func NewFileOutput(cfg FileConfig) (*FileOutput, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: file output path must not be empty")
	}

	parentDir := filepath.Dir(cfg.Path)
	if _, err := os.Lstat(parentDir); err != nil {
		return nil, fmt.Errorf("audit: file output parent directory %q: %w", parentDir, err)
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

	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}

	compress := true
	if cfg.Compress != nil {
		compress = *cfg.Compress
	}

	// Set file permissions before lumberjack opens the file.
	if err := ensureFilePermissions(cfg.Path, perm); err != nil {
		return nil, err
	}

	lj := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   compress,
		LocalTime:  true,
	}

	return &FileOutput{logger: lj, path: cfg.Path}, nil
}

// Write sends a serialised audit event to the file. Write returns
// [ErrOutputClosed] if the output has been closed. Write is safe for
// concurrent use.
func (f *FileOutput) Write(data []byte) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return ErrOutputClosed
	}
	if _, err := f.logger.Write(data); err != nil {
		return fmt.Errorf("audit: file output write: %w", err)
	}
	return nil
}

// Close closes the underlying lumberjack logger and marks the output
// as closed. Close is idempotent and safe for concurrent use with
// [FileOutput.Write].
func (f *FileOutput) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if err := f.logger.Close(); err != nil {
		return fmt.Errorf("audit: file output close: %w", err)
	}
	return nil
}

// Name returns the human-readable identifier for this output.
func (f *FileOutput) Name() string {
	return "file:" + f.path
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

// ensureFilePermissions creates or updates the file with the given
// permissions. If the file does not exist, it is created. If it
// exists, its permissions are updated via the file descriptor to
// avoid symlink TOCTOU races.
func ensureFilePermissions(path string, perm os.FileMode) error {
	// Check for symlinks before opening to prevent following them.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("audit: file output path %q is a symlink", path)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return fmt.Errorf("audit: file output create %q: %w", path, err)
	}

	// Use f.Chmod on the file descriptor rather than os.Chmod on the
	// path to avoid a second path resolution (symlink TOCTOU).
	chmodErr := f.Chmod(perm)
	closeErr := f.Close()
	if chmodErr != nil {
		return fmt.Errorf("audit: file output chmod %q: %w", path, chmodErr)
	}
	if closeErr != nil {
		return fmt.Errorf("audit: file output close %q: %w", path, closeErr)
	}
	return nil
}
