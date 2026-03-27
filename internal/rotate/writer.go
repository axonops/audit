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

// Package rotate provides a symlink-safe, permission-enforcing file
// writer with size-based rotation, backup retention, age-based cleanup,
// and optional gzip compression.
package rotate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config controls the rotation behaviour of a [Writer].
type Config struct {
	// MaxSize is the maximum size in bytes of the active log file before
	// rotation is triggered. Required; must be > 0.
	MaxSize int64

	// MaxAge is the maximum age of backup files. Backups older than this
	// duration are removed during cleanup. Zero means no age limit.
	MaxAge time.Duration

	// Mode is the file permission bits applied to every file the writer
	// creates or opens — active, backup, and compressed. Required; must
	// be non-zero.
	Mode os.FileMode

	// MaxBackups is the maximum number of backup files to retain. Zero
	// means unlimited.
	MaxBackups int

	// Compress enables gzip compression of rotated backup files.
	Compress bool
}

// Writer is a concurrency-safe file writer with automatic size-based
// rotation. It protects against symlink attacks on every open and
// enforces configured permissions on all files it creates.
//
// Writer is lazy — [New] validates the configuration but does not
// create or open the file. The file is opened on the first [Writer.Write].
type Writer struct {
	cfg      Config
	filename string // absolute, cleaned path
	dir      string
	prefix   string // base name without extension, with trailing "-"
	ext      string // extension including the dot

	size int64
	file *os.File

	mu       sync.Mutex
	millCh   chan struct{}
	millDone chan struct{} // closed when the mill goroutine exits
	millOnce sync.Once
	closed   bool

	// now is used for testing to control time.
	now func() time.Time
}

// New creates a [Writer] that will write to filename with the given
// rotation configuration. New validates the configuration and checks
// that the parent directory exists, but does not create or open the
// file.
func New(filename string, cfg Config) (*Writer, error) {
	if filename == "" {
		return nil, errors.New("rotate: filename must not be empty")
	}

	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("rotate: resolve path: %w", err)
	}
	filename = filepath.Clean(abs)

	dir := filepath.Dir(filename)
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("rotate: parent directory %q: %w", dir, err)
	}

	if cfg.MaxSize <= 0 {
		return nil, errors.New("rotate: MaxSize must be > 0")
	}
	if cfg.Mode == 0 {
		return nil, errors.New("rotate: Mode must be non-zero")
	}

	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"

	return &Writer{
		cfg:      cfg,
		filename: filename,
		dir:      dir,
		prefix:   prefix,
		ext:      ext,
		now:      time.Now,
	}, nil
}

// Write writes p to the active log file, rotating if the write would
// cause the file to exceed [Config.MaxSize]. A single write that
// exceeds MaxSize is accepted (written then rotated) to avoid
// silently dropping audit events.
//
// Write returns an error wrapping [os.ErrClosed] if the writer has
// been closed.
func (w *Writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, fmt.Errorf("rotate: %w", os.ErrClosed)
	}

	writeLen := int64(len(p))

	if w.file == nil {
		if err := w.openExistingOrNew(writeLen); err != nil {
			return 0, err
		}
	}

	if w.size+writeLen > w.cfg.MaxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err = w.file.Write(p)
	w.size += int64(n)
	if err != nil {
		return n, fmt.Errorf("rotate: write: %w", err)
	}
	return n, nil
}

// Close closes the active file and waits for any in-progress
// compression to finish. Close is idempotent.
func (w *Writer) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	err := w.closeFile()
	millCh := w.millCh
	w.mu.Unlock()

	// Signal the mill goroutine to stop and wait for it.
	if millCh != nil {
		close(millCh)
		<-w.millDone
	}

	return err
}

// openExistingOrNew opens an existing file for appending if it exists
// and has capacity, or creates a new file.
func (w *Writer) openExistingOrNew(writeLen int64) error {
	info, err := safeStat(w.filename)
	if os.IsNotExist(err) {
		return w.openNew()
	}
	if err != nil {
		return fmt.Errorf("rotate: stat %q: %w", w.filename, err)
	}

	if info.Size()+writeLen > w.cfg.MaxSize {
		return w.rotate()
	}

	f, err := safeOpen(w.filename, os.O_APPEND|os.O_WRONLY, w.cfg.Mode)
	if err != nil {
		// If we can't open the existing file, create a new one.
		return w.openNew()
	}

	w.file = f
	w.size = info.Size()
	return nil
}

// openNew renames the current file (if any) to a timestamped backup
// name and creates a fresh file.
func (w *Writer) openNew() error {
	// If the current file exists, rename it to a backup.
	if _, err := safeStat(w.filename); err == nil {
		name := w.backupName(w.now())
		// Reject if the backup destination is a symlink — an attacker
		// could pre-create a symlink at the predictable backup path to
		// redirect audit data.
		if info, statErr := os.Lstat(name); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("rotate: backup path %q is a symlink", name)
			}
		}
		if renameErr := os.Rename(w.filename, name); renameErr != nil {
			return fmt.Errorf("rotate: rename to backup: %w", renameErr)
		}
	}

	f, err := safeOpen(w.filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, w.cfg.Mode)
	if err != nil {
		return fmt.Errorf("rotate: create %q: %w", w.filename, err)
	}

	w.file = f
	w.size = 0
	w.mill()
	return nil
}

// rotate closes the current file and opens a new one.
func (w *Writer) rotate() error {
	if err := w.closeFile(); err != nil {
		return err
	}
	return w.openNew()
}

// closeFile closes the current file handle if open.
func (w *Writer) closeFile() error {
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	w.size = 0
	if err != nil {
		return fmt.Errorf("rotate: close file: %w", err)
	}
	return nil
}

// Sync flushes the file's in-memory state to stable storage.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	return w.file.Sync()
}

// Ensure Writer satisfies io.WriteCloser.
var _ io.WriteCloser = (*Writer)(nil)
