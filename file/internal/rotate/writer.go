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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit/iouring"
)

// bufSize is the bufio.Writer buffer size. 32KB batches many small
// audit events (~200-500 bytes each) into fewer write(2) syscalls.
// MaxSize is treated as a soft limit — the file may exceed it by up
// to bufSize before rotation triggers.
const bufSize = 32 * 1024

// Config controls the rotation behaviour of a [Writer].
type Config struct {
	// OnRotate is called from the Write goroutine immediately after a
	// successful rotation. The path argument is the absolute path of
	// the file that was rotated. It must not block. If nil, rotation
	// events are silently discarded.
	OnRotate func(path string)

	// OnError is called sequentially from a single background goroutine
	// whenever a background operation (compression, backup removal,
	// age-based cleanup) fails. It must not block. If nil, errors are
	// silently discarded.
	OnError func(error)

	// MaxSize is the maximum size in bytes of the active log file before
	// rotation is triggered. Required; must be > 0.
	MaxSize int64

	// MaxAge is the maximum age of backup files. Backups older than this
	// duration are removed during cleanup. Zero means no age limit.
	MaxAge time.Duration

	// MaxBackups is the maximum number of backup files to retain. Zero
	// means unlimited.
	MaxBackups int

	// Mode is the file permission bits applied to every file the writer
	// creates or opens — active, backup, and compressed. Required; must
	// be non-zero.
	Mode os.FileMode

	// Compress enables gzip compression of rotated backup files.
	Compress bool

	// SyncOnWrite controls whether [Writer.Write] flushes the
	// bufio buffer to the OS page cache after every call. When
	// true (the previous default), every event is immediately
	// visible to readers at the cost of one syscall per call.
	// When false (the new default), bytes accumulate in the
	// bufio buffer and are flushed by the background timer
	// (see [Config.FlushInterval]), when the buffer fills, on
	// rotation, on Sync, and on Close — trading a bounded
	// data-at-risk window for measurably higher throughput on
	// the singular [Writer.Write] path.
	//
	// SyncOnWrite does NOT affect the batched [Writer.Writev]
	// path. Batched writes always commit in full to the page
	// cache as one syscall; there is no buffer between them
	// and the kernel.
	SyncOnWrite bool

	// FlushInterval is the cadence at which the background
	// flush goroutine drains the bufio buffer to the page
	// cache when [Config.SyncOnWrite] is false. Zero defaults
	// to 100 ms. Values below 1 ms are clamped to 1 ms.
	// Ignored when SyncOnWrite is true.
	FlushInterval time.Duration
}

// Writer is a concurrency-safe file writer with automatic size-based
// rotation. It protects against symlink attacks on every open and
// enforces configured permissions on all files it creates.
//
// Writer is lazy — [New] validates the configuration but does not
// create or open the file. The file is opened on the first [Writer.Write].
//
//nolint:govet // field order: logical grouping (construction inputs, then runtime state, then locks + flags)
type Writer struct {
	// now is used for testing to control time.
	now func() time.Time

	// iw is the dedicated iouring writer forced to
	// [iouring.StrategyWritev]. On ext4/NVMe benchmarks in ADR
	// 0002 the io_uring path was measurably slower than writev(2)
	// at every batch size (up to 9.4× slower at batch 1) because
	// our submit-and-wait pattern does not overlap in-flight
	// submissions — the one scenario where io_uring pays off.
	// A future async variant can re-enable io_uring via a config
	// knob; for v1.0, writev is the right default.
	//
	// On platforms without any vectored-write primitive (Windows),
	// iw is nil and Writev falls back to per-buffer bufio writes.
	iw *iouring.Writer

	// writevFn is the vectored-write primitive invoked by
	// [Writer.Writev]. Defaults to iw.Writev at construction;
	// tests swap it via export_test to simulate the ErrUnsupported
	// fallback path on every platform.
	writevFn func(fd int, bufs [][]byte) (int, error)

	file     *os.File
	bw       *bufio.Writer
	millCh   chan struct{}
	millDone chan struct{} // closed when the mill goroutine exits

	// flushCh signals the background flush goroutine to exit.
	// flushDone closes when the goroutine has exited so Close
	// can wait for a clean shutdown.
	flushCh   chan struct{}
	flushDone chan struct{}
	flushOnce sync.Once

	// pendingFlush is set by writeLocked when it adds bytes to
	// the bufio buffer without flushing (SyncOnWrite=false).
	// The flush goroutine skips the Flush syscall when no bytes
	// are pending, so an idle writer produces no wakeup traffic.
	pendingFlush bool

	filename string // absolute, cleaned path
	dir      string
	prefix   string // base name without extension, with trailing "-"
	ext      string // extension including the dot
	cfg      Config
	size     int64
	mu       sync.Mutex
	millOnce sync.Once
	closed   bool

	// vectoredSupported caches whether the platform offers any
	// vectored-write primitive. False on Windows (no writev);
	// [Writer.Writev] then loops over per-buffer bufio writes
	// to honour the same #450 prompt-visibility contract.
	vectoredSupported bool
}

// New creates a [Writer] that will write to filename with the given
// rotation configuration. New validates the configuration and checks
// that the parent directory exists, but does not create or open the
// file.
func New(filename string, cfg Config) (*Writer, error) {
	filename, dir, err := resolveAndValidatePath(filename)
	if err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"

	w := &Writer{
		cfg:      cfg,
		filename: filename,
		dir:      dir,
		prefix:   prefix,
		ext:      ext,
		now:      time.Now,
	}

	// Construct a dedicated iouring writer forced to the writev
	// strategy. This skips the package-level StrategyAuto (which
	// would pick io_uring on capable kernels) because measured
	// numbers in ADR 0002 show writev(2) outperforms io_uring at
	// every batch size for our submit-and-wait pattern.
	//
	// On Windows New returns ErrUnsupported; we catch that and
	// fall back to the bufio path, keeping audit output working
	// everywhere.
	iw, ierr := iouring.New(iouring.WithStrategy(iouring.StrategyWritev))
	switch {
	case ierr == nil:
		w.iw = iw
		w.writevFn = iw.Writev
		w.vectoredSupported = true
	case errors.Is(ierr, iouring.ErrUnsupported):
		// No vectored primitive available — fall back to bufio.
	default:
		return nil, fmt.Errorf("rotate: init writev: %w", ierr)
	}
	return w, nil
}

// Write writes p to the active log file, rotating if the write would
// cause the file to exceed [Config.MaxSize]. A single write that
// exceeds MaxSize is accepted (written then rotated) to avoid
// silently dropping audit events.
//
// Write returns an error wrapping [os.ErrClosed] if the writer has
// been closed.
func (w *Writer) Write(p []byte) (n int, err error) {
	var rotated bool

	w.mu.Lock()
	n, rotated, err = w.writeLocked(p)
	w.mu.Unlock()

	if rotated && w.cfg.OnRotate != nil {
		w.cfg.OnRotate(w.filename)
	}
	return n, err
}

// Writev writes bufs to the active log file as a single batched
// operation, rotating if the total size would cause the file to
// exceed [Config.MaxSize]. A single batch that itself exceeds
// MaxSize is accepted (written then rotated on the next call) —
// this mirrors the oversize-write semantics of [Writer.Write].
//
// On Linux 5.5+ with io_uring-capable kernels, Writev uses
// io_uring for the kernel-side write; on other Unix platforms it
// falls back to writev(2). The selection is handled entirely by
// [iouring.Writev]. Unlike [Writer.Write], the batched path does
// NOT go through [bufio.Writer]: the batch itself is the buffer,
// so the #450 "flush after every write" contract becomes "flush
// after every batch" — crashes lose at most one in-flight batch.
//
// Writev returns an error wrapping [os.ErrClosed] if the writer
// has been closed.
func (w *Writer) Writev(bufs [][]byte) (n int, err error) {
	var rotated bool

	w.mu.Lock()
	n, rotated, err = w.writevLocked(bufs)
	w.mu.Unlock()

	if rotated && w.cfg.OnRotate != nil {
		w.cfg.OnRotate(w.filename)
	}
	return n, err
}

// writevLocked performs the batched write under the mutex.
func (w *Writer) writevLocked(bufs [][]byte) (n int, rotated bool, err error) {
	if w.closed {
		return 0, false, fmt.Errorf("rotate: %w", os.ErrClosed)
	}

	var writeLen int64
	for _, b := range bufs {
		writeLen += int64(len(b))
	}
	if writeLen == 0 {
		return 0, false, nil
	}

	rotated, err = w.prepareForWrite(writeLen)
	if err != nil {
		return 0, false, err
	}

	// On platforms without a vectored-write primitive (currently
	// Windows), fall back to a loop of per-buffer bufio writes.
	// Each iteration uses the same flush-after-write contract as
	// [Writer.Write], preserving the #450 prompt-visibility
	// guarantee at the cost of one syscall per buffer.
	if !w.vectoredSupported {
		return w.writevViaBufio(bufs, rotated)
	}

	// Drain any bytes sitting in bufio before bypassing it with
	// iouring.Writev — otherwise batched bytes could land on disk
	// before earlier Write() bytes that are still in the buffer.
	if w.bw != nil {
		if fErr := w.bw.Flush(); fErr != nil {
			return 0, rotated, fmt.Errorf("rotate: flush: %w", fErr)
		}
	}

	written, werr := writevAll(int(w.file.Fd()), bufs, int(writeLen), w.writevFn)
	w.size += int64(written)
	if werr != nil {
		return written, rotated, werr
	}
	return written, rotated, nil
}

// writevViaBufio is the Windows / no-vectored-primitive fallback
// path. It loops over bufs, pushing each through the bufio
// writer and flushing. Preserves the #450 prompt-visibility
// contract — every batch is on the kernel page cache before
// this method returns.
func (w *Writer) writevViaBufio(bufs [][]byte, rotated bool) (n int, _ bool, err error) {
	total := 0
	for _, b := range bufs {
		if len(b) == 0 {
			continue
		}
		written, werr := w.bw.Write(b)
		total += written
		if werr != nil {
			w.size += int64(total)
			return total, rotated, fmt.Errorf("rotate: write: %w", werr)
		}
	}
	if fErr := w.bw.Flush(); fErr != nil {
		w.size += int64(total)
		return total, rotated, fmt.Errorf("rotate: flush: %w", fErr)
	}
	w.size += int64(total)
	return total, rotated, nil
}

// prepareForWrite opens a file if none is open yet and rotates
// if the pending write would exceed MaxSize. Returns whether a
// rotation occurred so the caller can fire OnRotate outside the
// lock.
func (w *Writer) prepareForWrite(writeLen int64) (rotated bool, err error) {
	if w.file == nil {
		openRotated, err := w.openExistingOrNew(writeLen)
		if err != nil {
			return false, err
		}
		rotated = openRotated
	}
	if w.size+writeLen > w.cfg.MaxSize {
		if rotateErr := w.rotate(); rotateErr != nil {
			return rotated, rotateErr
		}
		rotated = true
	}
	return rotated, nil
}

// writevAll submits bufs to fd via writevFn, retrying short
// writes by advancing the iovec remainder. Used by Writer.Writev
// after rotation and buffer-draining have completed. Returns
// total bytes written and any error.
func writevAll(fd int, bufs [][]byte, total int, writevFn func(int, [][]byte) (int, error)) (int, error) {
	written := 0
	remaining := bufs
	for written < total {
		got, werr := writevFn(fd, remaining)
		if werr != nil {
			return written, fmt.Errorf("rotate: writev: %w", werr)
		}
		if got == 0 {
			// No progress; avoid infinite loop.
			return written, nil
		}
		written += got
		remaining = advanceIovecs(remaining, got)
	}
	return written, nil
}

// resolveAndValidatePath normalises the filename to an absolute
// path and verifies the parent directory exists.
func resolveAndValidatePath(filename string) (cleaned, dir string, err error) {
	if filename == "" {
		return "", "", errors.New("rotate: filename must not be empty")
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return "", "", fmt.Errorf("rotate: resolve path: %w", err)
	}
	cleaned = filepath.Clean(abs)
	dir = filepath.Dir(cleaned)
	if _, err := os.Stat(dir); err != nil {
		return "", "", fmt.Errorf("rotate: parent directory %q: %w", dir, err)
	}
	return cleaned, dir, nil
}

// validateConfig checks required fields are set and normalises
// optional fields to their defaults. Mutates cfg in-place.
func validateConfig(cfg *Config) error {
	if cfg.MaxSize <= 0 {
		return errors.New("rotate: MaxSize must be > 0")
	}
	if cfg.Mode == 0 {
		return errors.New("rotate: Mode must be non-zero")
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	} else if cfg.FlushInterval < time.Millisecond {
		cfg.FlushInterval = time.Millisecond
	}
	return nil
}

// advanceIovecs returns a [][]byte representing the portion of
// bufs that remains unwritten after `done` bytes have been
// written. Completed inner slices are dropped; the first
// incomplete slice is re-sliced.
func advanceIovecs(bufs [][]byte, done int) [][]byte {
	for len(bufs) > 0 {
		if done < len(bufs[0]) {
			bufs[0] = bufs[0][done:]
			return bufs
		}
		done -= len(bufs[0])
		bufs = bufs[1:]
	}
	return bufs
}

// writeLocked performs the write under the mutex, returning whether
// a rotation occurred so the caller can invoke OnRotate outside the lock.
func (w *Writer) writeLocked(p []byte) (n int, rotated bool, err error) {
	if w.closed {
		return 0, false, fmt.Errorf("rotate: %w", os.ErrClosed)
	}

	writeLen := int64(len(p))

	if w.file == nil {
		var openRotated bool
		openRotated, err = w.openExistingOrNew(writeLen)
		if err != nil {
			return 0, false, err
		}
		if openRotated {
			rotated = true
		}
	}

	if w.size+writeLen > w.cfg.MaxSize {
		if rotateErr := w.rotate(); rotateErr != nil {
			return 0, false, rotateErr
		}
		rotated = true
	}

	n, err = w.bw.Write(p)
	w.size += int64(n)
	if err != nil {
		return n, rotated, fmt.Errorf("rotate: write: %w", err)
	}

	// Flush behaviour (#461): when SyncOnWrite is true, flush
	// immediately (the #450 prompt-visibility contract) — every
	// event hits the OS page cache before Write returns. When
	// SyncOnWrite is false (the default), mark the buffer dirty
	// so the background timer goroutine drains it on the next
	// tick. Bytes still land on the page cache within
	// FlushInterval (default 100 ms), but the per-call syscall
	// is eliminated.
	if w.cfg.SyncOnWrite {
		if fErr := w.bw.Flush(); fErr != nil {
			return n, rotated, fmt.Errorf("rotate: flush: %w", fErr)
		}
	} else {
		w.pendingFlush = true
		w.startFlushLoopLocked()
	}
	return n, rotated, nil
}

// startFlushLoopLocked starts the background flush goroutine if
// it isn't already running. Called by writeLocked once per
// writer. Must be called with w.mu held so the sync.Once + chan
// allocation is visible to Close.
func (w *Writer) startFlushLoopLocked() {
	w.flushOnce.Do(func() {
		// Defensive clamp: callers that bypassed New() and
		// constructed a Writer{} directly may leave
		// FlushInterval zero. Normalise here too so the ticker
		// never panics.
		interval := w.cfg.FlushInterval
		if interval < time.Millisecond {
			interval = 100 * time.Millisecond
		}
		w.flushCh = make(chan struct{})
		w.flushDone = make(chan struct{})
		go w.flushLoop(interval)
	})
}

// flushLoop drains the bufio buffer every interval while there
// are bytes pending. Exits cleanly when flushCh is closed.
func (w *Writer) flushLoop(interval time.Duration) {
	defer close(w.flushDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			w.tickFlush()
		case <-w.flushCh:
			return
		}
	}
}

// tickFlush is one iteration of the background flush. Skips
// the Flush syscall when no bytes are pending so an idle writer
// produces no wakeup traffic beyond the bare timer.
func (w *Writer) tickFlush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pendingFlush || w.bw == nil || w.closed {
		return
	}
	_ = w.bw.Flush() // errors surface on the next Write / via OnError
	w.pendingFlush = false
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
	err := w.closeFile() // flushes pending bytes
	millCh := w.millCh
	flushCh := w.flushCh
	flushDone := w.flushDone
	iw := w.iw
	w.iw = nil
	w.mu.Unlock()

	// Signal and drain the mill goroutine.
	if millCh != nil {
		close(millCh)
		<-w.millDone
	}

	// Signal and drain the background flush goroutine (#461).
	// Safe to call with flushCh == nil when SyncOnWrite was true
	// or the writer never wrote anything.
	if flushCh != nil {
		close(flushCh)
		<-flushDone
	}

	// Release the dedicated iouring writer. No effect on the
	// fallback-to-bufio path where iw is nil.
	if iw != nil {
		if ierr := iw.Close(); ierr != nil && err == nil {
			err = fmt.Errorf("rotate: close writev: %w", ierr)
		}
	}

	return err
}

// openExistingOrNew opens an existing file for appending if it exists
// and has capacity, or creates a new file. Returns true if a rotation
// occurred.
func (w *Writer) openExistingOrNew(writeLen int64) (bool, error) {
	info, err := safeStat(w.filename)
	if os.IsNotExist(err) {
		return false, w.openNew()
	}
	if err != nil {
		return false, fmt.Errorf("rotate: stat %q: %w", w.filename, err)
	}

	if info.Size()+writeLen > w.cfg.MaxSize {
		return true, w.rotate()
	}

	f, err := safeOpen(w.filename, os.O_APPEND|os.O_WRONLY, w.cfg.Mode)
	if err != nil {
		// If we can't open the existing file, create a new one.
		return false, w.openNew()
	}

	w.file = f
	w.bw = bufio.NewWriterSize(f, bufSize)
	w.size = info.Size()
	return false, nil
}

// openNew renames the current file (if any) to a timestamped backup
// name and creates a fresh file.
func (w *Writer) openNew() error {
	// If the current file exists, rename it to a backup.
	if _, err := safeStat(w.filename); err == nil {
		name, nameErr := w.backupName(w.now())
		if nameErr != nil {
			return nameErr
		}
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
	w.bw = bufio.NewWriterSize(f, bufSize)
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

// closeFile flushes buffered data and closes the current file handle.
func (w *Writer) closeFile() error {
	if w.file == nil {
		return nil
	}
	if w.bw != nil {
		if err := w.bw.Flush(); err != nil {
			return fmt.Errorf("rotate: flush: %w", err)
		}
		w.bw = nil
	}
	w.pendingFlush = false
	err := w.file.Close()
	w.file = nil
	w.size = 0
	if err != nil {
		return fmt.Errorf("rotate: close file: %w", err)
	}
	return nil
}

// Sync flushes the buffered writer and the file's in-memory state to
// stable storage.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	if w.bw != nil {
		if err := w.bw.Flush(); err != nil {
			return fmt.Errorf("rotate: flush: %w", err)
		}
		w.pendingFlush = false
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("rotate: sync: %w", err)
	}
	return nil
}

// reportError calls the configured OnError callback if non-nil.
func (w *Writer) reportError(err error) {
	if w.cfg.OnError != nil {
		w.cfg.OnError(err)
	}
}

// Ensure Writer satisfies io.WriteCloser.
var _ io.WriteCloser = (*Writer)(nil)
