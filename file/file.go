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
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file/internal/rotate"
)

// Compile-time assertions.
var (
	_ audit.Output                = (*Output)(nil)
	_ audit.DestinationKeyer      = (*Output)(nil)
	_ audit.DeliveryReporter      = (*Output)(nil)
	_ audit.OutputMetricsReceiver = (*Output)(nil)
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

	// DefaultBufferSize is the default async buffer capacity for the
	// file output. Matches the default for webhook and loki outputs
	// to provide consistent behaviour across all async outputs.
	DefaultBufferSize = 10_000

	// MaxOutputBufferSize is the maximum allowed per-output async
	// buffer capacity. Values above this limit cause [New] to return
	// an error wrapping [audit.ErrConfigInvalid].
	MaxOutputBufferSize = 100_000
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

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [audit.OutputMetrics.RecordDrop] is
	// called. Zero defaults to [DefaultBufferSize] (10,000). Values
	// above [MaxOutputBufferSize] (100,000) cause [New] to return an
	// error wrapping [audit.ErrConfigInvalid].
	BufferSize int
}

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// Output writes serialised audit events to a file with automatic
// size-based rotation. It supports backup retention, age-based cleanup,
// and optional gzip compression.
//
// Write enqueues events into an internal buffered channel and returns
// immediately. A background goroutine reads from the channel and
// performs the actual file I/O. If the channel is full, the event is
// dropped and metrics are recorded.
//
// Output is safe for concurrent use, including concurrent calls
// to [Output.Write] and [Output.Close].
type Output struct {
	writer        *rotate.Writer
	logger        *slog.Logger
	outputMetrics atomic.Pointer[audit.OutputMetrics]
	fileMetrics   atomic.Pointer[Metrics]
	ch            chan []byte
	closeCh       chan struct{}
	done          chan struct{}
	name          string
	path          string
	writeCount    uint64
	drops         dropLimiter
	closed        atomic.Bool
	mu            sync.Mutex
}

// SetDiagnosticLogger receives the library's diagnostic logger.
func (f *Output) SetDiagnosticLogger(l *slog.Logger) {
	f.logger = l
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
// It validates the path, permissions, and parent directory existence,
// then starts a background goroutine for async event delivery.
// The fileMetrics parameter is optional (may be nil).
//
// Unlike other output constructors (syslog, webhook, loki) which take
// *Config, New takes Config by value. This is intentional: file Config
// has no pointer fields (except Compress), so the value copy prevents
// caller mutation without requiring an explicit defensive copy inside
// New.
func New(cfg Config, fileMetrics Metrics, opts ...Option) (*Output, error) { //nolint:gocyclo,cyclop // constructor with validation
	o := resolveOptions(opts)
	logger := o.logger

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
		logger.Warn("audit: file output permissions grant group/world access",
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

	out := &Output{
		path:    cfg.Path,
		name:    "file:" + cfg.Path,
		logger:  logger,
		ch:      make(chan []byte, cfg.BufferSize),
		closeCh: make(chan struct{}),
		done:    make(chan struct{}),
	}
	if fileMetrics != nil {
		out.fileMetrics.Store(&fileMetrics)
	}

	logPath := cfg.Path // capture for closure
	rotCfg := rotate.Config{
		MaxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
		MaxAge:     time.Duration(cfg.MaxAgeDays) * 24 * time.Hour,
		Mode:       perm,
		MaxBackups: cfg.MaxBackups,
		Compress:   compress,
		OnError: func(err error) {
			out.logger.Warn("audit: file output background error",
				"path", logPath, "error", err)
		},
	}
	// Always install OnRotate — reads from the struct field so that
	// SetOutputMetrics can provide a Metrics implementation after
	// construction.
	rotCfg.OnRotate = func(path string) {
		if fmp := out.fileMetrics.Load(); fmp != nil {
			(*fmp).RecordFileRotation(path)
		}
	}
	rw, err := rotate.New(cfg.Path, rotCfg)
	if err != nil {
		return nil, fmt.Errorf("audit: file output: %w", err)
	}
	out.writer = rw

	go out.writeLoop()
	return out, nil
}

// Write enqueues a serialised audit event for async delivery to the
// file. The data is copied before enqueuing — the caller may reuse
// the backing array after Write returns. If the internal buffer is
// full, the event is dropped and [audit.OutputMetrics.RecordDrop] is
// called. Write never blocks the caller.
func (f *Output) Write(data []byte) error {
	if f.closed.Load() {
		return audit.ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case f.ch <- cp:
		return nil
	default:
		f.drops.record(dropWarnInterval, func(dropped int64) {
			f.logger.Warn("audit: output file: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(f.ch))
		})
		if omp := f.outputMetrics.Load(); omp != nil {
			(*omp).RecordDrop()
		}
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the background goroutine to drain the buffer and
// flush remaining events, then closes the underlying file writer.
// Close is idempotent and safe for concurrent use with [Output.Write].
func (f *Output) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal writeLoop to drain remaining events and exit.
	close(f.closeCh)

	// Wait for writeLoop to finish draining.
	shutdownTimeout := 10 * time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-f.done:
	case <-timer.C:
		remaining := len(f.ch)
		f.logger.Error("audit: output file: shutdown timeout, events lost",
			"timeout", shutdownTimeout,
			"events_lost", remaining)
	}

	// Close the rotate.Writer AFTER the writeLoop exits to ensure all
	// drained events are written before the file is closed.
	if err := f.writer.Close(); err != nil {
		return fmt.Errorf("audit: file output close: %w", err)
	}
	return nil
}

// ReportsDelivery returns true, indicating that Output reports its
// own delivery metrics from the background writeLoop after actual
// file I/O, not from the Write enqueue path.
func (f *Output) ReportsDelivery() bool { return true }

// SetOutputMetrics receives the per-output metrics instance created
// by the [audit.OutputMetricsFactory]. Called once after construction,
// before the first Write call.
func (f *Output) SetOutputMetrics(m audit.OutputMetrics) {
	f.outputMetrics.Store(&m)
	// Check if the OutputMetrics also implements the file-specific
	// Metrics extension interface for rotation recording.
	if fm, ok := m.(Metrics); ok {
		f.fileMetrics.Store(&fm)
	}
}

// writeLoop is the background goroutine that reads events from the
// channel and writes them to the rotate.Writer. It runs until closeCh
// is closed, then drains remaining events before returning.
func (f *Output) writeLoop() {
	defer close(f.done)

	for {
		select {
		case data := <-f.ch:
			f.writeEvent(data)
		case <-f.closeCh:
			f.drainRemaining()
			return
		}
	}
}

// writeEvent writes a single event to the rotate.Writer with panic
// recovery and metrics recording.
func (f *Output) writeEvent(data []byte) {
	// Load metrics once per event for consistent snapshot.
	var om audit.OutputMetrics
	if omp := f.outputMetrics.Load(); omp != nil {
		om = *omp
	}

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			f.logger.Error("audit: output file: panic recovered",
				"panic", r,
				"stack", string(buf[:n]))
			if om != nil {
				om.RecordError()
			}
		}
	}()

	// Sample queue depth every 64 events.
	f.writeCount++
	if om != nil && f.writeCount&63 == 0 {
		om.RecordQueueDepth(len(f.ch), cap(f.ch))
	}

	var start time.Time
	if om != nil {
		start = time.Now()
	}
	if _, err := f.writer.Write(data); err != nil {
		f.logger.Error("audit: output file: delivery failed",
			"error", err)
		if om != nil {
			om.RecordError()
		}
		return
	}
	if om != nil {
		om.RecordFlush(1, time.Since(start))
	}
}

// drainRemaining reads all remaining events from the channel after
// closeCh fires and writes them to the file.
func (f *Output) drainRemaining() {
	for {
		select {
		case data := <-f.ch:
			f.writeEvent(data)
		default:
			return
		}
	}
}

// Name returns the human-readable identifier for this output.
func (f *Output) Name() string {
	return f.name
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

// applyFileDefaults fills zero-valued rotation and buffer fields with defaults.
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
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}
}

// validateFileLimits checks that rotation and buffer fields do not
// exceed their upper bounds.
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
	if cfg.BufferSize > MaxOutputBufferSize {
		return fmt.Errorf("%w: buffer_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BufferSize, MaxOutputBufferSize)
	}
	return nil
}
