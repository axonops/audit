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

package iouring

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// defaultRingDepth is the io_uring submission-queue depth used when
// no [WithRingDepth] option is supplied. Matches the write-loop
// batch cap of 128 with headroom; doubling or halving it is a
// pure performance knob.
const defaultRingDepth = 16

// Writer performs vectored writes to file descriptors using the
// best available platform strategy. [Writer.Writev] and
// [Writer.Write] are NOT safe for concurrent use; callers must
// serialise access. [Writer.Close] is safe to call concurrently
// from any goroutine and is idempotent.
//
// For a zero-ceremony, concurrent-safe entry point, use the
// package-level [Writev] / [Write] instead of constructing a
// Writer.
type Writer struct {
	impl      strategyImpl
	closeOnce sync.Once
	closed    atomic.Bool
}

// config holds option values resolved before a strategy is chosen.
type config struct {
	strategy  Strategy
	ringDepth uint32
	logger    *slog.Logger
}

// Option configures [New]. All options are optional; [New] with
// zero options uses sensible defaults.
type Option func(*config)

// WithStrategy forces a specific [Strategy]. Passing
// [StrategyIouring] on a host without io_uring causes [New] to
// return an error wrapping [ErrUnsupported]. Passing
// [StrategyWritev] forces the writev path even on io_uring-capable
// hosts — useful for benchmarking and testing. The default is
// [StrategyAuto].
func WithStrategy(s Strategy) Option {
	return func(c *config) { c.strategy = s }
}

// WithRingDepth sets the io_uring submission-queue depth. Must be
// a power of two between 1 and 4096 inclusive. Ignored by
// strategies other than [StrategyIouring]. Defaults to 16.
func WithRingDepth(n uint32) Option {
	return func(c *config) { c.ringDepth = n }
}

// WithLogger configures a [slog.Logger] that receives exactly one
// log line at construction indicating the selected strategy and
// (if applicable) the reason. Nil — the default — disables
// logging. Writers never log on the hot path.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// New constructs a [Writer] with the given options. The default
// strategy is [StrategyAuto], which prefers io_uring on capable
// Linux hosts and falls back to writev(2) on other Unix platforms.
// On platforms without any vectored-write support (currently
// Windows), New returns an error wrapping [ErrUnsupported].
//
// The returned Writer MUST be released with [Writer.Close] when
// no longer needed, regardless of which strategy it uses.
func New(opts ...Option) (*Writer, error) {
	cfg := config{
		strategy:  StrategyAuto,
		ringDepth: defaultRingDepth,
	}
	for _, o := range opts {
		o(&cfg)
	}
	impl, err := chooseStrategy(&cfg)
	if err != nil {
		return nil, err
	}
	if cfg.logger != nil {
		cfg.logger.Info("iouring: writer constructed", "strategy", impl.kind().String())
	}
	return &Writer{impl: impl}, nil
}

// Writev writes bufs to fd as a single vectored operation and
// blocks until completion. Returns bytes written and any error.
// See the package documentation for short-write and atomicity
// semantics.
//
// Writev is NOT safe for concurrent use.
func (w *Writer) Writev(fd int, bufs [][]byte) (int, error) {
	if w == nil || w.impl == nil || w.closed.Load() {
		return 0, ErrClosed
	}
	return w.impl.writev(fd, bufs)
}

// Write is a single-buffer convenience wrapper around [Writer.Writev].
func (w *Writer) Write(fd int, buf []byte) (int, error) {
	return w.Writev(fd, [][]byte{buf})
}

// Strategy reports the negotiated strategy this [Writer] is using.
// The result is stable for the Writer's lifetime and is one of
// [StrategyIouring] or [StrategyWritev] — never [StrategyAuto].
func (w *Writer) Strategy() Strategy {
	if w == nil || w.impl == nil {
		return StrategyUnsupported
	}
	return w.impl.kind()
}

// Close releases any resources held by the [Writer]. Close is
// idempotent and safe to call concurrently from any goroutine.
// Subsequent [Writer.Writev] / [Writer.Write] calls return
// [ErrClosed].
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	var err error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.impl != nil {
			err = w.impl.close()
		}
	})
	return err
}

// ---------------------------------------------------------------
// Package-level convenience — zero-ceremony path
// ---------------------------------------------------------------

// defaultWriter is lazily initialised on first use of the
// package-level [Writev] / [Write]. Guarded by defaultMu for
// concurrent-safety — the default writer itself is not concurrent-
// safe, so we serialise access at this layer.
var (
	defaultOnce   sync.Once
	defaultWriter *Writer
	defaultErr    error
	defaultMu     sync.Mutex
)

// initDefault resolves the process-wide default writer. Called by
// sync.Once so initialisation happens at most once and subsequent
// lookups are branch-prediction-friendly.
func initDefault() {
	defaultWriter, defaultErr = New()
}

// Writev writes bufs to fd using the process-wide default
// [Writer]. Safe for concurrent use via an internal mutex on the
// default writer. For the uncontended case the mutex overhead is
// ~20ns; under heavy contention, construct a dedicated [Writer]
// with [New] per producer goroutine.
//
// If the platform has no vectored-write support, Writev returns
// [ErrUnsupported].
func Writev(fd int, bufs [][]byte) (int, error) {
	defaultOnce.Do(initDefault)
	if defaultErr != nil {
		return 0, defaultErr
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	return defaultWriter.Writev(fd, bufs)
}

// Write is a single-buffer convenience wrapper around the package-
// level [Writev].
func Write(fd int, buf []byte) (int, error) {
	return Writev(fd, [][]byte{buf})
}

// DefaultStrategy reports the [Strategy] the process-wide default
// writer chose, or [StrategyUnsupported] if the platform has no
// vectored-write support. The first call triggers lazy
// initialisation of the default writer; subsequent calls are O(1).
func DefaultStrategy() Strategy {
	defaultOnce.Do(initDefault)
	if defaultErr != nil || defaultWriter == nil {
		return StrategyUnsupported
	}
	return defaultWriter.Strategy()
}

// IouringSupported reports whether the [StrategyIouring] path is
// available on this host. The first call performs a probe
// syscall (~200μs) and caches the result. Callers using the
// default [StrategyAuto] do NOT need to call this — [New] and
// the package-level [Writev] handle negotiation internally.
//
// On non-Linux platforms, IouringSupported always returns false.
func IouringSupported() bool { return iouringSupported() }

// errStrategyNotSupported is returned when a caller passes
// WithStrategy(StrategyIouring) on a non-Linux host.
func errStrategyNotSupported(s Strategy) error {
	return fmt.Errorf("iouring: strategy %s not available on this platform: %w", s, ErrUnsupported)
}
