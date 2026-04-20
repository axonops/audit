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

// defaultRingDepth is the io_uring submission-queue depth used
// when no [WithRingDepth] option is supplied. Small enough for
// low per-construction cost; deep enough to absorb small bursts
// without head-of-line blocking on the kernel side.
const defaultRingDepth = 16

// Writer performs vectored writes to file descriptors using the
// best available platform strategy. [Writer.Writev] and
// [Writer.Write] are NOT safe for concurrent use; callers must
// serialise access, including against [Writer.Close]. A racing
// Writev and Close is undefined behaviour.
//
// [Writer.Close] is safe to call concurrently from any goroutine
// relative to itself (Close is idempotent).
//
// A Writer does not take ownership of the file descriptor passed
// to [Writer.Writev] / [Writer.Write]; the caller retains fd
// lifecycle responsibility. The fd must remain open for the
// duration of each call.
//
// For a zero-ceremony, concurrent-safe entry point, use the
// package-level [Writev] instead of constructing a Writer.
type Writer struct {
	impl      strategyImpl
	closeOnce sync.Once
	closed    atomic.Bool
}

// config holds resolved option values. Option errors are
// captured here and surfaced from [New], so a bad option never
// silently succeeds into an unexpected strategy.
type config struct {
	strategy  Strategy
	ringDepth uint32
	logger    *slog.Logger
	err       error // set by an option if validation fails
}

// Option configures [New]. All options are optional; [New] with
// zero options uses sensible defaults.
type Option func(*config)

// WithStrategy forces a specific [Strategy]. Passing
// [StrategyIouring] on a host without io_uring causes [New] to
// return an error wrapping [ErrUnsupported]. Passing
// [StrategyWritev] forces the writev path even on io_uring-capable
// hosts — useful for benchmarking and A/B testing. The default is
// [StrategyAuto].
//
// Passing an out-of-range Strategy value is a programmer error;
// [New] will return an error that does not wrap any sentinel.
func WithStrategy(s Strategy) Option {
	return func(c *config) { c.strategy = s }
}

// WithRingDepth sets the io_uring submission-queue depth. Must
// be a power of two between 1 and 4096 inclusive. Ignored by
// strategies other than [StrategyIouring]. Defaults to 16.
//
// Passing an out-of-range or non-power-of-two value is a
// programmer error; [New] will surface the validation error
// unwrapped.
func WithRingDepth(n uint32) Option {
	return func(c *config) {
		if n == 0 || n > 4096 || (n&(n-1)) != 0 {
			c.err = fmt.Errorf("iouring: WithRingDepth: entries must be a power of two in [1, 4096] (got %d)", n)
			return
		}
		c.ringDepth = n
	}
}

// WithLogger configures a [slog.Logger] that receives exactly
// one log line at construction indicating the selected strategy.
// Nil (the default) disables logging. Writers never log on the
// hot path — the logger is used at construction only.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// New constructs a [Writer] with the given options. The default
// strategy is [StrategyAuto], which prefers io_uring on capable
// Linux hosts and falls back to writev(2) on other Unix
// platforms. On platforms without any vectored-write support
// (currently Windows), New returns an error wrapping
// [ErrUnsupported].
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
	if cfg.err != nil {
		return nil, cfg.err
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
// Writev is NOT safe for concurrent use and must not race with
// [Writer.Close]. Zero-length elements within bufs are skipped;
// all-empty bufs return (0, nil) without touching the kernel.
// len(bufs) must not exceed [MaxIovecs].
func (w *Writer) Writev(fd int, bufs [][]byte) (int, error) {
	if w.closed.Load() {
		return 0, ErrClosed
	}
	return w.impl.writev(fd, bufs)
}

// Write is a single-buffer convenience wrapper around
// [Writer.Writev].
func (w *Writer) Write(fd int, buf []byte) (int, error) {
	return w.Writev(fd, [][]byte{buf})
}

// Strategy reports the negotiated strategy this [Writer] is
// using. The result is stable for the Writer's lifetime and is
// one of [StrategyIouring] or [StrategyWritev] — never
// [StrategyAuto].
func (w *Writer) Strategy() Strategy {
	return w.impl.kind()
}

// Close releases any resources held by the [Writer]. Close is
// idempotent and safe to call concurrently with itself. Calling
// Close concurrently with [Writer.Writev] / [Writer.Write] is
// undefined behaviour; callers must serialise.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		err = w.impl.close()
	})
	return err
}

// ---------------------------------------------------------------
// Package-level convenience — zero-ceremony path
// ---------------------------------------------------------------

// Package-level default writer.
//
// defaultOnce guards one-shot initialisation. defaultMu
// serialises subsequent calls to the underlying (non-concurrent-
// safe) Writer. Once defaultErr is set by the one-shot init it
// is permanent for the process lifetime; callers needing a
// recoverable path should construct their own [Writer] with
// [New].
var (
	defaultOnce   sync.Once
	defaultWriter *Writer
	defaultErr    error
	defaultMu     sync.Mutex
)

// initDefault resolves the process-wide default writer.
func initDefault() {
	defaultWriter, defaultErr = New()
}

// Writev writes bufs to fd using the process-wide default
// [Writer]. Safe for concurrent use via an internal mutex on
// the default writer. For the uncontended case the mutex
// overhead is ~20 ns; under heavy contention, construct a
// dedicated [Writer] per producer goroutine with [New].
//
// If the platform has no vectored-write support, Writev returns
// an error wrapping [ErrUnsupported]. Writev does not return
// [ErrClosed] — the default writer is never closed.
func Writev(fd int, bufs [][]byte) (int, error) {
	defaultOnce.Do(initDefault)
	if defaultErr != nil {
		return 0, defaultErr
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	return defaultWriter.Writev(fd, bufs)
}

// IouringSupported reports whether the [StrategyIouring] path
// is available on this host. The first call performs a probe
// syscall (~200 μs) and caches the result. Callers using the
// default [StrategyAuto] do NOT need to call this — [New] and
// the package-level [Writev] handle negotiation internally.
//
// On non-Linux platforms, IouringSupported always returns false.
func IouringSupported() bool { return iouringSupported() }
