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

// Strategy identifies the vectored-write path a [Writer] uses.
// The concrete strategy is chosen at construction and is stable
// for the Writer's lifetime; callers retrieve it with
// [Writer.Strategy].
type Strategy int

const (
	// StrategyAuto requests the best available strategy at
	// construction. It is the default when no [WithStrategy]
	// option is supplied. After construction, [Writer.Strategy]
	// returns the strategy that was actually selected
	// ([StrategyIouring] or [StrategyWritev]), never
	// StrategyAuto.
	StrategyAuto Strategy = iota

	// StrategyIouring is the Linux io_uring fast path. Requires
	// kernel 5.5+ with IORING_FEAT_NODROP. Passing this to
	// [WithStrategy] and calling [New] on an unsupported host
	// returns an error wrapping [ErrUnsupported].
	StrategyIouring

	// StrategyWritev is the portable writev(2) path. Available
	// on all Unix platforms (Linux, Darwin, the *BSDs). Passing
	// this to [WithStrategy] forces the writev path even on
	// io_uring-capable hosts — useful for benchmarking and
	// testing the fallback path.
	StrategyWritev

	// StrategyUnsupported indicates no vectored-write path is
	// available on the current platform. [New] returns
	// [ErrUnsupported] for this strategy; it is exposed only as
	// the return value of [Writer.Strategy] on platforms where
	// construction would fail.
	StrategyUnsupported
)

// String returns a stable lowercase name for the strategy. These
// strings are part of the library's public contract — consumers
// log and alert on them.
func (s Strategy) String() string {
	switch s {
	case StrategyAuto:
		return "auto"
	case StrategyIouring:
		return "iouring"
	case StrategyWritev:
		return "writev"
	case StrategyUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

// strategyImpl is the internal interface every platform-specific
// strategy implements. It is unexported because the concrete
// implementations are build-tagged and callers should access them
// only through [Writer].
type strategyImpl interface {
	writev(fd int, bufs [][]byte) (int, error)
	close() error
	kind() Strategy
}
