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

//go:build unix

package iouring

import "fmt"

// chooseStrategy resolves a Writer configuration into a concrete
// strategyImpl. It is the single point where the StrategyAuto
// negotiation lives.
//
// Precedence (StrategyAuto):
//  1. io_uring if the kernel supports it and the platform has
//     an io_uring binding (Linux only).
//  2. writev(2) on every Unix platform, including Linux without
//     io_uring or with an io_uring_setup failure.
//
// Forced strategies skip the negotiation and fail cleanly when
// the requested path is unavailable.
func chooseStrategy(cfg *config) (strategyImpl, error) {
	switch cfg.strategy {
	case StrategyIouring:
		impl, err := tryIouring(cfg.ringDepth)
		if err != nil {
			return nil, err
		}
		return impl, nil

	case StrategyWritev:
		return newWritevStrategy(), nil

	case StrategyAuto:
		// Prefer io_uring; fall back to writev on failure.
		if impl, err := tryIouring(cfg.ringDepth); err == nil {
			return impl, nil
		}
		return newWritevStrategy(), nil

	default:
		return nil, fmt.Errorf("iouring: invalid Strategy value %d", cfg.strategy)
	}
}
