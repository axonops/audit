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

//go:build !unix

package iouring

import "fmt"

// chooseStrategy on non-Unix platforms always returns an error
// wrapping [ErrUnsupported]. The concrete cause (Windows, Plan 9,
// etc.) is named in the wrapped message to keep diagnostics
// actionable.
func chooseStrategy(_ *config) (strategyImpl, error) {
	return nil, fmt.Errorf("iouring: vectored-write unavailable on this platform: %w", ErrUnsupported)
}

// iouringSupported on non-Unix platforms always returns false.
func iouringSupported() bool { return false }
