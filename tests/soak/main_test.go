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

//go:build soak

// Package soak_test runs the long-running mixed-output workload that
// exercises the audit hot path for `SOAK_DURATION` (default 12h) before
// each release tag. It is gated by the `soak` build tag so it never
// runs under `go test ./...`. Invoke via `make soak` (#573).
package soak_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak.VerifyTestMain so the 12-hour run terminates
// with a non-zero exit if any goroutine outlives the soak driver.
// Ignorelist matches tests/integration/fanout_test.go: the standard
// net/http.persistConn read/write loops are kept alive by the
// httptest.Server's connection pool and are not leaks.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}
