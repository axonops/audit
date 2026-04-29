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

package webhook_test

// Tests for the mockMetrics / mockOutputMetrics waitFor* helpers
// themselves. The helpers are the synchronisation primitive every
// metric-driven test relies on (#705 family fix); a bug here would
// silently mask flakes elsewhere.

import (
	"testing"
	"time"

	"github.com/axonops/audit"
)

// TestMockMetrics_WaitForEventCount_PredicateAlreadyTrue verifies the
// helper returns immediately when the count is already at or above
// the requested level, without sleeping or blocking on Wait.
func TestMockMetrics_WaitForEventCount_PredicateAlreadyTrue(t *testing.T) {
	m := newMockMetrics()
	m.RecordDelivery("out", audit.EventSuccess)
	m.RecordDelivery("out", audit.EventSuccess)

	start := time.Now()
	m.waitForEventCount(t, "out", audit.EventSuccess, 2, 5*time.Second)
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("waitForEventCount blocked unnecessarily: %v", elapsed)
	}
}

// TestMockMetrics_WaitForEventCount_BroadcastWakesWaiter verifies a
// goroutine that records the deciding event after the test goroutine
// is already blocked in Wait correctly wakes the wait.
func TestMockMetrics_WaitForEventCount_BroadcastWakesWaiter(t *testing.T) {
	m := newMockMetrics()

	go func() {
		// Slight delay so the main goroutine reaches Wait first.
		time.Sleep(10 * time.Millisecond)
		m.RecordDelivery("out", audit.EventSuccess)
	}()

	m.waitForEventCount(t, "out", audit.EventSuccess, 1, 2*time.Second)
}

// TestMockOutputMetrics_WaitForDrops_PredicateAlreadyTrue mirrors the
// mockMetrics counterpart for the OutputMetrics waitForDrops helper.
func TestMockOutputMetrics_WaitForDrops_PredicateAlreadyTrue(t *testing.T) {
	m := newMockOutputMetrics()
	m.RecordDrop()

	start := time.Now()
	m.waitForDrops(t, 1, 5*time.Second)
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("waitForDrops blocked unnecessarily: %v", elapsed)
	}
}

// TestMockOutputMetrics_WaitForDrops_BroadcastWakesWaiter verifies a
// drop recorded after the wait begins wakes the waiter.
func TestMockOutputMetrics_WaitForDrops_BroadcastWakesWaiter(t *testing.T) {
	m := newMockOutputMetrics()

	go func() {
		time.Sleep(10 * time.Millisecond)
		m.RecordDrop()
		m.RecordDrop()
	}()

	m.waitForDrops(t, 2, 2*time.Second)
}

// The timeout-fires-Fatal path is exercised implicitly any time a
// real test fails; pinning it here would require either a fake
// testing.T or wrapping the helper signatures around testing.TB.
// The watchdog timer + deadline-check loop is small enough that
// the broadcast-wakes-waiter and predicate-already-true tests
// above are a sufficient correctness gate.
