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
//
// Note (#894): the waitForEventCount tests were removed alongside
// audit.Metrics.RecordDelivery / audit.EventStatus. The remaining
// OutputMetrics-based waitFor helpers carry the same synchronisation
// guarantees.

import (
	"testing"
	"time"
)

// TestMockOutputMetrics_WaitForDrops_PredicateAlreadyTrue mirrors the
// mockMetrics counterpart for the OutputMetrics waitForDrops helper.
func TestMockOutputMetrics_WaitForDrops_PredicateAlreadyTrue(t *testing.T) {
	m := newMockOutputMetrics()
	m.RecordDrop(1)

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
		m.RecordDrop(1)
		m.RecordDrop(1)
	}()

	m.waitForDrops(t, 2, 2*time.Second)
}

// The timeout-fires-Fatal path is exercised implicitly any time a
// real test fails; pinning it here would require either a fake
// testing.T or wrapping the helper signatures around testing.TB.
// The watchdog timer + deadline-check loop is small enough that
// the broadcast-wakes-waiter and predicate-already-true tests
// above are a sufficient correctness gate.
