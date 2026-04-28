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

package testhelper_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/internal/testhelper"
)

// TestMockOutput_WaitForN_HighVolume drives 10000 events through
// MockOutput from concurrent goroutines and asserts WaitForEvents
// returns true. Pre-#567 the buffered WriteCh dropped signals at
// 1000+ events; this test pins the post-fix sync.Cond contract
// where every Write broadcasts and no signal is ever dropped.
// (#567 AC#1, AC#3).
func TestMockOutput_WaitForN_HighVolume(t *testing.T) {
	t.Parallel()
	const total = 10_000
	out := testhelper.NewMockOutput("high-volume")

	var wg sync.WaitGroup
	const writers = 8
	per := total / writers
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := out.Write([]byte(fmt.Sprintf(`{"w":%d,"i":%d}`, workerID, i))); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	// All writes complete; WaitForEvents must observe them.
	assert.True(t, out.WaitForEvents(total, 5*time.Second),
		"WaitForEvents must return true once N events arrive — even at high volume")
	assert.Equal(t, total, out.EventCount(),
		"every enqueued event must be captured")
}

// TestMockOutput_WaitForEvents_ExactN proves that WaitForEvents
// returns true exactly when EventCount reaches the requested N,
// neither prematurely nor late. (#567 AC#2).
func TestMockOutput_WaitForEvents_ExactN(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("exact-n")
	const n = 5

	// Spawn the waiter first; it must block until exactly N
	// events arrive.
	done := make(chan bool, 1)
	go func() {
		done <- out.WaitForEvents(n, 2*time.Second)
	}()

	// Send N-1 events; the waiter must NOT return yet.
	for i := 0; i < n-1; i++ {
		require.NoError(t, out.Write([]byte("e")))
	}
	select {
	case <-done:
		t.Fatalf("WaitForEvents returned before N events arrived")
	case <-time.After(50 * time.Millisecond):
		// expected — waiter is still blocked
	}

	// Send the Nth event; waiter must wake and return true.
	require.NoError(t, out.Write([]byte("e")))
	select {
	case ok := <-done:
		assert.True(t, ok, "WaitForEvents must return true once N events arrive")
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForEvents did not return within 2 s after Nth event arrived")
	}
}

// TestMockOutput_WaitForEvents_TimeoutPath proves that
// WaitForEvents returns false on timeout when fewer than N events
// arrive. The previous channel-based implementation could deadlock
// if the buffer was full and no further signal could arrive; the
// sync.Cond + AfterFunc broadcast keeps the timeout path live.
// (#567 AC#3).
func TestMockOutput_WaitForEvents_TimeoutPath(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("timeout")
	require.NoError(t, out.Write([]byte("only-one")))

	start := time.Now()
	got := out.WaitForEvents(2, 100*time.Millisecond)
	elapsed := time.Since(start)
	assert.False(t, got, "WaitForEvents must return false when N is not reached")
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond,
		"WaitForEvents must wait at least the configured timeout")
	assert.Less(t, elapsed, 1*time.Second,
		"WaitForEvents must not wait significantly past the timeout")
}
