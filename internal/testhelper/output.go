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

package testhelper

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
)

// Compile-time assertion: MockOutput satisfies audit.Output.
var _ audit.Output = (*MockOutput)(nil)

// Compile-time assertion: NoopOutput satisfies audit.Output.
var _ audit.Output = (*NoopOutput)(nil)

// NoopOutput is a true zero-cost output for benchmarks: it does NOT
// copy or inspect the bytes, only increments an atomic counter. Use
// this in pipeline benchmarks that want to measure the audit path
// without contamination from output-side allocations or copies.
//
// NoopOutput honours the [audit.Output.Write] retention contract by
// trivially not retaining anything.
type NoopOutput struct {
	name   string
	writes atomic.Uint64
}

// NewNoopOutput creates a NoopOutput with the given name.
func NewNoopOutput(name string) *NoopOutput {
	return &NoopOutput{name: name}
}

// Write counts the call and returns nil. The data bytes are never read.
func (n *NoopOutput) Write(_ []byte) error {
	n.writes.Add(1)
	return nil
}

// Close is a noop for NoopOutput.
func (*NoopOutput) Close() error { return nil }

// Name returns the configured name.
func (n *NoopOutput) Name() string { return n.name }

// Writes returns the number of Write calls observed.
func (n *NoopOutput) Writes() uint64 { return n.writes.Load() }

// MockOutput is a thread-safe in-memory output that captures written
// events for assertion.
//
// Synchronisation between Write and WaitForEvents uses a sync.Cond
// keyed off mu rather than a buffered signal channel. The earlier
// 1000-slot WriteCh design (#567) silently dropped signals once the
// channel filled, which caused WaitForEvents to time out on
// high-volume scenarios (10k+ events) even though every event
// reached the output. Cond.Broadcast cannot drop signals: every
// Write notifies every Wait, and the predicate check on EventCount
// guarantees correctness.
type MockOutput struct {
	WriteErr error
	cond     *sync.Cond
	name     string
	events   [][]byte
	mu       sync.Mutex
	closed   bool
}

// NewMockOutput creates a MockOutput with the given name.
func NewMockOutput(name string) *MockOutput {
	m := &MockOutput{name: name}
	m.cond = sync.NewCond(&m.mu)
	return m
}

func (m *MockOutput) Write(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.WriteErr != nil {
		return m.WriteErr
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	m.events = append(m.events, cp)
	m.cond.Broadcast()
	return nil
}

func (m *MockOutput) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *MockOutput) Name() string { return m.name }

// SetWriteErr sets the error returned by subsequent Write calls.
func (m *MockOutput) SetWriteErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.WriteErr = err
}

// GetEvents returns a copy of all captured events.
func (m *MockOutput) GetEvents() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([][]byte, len(m.events))
	copy(cp, m.events)
	return cp
}

// EventCount returns the number of captured events.
func (m *MockOutput) EventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// GetEvent unmarshals the i-th captured event as a map.
func (m *MockOutput) GetEvent(i int) map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result map[string]interface{}
	if err := json.Unmarshal(m.events[i], &result); err != nil {
		panic("unmarshal event: " + err.Error())
	}
	return result
}

// WaitForEvents waits until at least n events are captured or
// timeout expires. The implementation uses sync.Cond.Wait under
// the same mutex that protects the events slice, so the count
// check and the wait are atomic — no signal can be dropped between
// EventCount and the next Wait, and Write's Broadcast is observed
// by every concurrent waiter.
//
// Returns true if EventCount reached n before the deadline; false
// on timeout.
func (m *MockOutput) WaitForEvents(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Spawn a watchdog goroutine that broadcasts the cond when
	// the deadline expires so the Wait below unblocks. Without
	// this, sync.Cond.Wait has no built-in timeout.
	timer := time.AfterFunc(timeout, func() {
		m.mu.Lock()
		m.cond.Broadcast()
		m.mu.Unlock()
	})
	defer timer.Stop()

	for len(m.events) < n {
		if time.Now().After(deadline) {
			return false
		}
		m.cond.Wait()
	}
	return true
}

// IsClosed returns whether Close has been called.
func (m *MockOutput) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}
