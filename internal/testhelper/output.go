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
	"time"

	"github.com/axonops/go-audit"
)

// Compile-time assertion: MockOutput satisfies audit.Output.
var _ audit.Output = (*MockOutput)(nil)

// MockOutput is a thread-safe in-memory output that captures written
// events for assertion.
type MockOutput struct {
	WriteErr error
	WriteCh  chan struct{}
	name     string
	events   [][]byte
	mu       sync.Mutex
	closed   bool
}

// NewMockOutput creates a MockOutput with the given name.
func NewMockOutput(name string) *MockOutput {
	return &MockOutput{
		name:    name,
		WriteCh: make(chan struct{}, 1000),
	}
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
	select {
	case m.WriteCh <- struct{}{}:
	default:
	}
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

// WaitForEvents polls until at least n events are captured or timeout expires.
func (m *MockOutput) WaitForEvents(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if m.EventCount() >= n {
			return true
		}
		select {
		case <-m.WriteCh:
		case <-deadline:
			return false
		}
	}
}

// IsClosed returns whether Close has been called.
func (m *MockOutput) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}
