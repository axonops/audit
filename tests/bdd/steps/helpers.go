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

package steps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// testHTTPClient is used for all test helper HTTP calls. The short
// timeout prevents 30s hangs when Docker infrastructure isn't running.
var testHTTPClient = &http.Client{Timeout: 2 * time.Second} //nolint:gochecknoglobals // test infrastructure

// marker generates a unique crypto-random hex string for event correlation.
func marker(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// resetWebhookReceiver calls POST /reset to clear stored events and config.
// Uses testHTTPClient (2s timeout) to avoid 30s hangs when Docker isn't up.
func resetWebhookReceiver(baseURL string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/reset", http.NoBody)
	if err != nil {
		return fmt.Errorf("webhook reset request: %w", err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook reset: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("webhook reset: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// parseJSONLines parses newline-delimited JSON from raw bytes.
func parseJSONLines(data []byte) ([]map[string]any, error) {
	lines := strings.Split(string(data), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("invalid JSON line: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

// eventContainsAllFields checks if the event map contains all expected
// field/value pairs. Returns true on match, or false with a description
// of the first mismatch.
func eventContainsAllFields(event map[string]any, expected map[string]string) (match bool, mismatch string) {
	for field, want := range expected {
		got, exists := event[field]
		if !exists {
			return false, fmt.Sprintf("field %q not found in event", field)
		}
		gotStr := fmt.Sprintf("%v", got)
		if want != gotStr {
			return false, fmt.Sprintf("field %q: want %q, got %q", field, want, gotStr)
		}
	}
	return true, ""
}

// --- Mock metrics ---

// MockMetrics captures all metrics calls for assertion in BDD steps.
// Thread-safe: the drain goroutine calls metrics methods concurrently.
type MockMetrics struct {
	Events            map[string]int // "output:status" -> count
	OutputErrors      map[string]int
	OutputFiltered    map[string]int
	ValidationErrors  map[string]int
	Filtered          map[string]int
	SerializationErrs map[string]int
	mu                sync.Mutex
	BufferDrops       int
}

// NewMockMetrics creates a fresh MockMetrics.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		Events:            make(map[string]int),
		OutputErrors:      make(map[string]int),
		OutputFiltered:    make(map[string]int),
		ValidationErrors:  make(map[string]int),
		Filtered:          make(map[string]int),
		SerializationErrs: make(map[string]int),
	}
}

// RecordEvent satisfies audit.Metrics.
func (m *MockMetrics) RecordEvent(output, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events[output+":"+status]++
}

// RecordOutputError satisfies audit.Metrics.
func (m *MockMetrics) RecordOutputError(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OutputErrors[output]++
}

// RecordOutputFiltered satisfies audit.Metrics.
func (m *MockMetrics) RecordOutputFiltered(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OutputFiltered[output]++
}

// RecordValidationError satisfies audit.Metrics.
func (m *MockMetrics) RecordValidationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidationErrors[eventType]++
}

// RecordFiltered satisfies audit.Metrics.
func (m *MockMetrics) RecordFiltered(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Filtered[eventType]++
}

// RecordSerializationError satisfies audit.Metrics.
func (m *MockMetrics) RecordSerializationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SerializationErrs[eventType]++
}

// RecordBufferDrop satisfies audit.Metrics.
func (m *MockMetrics) RecordBufferDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BufferDrops++
}
