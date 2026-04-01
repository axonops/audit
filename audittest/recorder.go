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

package audittest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

// RecordedEvent is a single captured audit event with structured access
// to its fields. Events are captured after serialisation and
// deserialised back into structured form.
//
// Fields contains the event's non-framework field values. Values
// follow encoding/json conventions: numbers are float64, nested
// objects are map[string]interface{}, arrays are []interface{}.
type RecordedEvent struct { //nolint:govet // readability over alignment
	// EventType is the event type name (e.g., "user_create").
	EventType string
	// Severity is the resolved severity (0-10).
	Severity int
	// Timestamp is the event timestamp set by the drain goroutine.
	Timestamp time.Time
	// Fields contains all non-framework fields.
	Fields map[string]any
	// RawJSON is the original serialised bytes for format-level assertions.
	RawJSON []byte
}

// Field returns the value of the named field, or nil if not present.
func (e *RecordedEvent) Field(key string) any {
	return e.Fields[key]
}

// HasField reports whether the event has a field with the given key
// and value. Comparison uses [reflect.DeepEqual].
func (e *RecordedEvent) HasField(key string, want any) bool {
	got, ok := e.Fields[key]
	if !ok {
		return false
	}
	return reflect.DeepEqual(got, want)
}

// GoString returns a human-readable representation of the event,
// suitable for test failure messages.
func (e *RecordedEvent) GoString() string {
	return fmt.Sprintf("RecordedEvent{Type: %q, Severity: %d, Fields: %v}",
		e.EventType, e.Severity, e.Fields)
}

// Recorder implements [audit.Output] and captures events in memory
// for assertion. It is safe for concurrent use by the drain goroutine
// (writing) and the test goroutine (reading).
type Recorder struct {
	events []RecordedEvent
	mu     sync.Mutex
}

// NewRecorder creates a Recorder. Use it with [audit.WithOutputs] or
// [audit.WithNamedOutput] when composing a logger manually. For the
// common case, use [NewLogger] or [NewLoggerQuick] instead.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Write implements [audit.Output]. It parses the serialised JSON event
// and appends it to the recorded events.
func (r *Recorder) Write(data []byte) error {
	re := parseEvent(data)
	r.mu.Lock()
	r.events = append(r.events, re)
	r.mu.Unlock()
	return nil
}

// Name implements [audit.Output].
func (r *Recorder) Name() string { return "recorder" }

// Close implements [audit.Output]. It is a no-op — the Recorder does
// not own any resources.
func (r *Recorder) Close() error { return nil }

// Events returns all recorded events in drain order. Call after
// [audit.Logger.Close] to ensure all events have been processed.
func (r *Recorder) Events() []RecordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]RecordedEvent, len(r.events))
	copy(cp, r.events)
	return cp
}

// FindByType returns all recorded events matching the given event type.
func (r *Recorder) FindByType(eventType string) []RecordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []RecordedEvent
	for _, e := range r.events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}

// Count returns the number of recorded events.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// Reset clears all recorded events. The underlying logger remains
// open and functional. Use Reset between sub-tests to isolate
// assertions without creating a new logger.
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.events = r.events[:0]
	r.mu.Unlock()
}

// GoString returns a human-readable summary of all recorded events,
// suitable for test failure messages.
func (r *Recorder) GoString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return "Recorder{events: []}"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Recorder{events: [\n")
	for i, e := range r.events {
		fmt.Fprintf(&b, "  [%d] %#v\n", i, e)
	}
	b.WriteString("]}")
	return b.String()
}

// parseEvent deserialises a JSON event into a RecordedEvent.
func parseEvent(data []byte) RecordedEvent {
	raw := make([]byte, len(data))
	copy(raw, data)

	var m map[string]any
	_ = json.Unmarshal(data, &m) // best-effort parse

	re := RecordedEvent{
		RawJSON: raw,
		Fields:  make(map[string]any),
	}

	// Extract framework fields.
	if et, ok := m["event_type"].(string); ok {
		re.EventType = et
	}
	if sev, ok := m["severity"].(float64); ok {
		re.Severity = int(sev)
	}
	if ts, ok := m["timestamp"].(string); ok {
		re.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	}

	// Copy non-framework fields.
	for k, v := range m {
		switch k {
		case "event_type", "severity", "timestamp":
			continue
		default:
			re.Fields[k] = v
		}
	}

	return re
}
