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

	"github.com/axonops/audit"
)

var _ audit.Output = (*Recorder)(nil)

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
	// Fields contains all non-framework fields. Note: numeric values
	// are stored as float64 due to JSON round-tripping. Use
	// [RecordedEvent.IntField] for int assertions.
	Fields map[string]any
	// RawJSON is the original serialised bytes for format-level assertions.
	RawJSON []byte
	// ParseErr holds any error from JSON deserialisation of the raw bytes.
	// When non-nil, EventType, Severity, Timestamp, and Fields are all
	// zero-valued. Tests SHOULD assert ParseErr == nil before inspecting
	// other fields to avoid masking serialisation bugs.
	ParseErr error
}

// Field returns the value of the named field, or nil if not present.
func (e RecordedEvent) Field(key string) any { //nolint:gocritic // value receiver required for fmt.GoStringer on non-addressable values
	return e.Fields[key]
}

// StringField returns the value of the named field as a string.
// Returns the empty string if the key is missing or the value is not
// a string.
func (e RecordedEvent) StringField(key string) string { //nolint:gocritic // value receiver for consistency
	v, _ := e.Fields[key].(string)
	return v
}

// IntField returns the value of the named field as an int. JSON
// round-tripping stores all numbers as float64, so this method
// handles the float64→int coercion transparently.
func (e RecordedEvent) IntField(key string) int { //nolint:gocritic // value receiver for consistency
	switch v := e.Fields[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return 0
	}
}

// FloatField returns the value of the named field as a float64.
// Returns 0 if the key is missing or the value is not numeric.
func (e RecordedEvent) FloatField(key string) float64 { //nolint:gocritic // value receiver for consistency
	v, _ := e.Fields[key].(float64)
	return v
}

// UserFields returns a copy of the event's fields with framework
// fields removed (event_category, app_name, host, timezone, pid,
// duration_ms, _hmac, _hmac_v). This is useful for count assertions
// where framework fields would inflate the total.
func (e RecordedEvent) UserFields() map[string]any { //nolint:gocritic // value receiver for consistency
	out := make(map[string]any, len(e.Fields))
	for k, v := range e.Fields {
		if isFrameworkField(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// HasField reports whether the event has a field with the given key
// and value. Comparison uses [reflect.DeepEqual].
func (e RecordedEvent) HasField(key string, want any) bool { //nolint:gocritic // value receiver required for consistency with Field/GoString
	got, ok := e.Fields[key]
	if !ok {
		return false
	}
	return reflect.DeepEqual(got, want)
}

// GoString returns a human-readable representation of the event,
// suitable for test failure messages.
func (e RecordedEvent) GoString() string { //nolint:gocritic // value receiver required for fmt.GoStringer on non-addressable values
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
// [audit.WithNamedOutput] when composing an auditor manually. For the
// common case, use [New] or [NewQuick] instead.
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

// Events returns a snapshot of all recorded events in drain order.
// The returned slice is a copy; later Reset calls do not affect it.
// Call after [audit.Auditor.Close] to ensure all events have been processed.
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

// Reset clears all recorded events. The underlying auditor remains
// open and functional. Use Reset between sub-tests to isolate
// assertions without creating a new auditor.
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

// frameworkFields are fields added by the audit framework (not by the
// consumer). These are filtered out by [RecordedEvent.UserFields].
var frameworkFields = map[string]bool{
	"event_category": true,
	"app_name":       true,
	"host":           true,
	"timezone":       true,
	"pid":            true,
	"duration_ms":    true,
	"_hmac":          true,
	"_hmac_v":        true,
}

func isFrameworkField(key string) bool {
	return frameworkFields[key]
}

// parseEvent deserialises a JSON event into a RecordedEvent.
func parseEvent(data []byte) RecordedEvent {
	raw := make([]byte, len(data))
	copy(raw, data)

	re := RecordedEvent{
		RawJSON: raw,
		Fields:  make(map[string]any),
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		re.ParseErr = err
		return re
	}

	// Extract framework fields.
	if et, ok := m["event_type"].(string); ok {
		re.EventType = et
	}
	if sev, ok := m["severity"].(float64); ok {
		re.Severity = int(sev)
	}
	switch ts := m["timestamp"].(type) {
	case string:
		re.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	case float64:
		re.Timestamp = time.UnixMilli(int64(ts))
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
