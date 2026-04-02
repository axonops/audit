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

package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

var testDef = &audit.EventDef{
	Required: []string{"outcome", "actor_id", "subject"},
	Optional: []string{"schema_type", "version"},
}

// ---------------------------------------------------------------------------
// JSONFormatter tests
// ---------------------------------------------------------------------------

func TestJSONFormatter_ValidOutput(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	// Must end with newline.
	assert.True(t, data[len(data)-1] == '\n', "output must end with newline")

	// Must be valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "schema_register", m["event_type"])
	assert.Equal(t, "success", m["outcome"])
	assert.Equal(t, "alice", m["actor_id"])
	assert.NotEmpty(t, m["timestamp"])
}

func TestJSONFormatter_FieldOrdering(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
		"version":     1,
	}, testDef, nil)
	require.NoError(t, err)

	raw := string(data)
	// Framework fields first.
	tsIdx := strings.Index(raw, `"timestamp"`)
	etIdx := strings.Index(raw, `"event_type"`)
	// Required fields sorted: actor_id, outcome, subject.
	aiIdx := strings.Index(raw, `"actor_id"`)
	oIdx := strings.Index(raw, `"outcome"`)
	sIdx := strings.Index(raw, `"subject"`)
	// Optional fields sorted: schema_type, version.
	stIdx := strings.Index(raw, `"schema_type"`)
	vIdx := strings.Index(raw, `"version"`)

	assert.Less(t, tsIdx, etIdx, "timestamp before event_type")
	assert.Less(t, etIdx, aiIdx, "event_type before required fields")
	assert.Less(t, aiIdx, oIdx, "actor_id before outcome (sorted)")
	assert.Less(t, oIdx, sIdx, "outcome before subject (sorted)")
	assert.Less(t, sIdx, stIdx, "required before optional")
	assert.Less(t, stIdx, vIdx, "schema_type before version (sorted)")
}

func TestJSONFormatter_DurationMarshalling(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"duration_ms": 1500 * time.Millisecond,
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// duration_ms should be int64 milliseconds, not Go duration string.
	assert.Equal(t, float64(1500), m["duration_ms"])
}

func TestJSONFormatter_DurationAsInt(t *testing.T) {
	// duration_ms as a plain int (not time.Duration) must not be dropped.
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"duration_ms": 250,
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, float64(250), m["duration_ms"], "duration_ms as int must not be dropped")
}

func TestCEFFormatter_DurationAsInt(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":     "ok",
		"duration_ms": 500,
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"duration_ms"},
	}, nil)
	require.NoError(t, err)

	// Non-Duration duration_ms should appear as a regular field, not be dropped.
	line := string(data)
	assert.Contains(t, line, "duration_ms=500", "duration_ms as int must not be dropped in CEF")
}

func TestCEFFormatter_SeverityClamped(t *testing.T) {
	tests := []struct {
		name     string
		severity int
		want     int
	}{
		{"below zero", -5, 0},
		{"above ten", 42, 10},
		{"in range", 7, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &audit.CEFFormatter{
				Vendor: "V", Product: "P", Version: "1",
				SeverityFunc: func(string) int { return tt.severity },
			}
			data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
				Required: []string{"outcome"},
			}, nil)
			require.NoError(t, err)
			assert.Contains(t, string(data), fmt.Sprintf("|%d|", tt.want))
		})
	}
}

func TestJSONFormatter_TimestampRFC3339Nano(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string for RFC3339Nano")
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err)
	assert.Equal(t, testTime, parsed)
}

func TestJSONFormatter_TimestampUnixMillis(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(float64)
	require.True(t, ok, "timestamp should be a number for unix_ms")
	assert.Equal(t, float64(testTime.UnixMilli()), ts)
}

func TestJSONFormatter_UnrecognisedTimestampFormat(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampFormat("bogus")}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m), "output must be valid JSON")

	ts, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string (RFC3339Nano fallback)")
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err, "timestamp should parse as RFC3339Nano")
	assert.Equal(t, testTime, parsed)
}

func TestJSONFormatter_OmitEmptyTrue(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: true}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type and version not provided
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.False(t, has, "OmitEmpty should omit missing optional fields")
}

func TestJSONFormatter_OmitEmptyFalse(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.True(t, has, "OmitEmpty=false should include all registered fields")
	assert.Nil(t, m["schema_type"], "missing optional should be null")
}

func TestJSONFormatter_UnicodeValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
		"name":    "hello \u4e16\u754c",
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"name"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Contains(t, m["name"], "\u4e16\u754c")
}

func TestJSONFormatter_LongValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	longVal := strings.Repeat("x", 64*1024) // 64KB
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": longVal,
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, longVal, m["outcome"])
}

func TestJSONFormatter_NilFields(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", nil, &audit.EventDef{}, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "ev", m["event_type"])
}

func TestJSONFormatter_NewlineInjection(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success\n{\"injected\":true}",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// The output must be a single line (one trailing newline only).
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second line")
}

func TestJSONFormatter_ExtraFieldsSorted(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"zebra":   "z",
		"alpha":   "a",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	raw := string(data)
	aIdx := strings.Index(raw, `"alpha"`)
	zIdx := strings.Index(raw, `"zebra"`)
	assert.Less(t, aIdx, zIdx, "extra fields should be sorted")
}

// ---------------------------------------------------------------------------
// CEFFormatter tests
// ---------------------------------------------------------------------------

func TestCEFFormatter_ValidHeader(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef, nil)
	require.NoError(t, err)

	line := string(data)
	assert.True(t, strings.HasPrefix(line, "CEF:0|TestVendor|TestProduct|1.0|schema_register|"))
	assert.True(t, strings.HasSuffix(line, "\n"), "must end with newline")

	// Should be a single line.
	lines := strings.Split(strings.TrimSuffix(line, "\n"), "\n")
	assert.Equal(t, 1, len(lines))
}

func TestCEFFormatter_DefaultSeverity(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// Default severity is 5.
	assert.Contains(t, string(data), "|ev|5|")
}

func TestCEFFormatter_CustomSeverity(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		SeverityFunc: func(et string) int {
			if et == "auth_failure" {
				return 8
			}
			return 3
		},
	}
	data, err := f.Format(testTime, "auth_failure", audit.Fields{"outcome": "fail"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "|auth_failure|8|")
}

func TestCEFFormatter_DefaultDescription(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "my_event", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	// Default description is the event type itself.
	assert.Contains(t, string(data), "|my_event|my_event|")
}

func TestCEFFormatter_CustomDescription(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		DescriptionFunc: func(et string) string {
			return "Custom: " + et
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "|Custom: ev|")
}

func TestCEFFormatter_ExtensionFields(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	// actor_id maps to suser via DefaultCEFFieldMapping.
	assert.Contains(t, line, "suser=alice")
	assert.Contains(t, line, "outcome=success")
}

func TestCEFFormatter_CustomFieldMapping(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "customActor",
			"outcome":  "result",
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "customActor=alice")
	assert.Contains(t, line, "result=success")
	assert.NotContains(t, line, "suser=")
}

func TestCEFFormatter_CustomFieldMappingMergesDefaults(t *testing.T) {
	// Custom mapping overrides actor_id but source_ip should still
	// use the default mapping to "src".
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"actor_id": "customActor",
		},
	}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":   "success",
		"actor_id":  "alice",
		"source_ip": "10.0.0.1",
	}, &audit.EventDef{
		Required: []string{"outcome", "actor_id"},
		Optional: []string{"source_ip"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "customActor=alice", "override should apply")
	assert.Contains(t, line, "src=10.0.0.1", "default mapping should still apply")
}

func TestCEFFormatter_OmitEmpty(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1", OmitEmpty: true}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"empty":   "",
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"empty"},
	}, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "empty=")
}

func TestCEFFormatter_DurationInExtensions(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":     "ok",
		"duration_ms": 2500 * time.Millisecond,
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "cn1=2500")
	assert.Contains(t, string(data), "cn1Label=durationMs")
}

// ---------------------------------------------------------------------------
// CEF escaping tests (exhaustive)
// ---------------------------------------------------------------------------

func TestCEFEscapeHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"pipe", "hello|world", `hello\|world`},
		{"backslash", `hello\world`, `hello\\world`},
		{"both", `a\b|c`, `a\\b\|c`},
		{"newline stripped", "line1\nline2", "line1 line2"},
		{"cr stripped", "line1\rline2", "line1 line2"},
		{"clean", "hello", "hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.CEFEscapeHeaderForTest(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCEFEscapeExtValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"equals", "a=b", `a\=b`},
		{"backslash", `a\b`, `a\\b`},
		{"newline", "a\nb", `a\nb`},
		{"cr", "a\rb", `a\rb`},
		{"all special", "a\\=b\nc\r", `a\\\=b\nc\r`},
		{"clean", "hello", "hello"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.CEFEscapeExtValueForTest(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCEFExtKeyValidation(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"suser", true},
		{"cn1Label", true},
		{"custom_field", true},
		{"field123", true},
		{"has space", false},
		{"has=equals", false},
		{"has|pipe", false},
		{"", false},
		{"has.dot", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			err := audit.ValidateExtKeyForTest(tt.key)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestCEFFormatter_PoolSafety verifies that the sync.Pool buffer reuse
// does not corrupt cached Format() results.
func TestCEFFormatter_PoolSafety(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	def := &audit.EventDef{Required: []string{"outcome"}}
	ts := time.Now()

	result1, err := f.Format(ts, "ev1", audit.Fields{"outcome": "first"}, def, nil)
	require.NoError(t, err)

	result2, err := f.Format(ts, "ev2", audit.Fields{"outcome": "second"}, def, nil)
	require.NoError(t, err)

	assert.Contains(t, string(result1), "outcome=first")
	assert.Contains(t, string(result2), "outcome=second")
	assert.NotEqual(t, result1, result2)
}

func TestCEFEscapeExtValue_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeExtValueForTest(s)
		old := audit.CEFEscapeExtValueOldForTest(s)
		// Output must be byte-for-byte identical to the old implementation.
		if escaped != old {
			return false
		}
		// No raw newlines or carriage returns in escaped output.
		return !strings.Contains(escaped, "\n") && !strings.Contains(escaped, "\r")
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Error(err)
	}
}

func TestCEFEscapeHeader_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeHeaderForTest(s)
		old := audit.CEFEscapeHeaderOldForTest(s)
		// Output must be byte-for-byte identical to the old implementation.
		if escaped != old {
			return false
		}
		// No raw newlines, carriage returns, or unescaped pipes.
		if strings.Contains(escaped, "\n") || strings.Contains(escaped, "\r") {
			return false
		}
		// Check no unescaped pipe: every | must be preceded by \.
		for i, ch := range escaped {
			if ch == '|' && (i == 0 || escaped[i-1] != '\\') {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// CEF log injection prevention
// ---------------------------------------------------------------------------

func TestCEFFormatter_NewlineInjection(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success\n{injected}",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second CEF line")
}

func TestCEFFormatter_HeaderPipeInjection(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "Bad|Vendor", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev|bad", audit.Fields{
		"outcome": "ok",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	// The vendor's pipe should be escaped in the header.
	assert.Contains(t, line, `Bad\|Vendor`)
	// The event type's pipe should be escaped in the header.
	assert.Contains(t, line, `ev\|bad`)
	// Single line.
	lines := strings.Split(strings.TrimSuffix(line, "\n"), "\n")
	assert.Equal(t, 1, len(lines))
}

// ---------------------------------------------------------------------------
// Logger integration tests
// ---------------------------------------------------------------------------

func TestLogger_WithFormatter_Custom(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	called := false
	custom := &stubFormatter{
		fn: func(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef) ([]byte, error) {
			called = true
			return []byte(`{"custom":true}` + "\n"), nil
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(custom),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.True(t, called, "custom formatter should have been called")
}

type stubFormatter struct {
	fn func(time.Time, string, audit.Fields, *audit.EventDef) ([]byte, error)
}

func (s *stubFormatter) Format(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return s.fn(ts, eventType, fields, def)
}

func TestLogger_DefaultJSONFormatter(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Default formatter should produce valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.GetEvents()[0], &m))
	assert.Equal(t, "auth_failure", m["event_type"])
}

func TestLogger_CEFViaWithFormatter(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	cef := &audit.CEFFormatter{
		Vendor:  "TestCo",
		Product: "TestApp",
		Version: "2.0",
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(cef),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	line := string(out.GetEvents()[0])
	assert.True(t, strings.HasPrefix(line, "CEF:0|TestCo|TestApp|2.0|auth_failure|"))
}

func TestLogger_WithFormatter_Nil(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithFormatter(nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "formatter must not be nil")
}

// ---------------------------------------------------------------------------
// CEF extension key validation
// ---------------------------------------------------------------------------

func TestCEFFormatter_FieldValueTypes(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "ok",
		"count":    42,
		"count64":  int64(100),
		"ratio":    3.14,
		"active":   true,
		"inactive": false,
		"dur":      2 * time.Second,
		"when":     testTime,
		"nilfield": nil,
		"custom":   []string{"a", "b"},
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"count", "count64", "ratio", "active", "inactive", "dur", "when", "nilfield", "custom"},
	}, nil)
	require.NoError(t, err)

	line := string(data)
	assert.Contains(t, line, "count=42")
	assert.Contains(t, line, "count64=100")
	assert.Contains(t, line, "ratio=3.14")
	assert.Contains(t, line, "active=true")
	assert.Contains(t, line, "inactive=false")
	assert.Contains(t, line, "dur=2000")
	assert.Contains(t, line, "when=2026-03-17T12:00:00Z")
}

func TestJSONFormatter_WriteFieldError(t *testing.T) {
	// A channel value cannot be marshalled — the formatter should
	// return an error, not panic.
	f := &audit.JSONFormatter{}
	_, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"bad":     make(chan struct{}),
	}, &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"bad"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "json format")
}

func TestDefaultCEFFieldMapping(t *testing.T) {
	m := audit.DefaultCEFFieldMapping()
	assert.Equal(t, "suser", m["actor_id"])
	assert.Equal(t, "src", m["source_ip"])

	// Mutating the returned copy should not affect the default.
	m["actor_id"] = "modified"
	m2 := audit.DefaultCEFFieldMapping()
	assert.Equal(t, "suser", m2["actor_id"], "default mapping must not be mutated")
}

func TestDefaultCEFFieldMapping_IndependentCopies(t *testing.T) {
	// Each call must return a distinct map instance. Mutating one
	// must not affect the other.
	m1 := audit.DefaultCEFFieldMapping()
	m2 := audit.DefaultCEFFieldMapping()

	m1["actor_id"] = "corrupted"
	m1["new_key"] = "injected"

	assert.Equal(t, "suser", m2["actor_id"], "second call must not see first call's mutation")
	_, hasNew := m2["new_key"]
	assert.False(t, hasNew, "second call must not see first call's new key")
}

func TestDefaultCEFFieldMapping_AllStandardEntries(t *testing.T) {
	t.Parallel()
	m := audit.DefaultCEFFieldMapping()

	expected := map[string]string{
		// Identity and access
		"actor_id":    "suser",
		"actor_uid":   "suid",
		"role":        "spriv",
		"target_id":   "duser",
		"target_uid":  "duid",
		"target_role": "dpriv",
		// Event context
		"outcome": "outcome",
		"reason":  "reason",
		"message": "msg",
		// Network
		"source_ip":   "src",
		"source_host": "shost",
		"source_port": "spt",
		"dest_ip":     "dst",
		"dest_host":   "dhost",
		"dest_port":   "dpt",
		"protocol":    "app",
		"transport":   "proto",
		// HTTP / request
		"request_id": "externalId",
		"user_agent": "requestClientApplication",
		"referrer":   "requestContext",
		"method":     "requestMethod",
		"path":       "request",
		// Temporal
		"start_time": "start",
		"end_time":   "end",
		// File
		"file_name": "fname",
		"file_path": "filePath",
		"file_hash": "fileHash",
		"file_size": "fsize",
	}

	assert.Len(t, m, len(expected), "mapping should have %d entries", len(expected))
	for auditField, cefKey := range expected {
		assert.Equal(t, cefKey, m[auditField], "audit field %q should map to %q", auditField, cefKey)
	}
}

func TestDefaultCEFFieldMapping_NoDuplicateCEFKeys(t *testing.T) {
	t.Parallel()
	m := audit.DefaultCEFFieldMapping()
	seen := make(map[string]string, len(m))
	for auditField, cefKey := range m {
		if prev, ok := seen[cefKey]; ok {
			t.Errorf("duplicate CEF key %q: used by both %q and %q", cefKey, prev, auditField)
		}
		seen[cefKey] = auditField
	}
}

func TestCEFFormatter_ConcurrentFormat_NoRace(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
	}
	def := &audit.EventDef{
		Required: []string{"outcome"},
	}
	ts := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine gets its own fields map to avoid relying
			// on Format never writing to the map.
			f := audit.Fields{"outcome": "ok"}
			data, err := cf.Format(ts, "ev", f, def, nil)
			if err != nil {
				t.Errorf("Format failed: %v", err)
				return
			}
			s := string(data)
			if !strings.HasPrefix(s, "CEF:0|V|P|1|") {
				t.Errorf("unexpected output prefix: %s", s[:40])
			}
			if !strings.HasSuffix(s, "\n") {
				t.Errorf("output missing newline terminator")
			}
		}()
	}
	wg.Wait()
}

func TestCEFFormatter_AllocCount(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	ts := testTime

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = cf.Format(ts, "schema_register", fields, def, nil)
	})

	t.Logf("CEFFormatter.Format AllocsPerRun = %.0f", allocs)
	// Measured: 5 allocs normally, 6 with -race (was 11 before #39).
	// The race detector adds instrumentation allocs. Threshold covers both.
	const maxCEFAllocs = 10
	if allocs > maxCEFAllocs {
		t.Errorf("CEFFormatter.Format allocations = %.0f, want <= %d (was 11 before single-buffer fix)", allocs, maxCEFAllocs)
	}
}

func TestJSONFormatter_AllocCount(t *testing.T) {
	jf := &audit.JSONFormatter{}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	ts := testTime

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = jf.Format(ts, "schema_register", fields, def, nil)
	})

	t.Logf("JSONFormatter.Format AllocsPerRun = %.0f", allocs)
	// Measured: 25 allocs normally, ~41 with -race. The race detector
	// instruments memory operations and adds significant allocations.
	// Threshold covers both modes.
	const maxJSONAllocs = 45
	if allocs > maxJSONAllocs {
		t.Errorf("JSONFormatter.Format allocations = %.0f, want <= %d", allocs, maxJSONAllocs)
	}
}

func TestCEFFormatter_NullByteStripped(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok\x00injected",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "\x00", "null bytes must be stripped")
}

func TestCEFFormatter_InvalidExtKeyRejected(t *testing.T) {
	f := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
		FieldMapping: map[string]string{
			"outcome": "bad key",
		},
	}
	_, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
	}, &audit.EventDef{
		Required: []string{"outcome"},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid extension key")
}

func TestCEFFormatter_Format_DuplicateExtKey(t *testing.T) {
	baseDef := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"source_ip", "actor_id"},
	}

	t.Run("rt_collision", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"source_ip": "rt"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":   "ok",
			"source_ip": "10.0.0.1",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "rt="),
			"framework rt should appear once, user collision skipped")
		// Verify the framework value (epoch ms timestamp) survived, not the user value.
		assert.Contains(t, output,
			"rt="+strconv.FormatInt(testTime.UnixMilli(), 10))
		assert.NotContains(t, output, "rt=10.0.0.1")
	})

	t.Run("act_collision", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "act"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":  "ok",
			"actor_id": "alice",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "act="),
			"framework act should appear once, user collision skipped")
		// Verify the framework value (event type) survived, not the user value.
		assert.Contains(t, output, "act=ev")
		assert.NotContains(t, output, "act=alice")
	})

	t.Run("cn1_with_duration", func(t *testing.T) {
		def := &audit.EventDef{
			Required: []string{"outcome"},
			Optional: []string{"actor_id", "duration_ms"},
		}
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "cn1"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":     "ok",
			"actor_id":    "alice",
			"duration_ms": 500 * time.Millisecond,
		}, def, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "cn1="),
			"framework cn1 (duration) should appear once, user collision skipped")
	})

	t.Run("cn1_without_duration", func(t *testing.T) {
		f := &audit.CEFFormatter{
			Vendor:       "V",
			Product:      "P",
			Version:      "1",
			FieldMapping: map[string]string{"actor_id": "cn1"},
		}
		data, err := f.Format(testTime, "ev", audit.Fields{
			"outcome":  "ok",
			"actor_id": "alice",
		}, baseDef, nil)
		require.NoError(t, err)
		output := string(data)
		assert.Equal(t, 1, strings.Count(output, "cn1="),
			"cn1 not reserved when duration_ms absent, consumer mapping permitted")
		assert.Contains(t, output, "cn1=alice")
	})
}

// ---------------------------------------------------------------------------
// writeJSONString tests
// ---------------------------------------------------------------------------

func TestWriteJSONString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "plain_ascii", input: "hello world"},
		{name: "quotes", input: `say "hello"`},
		{name: "backslash", input: `back\slash`},
		{name: "newline", input: "line1\nline2"},
		{name: "tab", input: "col1\tcol2"},
		{name: "carriage_return", input: "line1\rline2"},
		{name: "null_byte", input: "null\x00byte"},
		{name: "all_control_chars", input: "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"},
		{name: "html_lt", input: "<script>"},
		{name: "html_gt", input: "value>other"},
		{name: "html_amp", input: "a&b"},
		{name: "html_mixed", input: `<a href="x&y">`},
		{name: "utf8_emoji", input: "hello 🎉 world"},
		{name: "utf8_cjk", input: "日本語テスト"},
		{name: "utf8_accented", input: "café résumé"},
		{name: "invalid_utf8", input: "bad\xfe\xffbyte"},
		{name: "line_separator_u2028", input: "before\u2028after"},
		{name: "paragraph_separator_u2029", input: "before\u2029after"},
		{name: "mixed_special", input: "line1\nline2\t\"quoted\"\\back<html>&amp;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			audit.WriteJSONStringForTest(&buf, tt.input)
			got := buf.Bytes()

			want, err := json.Marshal(tt.input)
			require.NoError(t, err)

			assert.Equal(t, string(want), string(got),
				"writeJSONString output must match json.Marshal")
		})
	}
}

// TestJSONFormatter_TimestampAppendFormat verifies that the
// ts.AppendFormat + AvailableBuffer pattern produces the same
// timestamp output as the old json.Marshal(ts.Format(...)) approach.
func TestJSONFormatter_TimestampAppendFormat(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	def := &audit.EventDef{Required: []string{"outcome"}}

	// Use a timestamp with nanosecond precision and a timezone offset
	// to exercise all format components.
	ts := time.Date(2026, 3, 28, 15, 4, 5, 123456789, time.FixedZone("EST", -5*60*60))

	data, err := f.Format(ts, "ev", audit.Fields{"outcome": "ok"}, def, nil)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	got, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string")
	want := ts.Format(time.RFC3339Nano)
	assert.Equal(t, want, got,
		"AppendFormat timestamp must match Format() string")
}

// TestJSONFormatter_PoolSafety verifies that the sync.Pool buffer
// reuse does not corrupt cached Format() results. This validates the
// copy-before-return pattern that prevents the pool-vs-cache race
// described in issue #101.
func TestJSONFormatter_PoolSafety(t *testing.T) {
	f := &audit.JSONFormatter{}
	def := &audit.EventDef{
		Required: []string{"outcome"},
	}
	ts := time.Now()

	// Call Format twice in succession. The second call should reuse
	// the pooled buffer but must not corrupt the first result.
	result1, err := f.Format(ts, "ev1", audit.Fields{"outcome": "first"}, def, nil)
	require.NoError(t, err)

	result2, err := f.Format(ts, "ev2", audit.Fields{"outcome": "second"}, def, nil)
	require.NoError(t, err)

	// Both results must be independent — the first must not have been
	// overwritten by the second.
	assert.Contains(t, string(result1), `"outcome":"first"`)
	assert.Contains(t, string(result2), `"outcome":"second"`)
	assert.NotEqual(t, result1, result2)
}

func TestWriteJSONString_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		var buf bytes.Buffer
		audit.WriteJSONStringForTest(&buf, s)

		want, err := json.Marshal(s)
		if err != nil {
			return false
		}
		return bytes.Equal(buf.Bytes(), want)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 10000}); err != nil {
		t.Errorf("writeJSONString diverges from json.Marshal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Formatter benchmarks
// ---------------------------------------------------------------------------

func BenchmarkJSONFormatter_Format(b *testing.B) {
	f := &audit.JSONFormatter{}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	audit.PrecomputeEventDefForTest(def)
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def, nil)
	}
}

func BenchmarkCEFFormatter_Format(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		"version":  1,
	}
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	audit.PrecomputeEventDefForTest(def)
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def, nil)
	}
}

// largeEventFixture returns a 20-field event for benchmarking formatter
// scaling with production-realistic field counts.
func largeEventFixture() (audit.Fields, *audit.EventDef) {
	def := &audit.EventDef{
		Required: []string{"outcome", "actor_id", "method", "path", "source_ip"},
		Optional: []string{
			"request_id", "user_agent", "subject", "schema_type", "version",
			"cluster", "datacenter", "tenant_id", "session_id", "trace_id",
			"span_id", "response_code", "content_type", "payload_size", "tags",
		},
	}
	fields := audit.Fields{
		"outcome":       "success",
		"actor_id":      "alice",
		"method":        "POST",
		"path":          "/api/v1/schemas",
		"source_ip":     "10.0.0.1",
		"request_id":    "550e8400-e29b-41d4-a716-446655440000",
		"user_agent":    "go-audit-client/1.0",
		"subject":       "my-topic",
		"schema_type":   "avro",
		"version":       3,
		"cluster":       "prod-us-east-1",
		"datacenter":    "dc1",
		"tenant_id":     "tenant-42",
		"session_id":    "sess-abc123",
		"trace_id":      "4bf92f3577b34da6a3ce929d0e0e4736",
		"span_id":       "00f067aa0ba902b7",
		"response_code": 200,
		"content_type":  "application/json",
		"payload_size":  1024,
		"tags":          "production,critical",
	}
	audit.PrecomputeEventDefForTest(def)
	return fields, def
}

func BenchmarkJSONFormatter_Format_LargeEvent(b *testing.B) {
	f := &audit.JSONFormatter{}
	fields, def := largeEventFixture()
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

func BenchmarkCEFFormatter_Format_LargeEvent(b *testing.B) {
	f := &audit.CEFFormatter{
		Vendor:  "TestVendor",
		Product: "TestProduct",
		Version: "1.0",
	}
	fields, def := largeEventFixture()
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "api_request", fields, def, nil)
	}
}

// ---------------------------------------------------------------------------
// FormatOptions.IsExcluded tests
// ---------------------------------------------------------------------------

func TestFormatOptions_IsExcluded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		opts     *audit.FormatOptions
		field    string
		excluded bool
	}{
		{"nil opts", nil, "email", false},
		{"nil FieldLabels", &audit.FormatOptions{ExcludedLabels: map[string]struct{}{"pii": {}}}, "email", false},
		{"nil ExcludedLabels", &audit.FormatOptions{FieldLabels: map[string]map[string]struct{}{"email": {"pii": {}}}}, "email", false},
		{"field not in FieldLabels", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"pii": {}},
			FieldLabels:    map[string]map[string]struct{}{"phone": {"pii": {}}},
		}, "email", false},
		{"label not excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"financial": {}},
			FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
		}, "email", false},
		{"label excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"pii": {}},
			FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
		}, "email", true},
		{"multi label one excluded", &audit.FormatOptions{
			ExcludedLabels: map[string]struct{}{"financial": {}},
			FieldLabels:    map[string]map[string]struct{}{"card": {"pii": {}, "financial": {}}},
		}, "card", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.excluded, tt.opts.IsExcluded(tt.field))
		})
	}
}

func TestJSONFormatter_Format_WithExclusion(t *testing.T) {
	t.Parallel()
	f := &audit.JSONFormatter{}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	def := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"email", "name"},
	}
	fields := audit.Fields{
		"outcome": "success",
		"email":   "alice@example.com",
		"name":    "Alice",
	}
	opts := &audit.FormatOptions{
		ExcludedLabels: map[string]struct{}{"pii": {}},
		FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
	}

	data, err := f.Format(ts, "user_create", fields, def, opts)
	require.NoError(t, err)
	s := string(data)

	assert.NotContains(t, s, "email")
	assert.NotContains(t, s, "alice@example.com")
	assert.Contains(t, s, `"name":"Alice"`)
	assert.Contains(t, s, `"outcome":"success"`)
	assert.Contains(t, s, `"event_type":"user_create"`)
}

func TestCEFFormatter_Format_WithExclusion(t *testing.T) {
	t.Parallel()
	f := &audit.CEFFormatter{Vendor: "Test", Product: "Test", Version: "1.0"}
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	def := &audit.EventDef{
		Required: []string{"outcome"},
		Optional: []string{"email"},
	}
	fields := audit.Fields{
		"outcome": "success",
		"email":   "alice@example.com",
	}
	opts := &audit.FormatOptions{
		ExcludedLabels: map[string]struct{}{"pii": {}},
		FieldLabels:    map[string]map[string]struct{}{"email": {"pii": {}}},
	}

	data, err := f.Format(ts, "user_create", fields, def, opts)
	require.NoError(t, err)
	s := string(data)

	assert.NotContains(t, s, "alice@example.com")
	assert.Contains(t, s, "outcome=success")
}
