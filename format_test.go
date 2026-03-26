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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

var testDef = &audit.EventDef{
	Category: "write",
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
	}, testDef)
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
	}, testDef)
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
	}, testDef)
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
	}, testDef)
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
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"duration_ms"},
	})
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
				Category: "write",
				Required: []string{"outcome"},
			})
			require.NoError(t, err)
			assert.Contains(t, string(data), fmt.Sprintf("|%d|", tt.want))
		})
	}
}

func TestJSONFormatter_TimestampRFC3339Nano(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(float64)
	require.True(t, ok, "timestamp should be a number for unix_ms")
	assert.Equal(t, float64(testTime.UnixMilli()), ts)
}

func TestJSONFormatter_OmitEmptyTrue(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: true}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type and version not provided
	}, testDef)
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
	}, testDef)
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
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"name"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, longVal, m["outcome"])
}

func TestJSONFormatter_NilFields(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", nil, &audit.EventDef{
		Category: "write",
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
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
	}, testDef)
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
		Category: "write",
		Required: []string{"outcome"},
	})
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
		Category: "security",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)
	assert.Contains(t, string(data), "|auth_failure|8|")
}

func TestCEFFormatter_DefaultDescription(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "my_event", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)
	assert.Contains(t, string(data), "|Custom: ev|")
}

func TestCEFFormatter_ExtensionFields(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome", "actor_id"},
	})
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
		Category: "write",
		Required: []string{"outcome", "actor_id"},
	})
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
		Category: "write",
		Required: []string{"outcome", "actor_id"},
		Optional: []string{"source_ip"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"empty"},
	})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "empty=")
}

func TestCEFFormatter_DurationInExtensions(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome":     "ok",
		"duration_ms": 2500 * time.Millisecond,
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
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

func TestCEFEscapeExtValue_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeExtValueForTest(s)
		// No raw newlines or carriage returns in escaped output.
		return !strings.Contains(escaped, "\n") && !strings.Contains(escaped, "\r")
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestCEFEscapeHeader_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		escaped := audit.CEFEscapeHeaderForTest(s)
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
	if err := quick.Check(f, nil); err != nil {
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
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second CEF line")
}

func TestCEFFormatter_HeaderPipeInjection(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "Bad|Vendor", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev|bad", audit.Fields{
		"outcome": "ok",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
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
	out := newMockOutput("test")
	called := false
	custom := &stubFormatter{
		fn: func(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef) ([]byte, error) {
			called = true
			return []byte(`{"custom":true}` + "\n"), nil
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(validTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(custom),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.waitForEvents(1, 2*time.Second))
	assert.True(t, called, "custom formatter should have been called")
}

type stubFormatter struct {
	fn func(time.Time, string, audit.Fields, *audit.EventDef) ([]byte, error)
}

func (s *stubFormatter) Format(ts time.Time, eventType string, fields audit.Fields, def *audit.EventDef) ([]byte, error) {
	return s.fn(ts, eventType, fields, def)
}

func TestLogger_DefaultJSONFormatter(t *testing.T) {
	out := newMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(validTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.waitForEvents(1, 2*time.Second))

	// Default formatter should produce valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(out.events[0], &m))
	assert.Equal(t, "auth_failure", m["event_type"])
}

func TestLogger_CEFViaWithFormatter(t *testing.T) {
	out := newMockOutput("test")
	cef := &audit.CEFFormatter{
		Vendor:  "TestCo",
		Product: "TestApp",
		Version: "2.0",
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(validTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(cef),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.waitForEvents(1, 2*time.Second))

	line := string(out.events[0])
	assert.True(t, strings.HasPrefix(line, "CEF:0|TestCo|TestApp|2.0|auth_failure|"))
}

func TestLogger_WithFormatter_Nil(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(validTaxonomy()),
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
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"count", "count64", "ratio", "active", "inactive", "dur", "when", "nilfield", "custom"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"bad"},
	})
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

func TestCEFFormatter_ConcurrentFormat_NoRace(t *testing.T) {
	cf := &audit.CEFFormatter{
		Vendor:  "V",
		Product: "P",
		Version: "1",
	}
	def := &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	}
	fields := audit.Fields{"outcome": "ok"}
	ts := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cf.Format(ts, "ev", fields, def)
			if err != nil {
				t.Errorf("Format failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestCEFFormatter_NullByteStripped(t *testing.T) {
	f := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok\x00injected",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
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
		Category: "write",
		Required: []string{"outcome"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid extension key")
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
		Category: "write",
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def)
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
		Category: "write",
		Required: []string{"outcome", "actor_id", "subject"},
		Optional: []string{"version"},
	}
	ts := time.Now()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = f.Format(ts, "schema_register", fields, def)
	}
}
