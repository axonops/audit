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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/tests/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFanout_DeliverToAll(t *testing.T) {
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	out3 := testhelper.NewMockOutput("out3")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithOutputs(out1, out2, out3),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	for _, out := range []*testhelper.MockOutput{out1, out2, out3} {
		assert.Equal(t, 1, out.EventCount(),
			"output %s should receive 1 event", out.Name())
	}
}

func TestFanout_OutputFailureIsolation(t *testing.T) {
	failing := testhelper.NewMockOutput("failing")
	failing.SetWriteErr(assert.AnError)
	healthy := testhelper.NewMockOutput("healthy")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithOutputs(failing, healthy),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 1, healthy.EventCount(),
		"healthy output should receive event despite failing output")
}

func TestFanout_RouteFiltering(t *testing.T) {
	tests := []struct {
		name      string
		route     audit.EventRoute
		events    []string // event types to emit
		wantCount int
	}{
		{
			name:      "include category matches",
			route:     audit.EventRoute{IncludeCategories: []string{"security"}},
			events:    []string{"user_create", "auth_failure"},
			wantCount: 1, // only auth_failure
		},
		{
			name:      "include category no match",
			route:     audit.EventRoute{IncludeCategories: []string{"security"}},
			events:    []string{"user_create", "user_get"},
			wantCount: 0,
		},
		{
			name:      "include event type matches",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			events:    []string{"auth_failure", "permission_denied"},
			wantCount: 1, // only auth_failure
		},
		{
			name: "include union matches category and event type",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				IncludeEventTypes: []string{"auth_failure"},
			},
			events:    []string{"user_create", "auth_failure", "user_get"},
			wantCount: 2, // user_create (write) + auth_failure
		},
		{
			name:      "exclude category skips",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			events:    []string{"user_create", "user_get"},
			wantCount: 1, // only user_create
		},
		{
			name:      "exclude event type skips",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			events:    []string{"config_get", "user_get"},
			wantCount: 1, // only user_get
		},
		{
			name: "exclude union skips both",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			events:    []string{"user_create", "user_delete", "user_get"},
			wantCount: 1, // only user_create
		},
		{
			name:      "empty route receives all",
			route:     audit.EventRoute{},
			events:    []string{"user_create", "auth_failure", "user_get"},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := testhelper.NewMockOutput("routed")
			logger, err := audit.NewLogger(
				audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
				audit.WithTaxonomy(testhelper.TestTaxonomy()),
				audit.WithNamedOutput(out, &tt.route, nil),
			)
			require.NoError(t, err)

			for _, evt := range tt.events {
				require.NoError(t, logger.Audit(evt, audit.Fields{"outcome": "success"}))
			}
			require.NoError(t, logger.Close())

			assert.Equal(t, tt.wantCount, out.EventCount())
		})
	}
}

func TestFanout_DuplicateOutputName_Error(t *testing.T) {
	out1 := testhelper.NewMockOutput("same-name")
	out2 := testhelper.NewMockOutput("same-name")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithOutputs(out1, out2),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate output name")
}

func TestFanout_WithOutputs_AfterWithNamedOutput_Error(t *testing.T) {
	out1 := testhelper.NewMockOutput("named")
	out2 := testhelper.NewMockOutput("plain")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out1, &audit.EventRoute{}, nil),
		audit.WithOutputs(out2), // should error
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be used with WithNamedOutput")
}

func TestFanout_BootstrapValidation_UnknownCategory(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"nonexistent"},
		}, nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_BootstrapValidation_MixedMode(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"write"},
			ExcludeCategories: []string{"read"},
		}, nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either include or exclude")
}

func TestFanout_SetOutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("routed")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)

	// Initially receives all events.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Set route to security only.
	require.NoError(t, logger.SetOutputRoute("routed", &audit.EventRoute{
		IncludeCategories: []string{"security"},
	}))

	require.NoError(t, logger.Audit("user_delete", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, logger.Close())

	// Should have: 1 initial + 1 auth_failure = 2 (user_delete filtered).
	assert.Equal(t, 2, out.EventCount())
}

func TestFanout_SetOutputRoute_DoesNotAffectOtherOutputs(t *testing.T) {
	outA := testhelper.NewMockOutput("a")
	outB := testhelper.NewMockOutput("b")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(outA, &audit.EventRoute{}, nil),
		audit.WithNamedOutput(outB, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)

	// Restrict A to security only.
	require.NoError(t, logger.SetOutputRoute("a", &audit.EventRoute{
		IncludeCategories: []string{"security"},
	}))

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 1, outA.EventCount(), "A should only get auth_failure")
	assert.Equal(t, 2, outB.EventCount(), "B should get both events")
}

func TestFanout_SetOutputRoute_UnknownOutput(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.SetOutputRoute("nonexistent", &audit.EventRoute{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_SetOutputRoute_InvalidRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.SetOutputRoute("test", &audit.EventRoute{
		IncludeCategories: []string{"bogus"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_ClearOutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("routed")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)

	// Clear route — now receives all events.
	require.NoError(t, logger.ClearOutputRoute("routed"))
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 2, out.EventCount(), "should receive all events after clearing route")
}

func TestFanout_ClearOutputRoute_UnknownOutput(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.ClearOutputRoute("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_GetOutputRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	route := audit.EventRoute{IncludeCategories: []string{"security"}}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &route, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	got, err := logger.GetOutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, route.IncludeCategories, got.IncludeCategories)

	// Mutating the returned route must not affect the stored route.
	got.IncludeCategories = append(got.IncludeCategories, "write")
	got2, err := logger.GetOutputRoute("test")
	require.NoError(t, err)
	assert.Len(t, got2.IncludeCategories, 1, "stored route should not be mutated")
}

func TestFanout_GetOutputRoute_UnknownOutput(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	_, err = logger.GetOutputRoute("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_GetOutputRoute_ReflectsSetAndClear(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Set a route.
	newRoute := audit.EventRoute{IncludeCategories: []string{"write"}}
	require.NoError(t, logger.SetOutputRoute("test", &newRoute))
	got, err := logger.GetOutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, []string{"write"}, got.IncludeCategories)

	// Clear.
	require.NoError(t, logger.ClearOutputRoute("test"))
	got, err = logger.GetOutputRoute("test")
	require.NoError(t, err)
	assert.True(t, got.IsEmpty())
}

func TestFanout_ConcurrentSetRouteAndAudit(t *testing.T) {
	out := testhelper.NewMockOutput("concurrent")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			_ = logger.Audit("auth_failure", audit.Fields{"outcome": "failure"})
		}
	}()

	go func() {
		defer wg.Done()
		for range 50 {
			_ = logger.SetOutputRoute("concurrent", &audit.EventRoute{
				IncludeCategories: []string{"security"},
			})
			_ = logger.ClearOutputRoute("concurrent")
		}
	}()

	wg.Wait()
	require.NoError(t, logger.Close())

	// All events are security category, so they should all arrive
	// regardless of route toggling (include security = match, empty = match).
	assert.Equal(t, 100, out.EventCount(),
		"all security events should arrive regardless of route toggling")
}

func TestFanout_GlobalFilterTakesPrecedence(t *testing.T) {
	out := testhelper.NewMockOutput("all")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(audit.Taxonomy{
			Version: 1,
			Categories: map[string][]string{
				"write":    {"user_create"},
				"security": {"auth_failure"},
			},
			Events: map[string]audit.EventDef{
				"user_create":  {Category: "write", Required: []string{"outcome"}},
				"auth_failure": {Category: "security", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write"}, // security NOT enabled
		}),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)

	// Globally disabled — should not reach output even though route includes it.
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 0, out.EventCount(),
		"globally disabled event should not reach any output")
}

func TestFanout_PerOutputFormatter(t *testing.T) {
	jsonOut := testhelper.NewMockOutput("json")
	cefOut := testhelper.NewMockOutput("cef")

	cefFmt := &audit.CEFFormatter{
		Vendor:  "Test",
		Product: "Audit",
		Version: "1.0",
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(jsonOut, &audit.EventRoute{}, nil),
		audit.WithNamedOutput(cefOut, &audit.EventRoute{}, cefFmt),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	require.Equal(t, 1, jsonOut.EventCount())
	require.Equal(t, 1, cefOut.EventCount())

	jsonData := jsonOut.GetEvents()[0]
	assert.Equal(t, byte('{'), jsonData[0], "json output should be JSON")

	cefData := cefOut.GetEvents()[0]
	assert.Contains(t, string(cefData), "CEF:0|", "cef output should be CEF")
}

func TestFanout_PanicInFormatter_DrainLoopSurvives(t *testing.T) {
	out := testhelper.NewMockOutput("survivor")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, &panicFormatter{}),
	)
	require.NoError(t, err)

	// The panic is recovered by processEntry — drain loop survives.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	// Second event also processed (drain loop not dead).
	require.NoError(t, logger.Audit("user_delete", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	// Events are lost due to panic, but the drain loop is alive.
	assert.Equal(t, 0, out.EventCount())
}

// panicFormatter is a Formatter that always panics.
type panicFormatter struct{}

func (p *panicFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
	panic("formatter panic")
}

func TestFanout_SharedFormatter_DeliversSameBytes(t *testing.T) {
	out1 := testhelper.NewMockOutput("a")
	out2 := testhelper.NewMockOutput("b")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithOutputs(out1, out2), // same default formatter
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	require.Equal(t, 1, out1.EventCount())
	require.Equal(t, 1, out2.EventCount())

	// Same formatter → same bytes.
	assert.Equal(t, out1.GetEvents()[0], out2.GetEvents()[0],
		"outputs sharing a formatter should receive identical bytes")
}

func TestFanout_PerOutputRouteFilter_MetricsRecordFiltered(t *testing.T) {
	out := testhelper.NewMockOutput("filtered")
	metrics := testhelper.NewMockMetrics()

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithMetrics(metrics),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)

	// This write event will be filtered by the per-output route.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 0, out.EventCount())
	assert.Greater(t, metrics.GetOutputFiltered("filtered"), 0,
		"RecordOutputFiltered should be called for route-filtered events")
}

func TestFanout_ExcludeEventType_EndToEnd(t *testing.T) {
	out := testhelper.NewMockOutput("no-config-get")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{
			ExcludeEventTypes: []string{"config_get"},
		}, nil),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("config_get", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("user_get", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 2, out.EventCount(), "config_get should be excluded")
}

// errorFormatter always returns an error (does not panic).
type errorFormatter struct{}

func (e *errorFormatter) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
	return nil, fmt.Errorf("format failed")
}

func TestFanout_ErrorFormatter_DoesNotBlockDefaultFormatter(t *testing.T) {
	goodOut := testhelper.NewMockOutput("good")
	badOut := testhelper.NewMockOutput("bad")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
		audit.WithNamedOutput(goodOut, &audit.EventRoute{}, nil),
		audit.WithNamedOutput(badOut, &audit.EventRoute{}, &errorFormatter{}),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	assert.Equal(t, 1, goodOut.EventCount(),
		"good output should receive event despite error formatter on other output")
	assert.Equal(t, 0, badOut.EventCount(),
		"bad output should receive nothing due to formatter error")
}
