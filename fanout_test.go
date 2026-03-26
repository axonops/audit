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
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFanoutTestLogger creates a logger with the testTaxonomy and the
// given outputs/options. It registers cleanup for Close.
func newFanoutTestLogger(t *testing.T, outputs []audit.Output, extraOpts ...audit.Option) *audit.Logger {
	t.Helper()
	opts := []audit.Option{
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithOutputs(outputs...),
	}
	opts = append(opts, extraOpts...)
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })
	return logger
}

func TestFanout_DeliverToAllOutputs(t *testing.T) {
	out1 := newMockOutput("out1")
	out2 := newMockOutput("out2")
	out3 := newMockOutput("out3")
	logger := newFanoutTestLogger(t, []audit.Output{out1, out2, out3})

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))

	for _, out := range []*mockOutput{out1, out2, out3} {
		require.True(t, out.waitForEvents(1, 2*time.Second),
			"output %s did not receive event", out.Name())
	}
}

func TestFanout_OutputFailureIsolation(t *testing.T) {
	failing := newMockOutput("failing")
	failing.setWriteErr(assert.AnError)
	healthy := newMockOutput("healthy")
	logger := newFanoutTestLogger(t, []audit.Output{failing, healthy})

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))

	require.True(t, healthy.waitForEvents(1, 2*time.Second),
		"healthy output should receive event despite failing output")
}

func TestFanout_IncludeRoute_CategoryMatch(t *testing.T) {
	secOut := newMockOutput("security-only")
	allOut := newMockOutput("all-events")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(allOut, audit.EventRoute{}, nil),
		audit.WithNamedOutput(secOut, audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Write event should go to allOut but not secOut.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	// Security event should go to both.
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))

	require.True(t, allOut.waitForEvents(2, 2*time.Second))
	// Give secOut time to potentially receive — it should only get 1.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, secOut.eventCount(), "security-only should receive 1 event")
}

func TestFanout_ExcludeRoute_CategoryMatch(t *testing.T) {
	noRead := newMockOutput("no-reads")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(noRead, audit.EventRoute{
			ExcludeCategories: []string{"read"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("user_get", audit.Fields{"outcome": "success"}))

	require.True(t, noRead.waitForEvents(1, 2*time.Second))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, noRead.eventCount(), "no-reads should skip read events")
}

func TestFanout_IncludeRoute_EventTypeMatch(t *testing.T) {
	out := newMockOutput("specific")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeEventTypes: []string{"auth_failure"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, logger.Audit("permission_denied", audit.Fields{"outcome": "failure"}))

	require.True(t, out.waitForEvents(1, 2*time.Second))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, out.eventCount())
}

func TestFanout_IncludeRoute_Union(t *testing.T) {
	out := newMockOutput("union")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeCategories: []string{"write"},
			IncludeEventTypes: []string{"auth_failure"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// write category event.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	// specific event type from a different category.
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	// not in either include.
	require.NoError(t, logger.Audit("user_get", audit.Fields{"outcome": "success"}))

	require.True(t, out.waitForEvents(2, 2*time.Second))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 2, out.eventCount(), "union should match write + auth_failure")
}

func TestFanout_EmptyRoute_ReceivesAll(t *testing.T) {
	out := newMockOutput("all")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))

	require.True(t, out.waitForEvents(2, 2*time.Second))
}

func TestFanout_DuplicateOutputName_Error(t *testing.T) {
	out1 := newMockOutput("same-name")
	out2 := newMockOutput("same-name")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithOutputs(out1, out2),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate output name")
}

func TestFanout_BootstrapValidation_UnknownCategory(t *testing.T) {
	out := newMockOutput("test")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeCategories: []string{"nonexistent"},
		}, nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_BootstrapValidation_MixedMode(t *testing.T) {
	out := newMockOutput("test")
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeCategories: []string{"write"},
			ExcludeCategories: []string{"read"},
		}, nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "either include or exclude")
}

func TestFanout_SetOutputRoute(t *testing.T) {
	out := newMockOutput("routed")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Initially receives all events.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.True(t, out.waitForEvents(1, 2*time.Second))

	// Set route to security only.
	require.NoError(t, logger.SetOutputRoute("routed", audit.EventRoute{
		IncludeCategories: []string{"security"},
	}))

	require.NoError(t, logger.Audit("user_delete", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))

	require.True(t, out.waitForEvents(2, 2*time.Second))
	time.Sleep(100 * time.Millisecond)
	// Should have: 1 initial + 1 auth_failure = 2 (user_delete filtered).
	assert.Equal(t, 2, out.eventCount())
}

func TestFanout_SetOutputRoute_UnknownOutput(t *testing.T) {
	logger := newFanoutTestLogger(t, nil)
	err := logger.SetOutputRoute("nonexistent", audit.EventRoute{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output")
}

func TestFanout_SetOutputRoute_InvalidRoute(t *testing.T) {
	out := newMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.SetOutputRoute("test", audit.EventRoute{
		IncludeCategories: []string{"bogus"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown taxonomy entries")
}

func TestFanout_ClearOutputRoute(t *testing.T) {
	out := newMockOutput("routed")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Only security events delivered initially.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, out.eventCount())

	// Clear route — now receives all.
	require.NoError(t, logger.ClearOutputRoute("routed"))
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))
	require.True(t, out.waitForEvents(1, 2*time.Second))
}

func TestFanout_GetOutputRoute(t *testing.T) {
	out := newMockOutput("test")
	route := audit.EventRoute{IncludeCategories: []string{"security"}}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, route, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	got, err := logger.GetOutputRoute("test")
	require.NoError(t, err)
	assert.Equal(t, route.IncludeCategories, got.IncludeCategories)
}

func TestFanout_ConcurrentSetRouteAndAudit(t *testing.T) {
	out := newMockOutput("concurrent")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(out, audit.EventRoute{}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: emit events.
	go func() {
		defer wg.Done()
		for range 100 {
			_ = logger.Audit("auth_failure", audit.Fields{"outcome": "failure"})
		}
	}()

	// Goroutine 2: toggle routes.
	go func() {
		defer wg.Done()
		for range 50 {
			_ = logger.SetOutputRoute("concurrent", audit.EventRoute{
				IncludeCategories: []string{"security"},
			})
			_ = logger.ClearOutputRoute("concurrent")
		}
	}()

	wg.Wait()
	// Just verify no panic or race; exact count doesn't matter.
	assert.GreaterOrEqual(t, out.eventCount(), 0)
}

func TestFanout_GlobalFilterTakesPrecedence(t *testing.T) {
	out := newMockOutput("all")
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
		audit.WithNamedOutput(out, audit.EventRoute{
			IncludeCategories: []string{"security"}, // route wants security
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Security is globally disabled — should not reach the output even
	// though the output route includes it.
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "failure"}))
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 0, out.eventCount(), "globally disabled event should not reach any output")
}

func TestFanout_PerOutputFormatter(t *testing.T) {
	jsonOut := newMockOutput("json")
	cefOut := newMockOutput("cef")

	cefFmt := &audit.CEFFormatter{
		Vendor:  "Test",
		Product: "Audit",
		Version: "1.0",
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(testTaxonomy()),
		audit.WithNamedOutput(jsonOut, audit.EventRoute{}, nil),   // default JSON
		audit.WithNamedOutput(cefOut, audit.EventRoute{}, cefFmt), // CEF
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success"}))

	require.True(t, jsonOut.waitForEvents(1, 2*time.Second))
	require.True(t, cefOut.waitForEvents(1, 2*time.Second))

	// JSON output should start with '{'.
	jsonData := jsonOut.getEvents()[0]
	assert.Equal(t, byte('{'), jsonData[0], "json output should be JSON")

	// CEF output should start with "CEF:0|".
	cefData := cefOut.getEvents()[0]
	assert.Contains(t, string(cefData), "CEF:0|", "cef output should be CEF")
}
