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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
	"github.com/cucumber/godog"
)

// registerLokiHMACSteps registers BDD steps for HMAC integrity
// verification on events stored in Loki.
func registerLokiHMACSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiHMACGivenSteps(ctx, tc)
	registerLokiHMACWhenSteps(ctx, tc)
	registerLokiHMACThenSteps(ctx, tc)
}

func registerLokiHMACGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^a logger with loki output and HMAC enabled using salt "([^"]*)" version "([^"]*)" and hash "([^"]*)"$`,
		func(salt, version, hash string) error {
			return createLokiLoggerWithHMAC(tc, salt, version, hash, nil)
		})

	ctx.Step(`^a logger with loki output using HMAC salt "([^"]*)" version "([^"]*)"$`,
		func(salt, version string) error {
			return createLokiLoggerWithHMACAndCapture(tc, salt, version)
		})

	ctx.Step(`^a capture output with HMAC salt "([^"]*)" version "([^"]*)"$`,
		func(salt, version string) error {
			// This step is called AFTER the loki logger is already set up
			// with a capture output added alongside. The loki logger setup
			// with capture is handled by createLokiLoggerWithHMACAndCapture.
			// This step is a no-op marker for readability.
			return nil
		})

	ctx.Step(`^a logger with loki output excluding label "([^"]*)" with HMAC salt "([^"]*)" version "([^"]*)"$`,
		func(label, salt, version string) error {
			excludeLabels := []string{label}
			return createLokiLoggerWithHMAC(tc, salt, version, "HMAC-SHA-256", excludeLabels)
		})

	ctx.Step(`^a capture output with no exclusions and HMAC salt "([^"]*)" version "([^"]*)"$`,
		func(_, _ string) error {
			// Already set up by the preceding Given step.
			return nil
		})

}

func registerLokiHMACWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with actor "([^"]*)" and outcome "([^"]*)"$`,
		func(eventType, actor, outcome string) error {
			if tc.Logger == nil {
				return fmt.Errorf("logger is nil")
			}
			m := marker("BDD")
			tc.Markers["default"] = m
			fields := audit.Fields{
				"actor_id": actor,
				"outcome":  outcome,
				"marker":   m,
			}
			return tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		})

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with actor "([^"]*)" and outcome "([^"]*)" and field "([^"]*)" = "([^"]*)"$`,
		func(eventType, actor, outcome, field, value string) error {
			if tc.Logger == nil {
				return fmt.Errorf("logger is nil")
			}
			m := marker("BDD")
			tc.Markers["default"] = m
			fields := audit.Fields{
				"actor_id": actor,
				"outcome":  outcome,
				"marker":   m,
				field:      value,
			}
			return tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		})

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with actor "([^"]*)" and outcome "([^"]*)" and field "([^"]*)" = "([^"]*)" named "([^"]*)"$`,
		func(eventType, actor, outcome, field, value, name string) error {
			if tc.Logger == nil {
				return fmt.Errorf("logger is nil")
			}
			m := marker("BDD")
			tc.Markers[name] = m
			fields := audit.Fields{
				"actor_id": actor,
				"outcome":  outcome,
				"marker":   m,
				field:      value,
			}
			return tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		})

}

func registerLokiHMACThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki event payload should contain field "([^"]*)"$`,
		func(field string) error {
			marker := tc.Markers["default"]
			raw, err := queryLokiForMarkerEvent(tc, marker)
			if err != nil {
				return err
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				return fmt.Errorf("parse loki event: %w", err)
			}
			if _, ok := m[field]; !ok {
				return fmt.Errorf("loki event does not contain field %q", field)
			}
			return nil
		})

	ctx.Step(`^the loki event payload should contain field "([^"]*)" with value "([^"]*)"$`,
		func(field, want string) error {
			marker := tc.Markers["default"]
			raw, err := queryLokiForMarkerEvent(tc, marker)
			if err != nil {
				return err
			}
			return assertJSONField(raw, field, want)
		})

	ctx.Step(`^the loki event payload should not contain field "([^"]*)"$`,
		func(field string) error {
			marker := tc.Markers["default"]
			raw, err := queryLokiForMarkerEvent(tc, marker)
			if err != nil {
				return err
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				return fmt.Errorf("parse loki event: %w", err)
			}
			if _, ok := m[field]; ok {
				return fmt.Errorf("loki event contains field %q but should not", field)
			}
			return nil
		})

	ctx.Step(`^independently recomputing HMAC-SHA-256 over the loki payload with salt "([^"]*)" matches the "_hmac" value$`,
		func(salt string) error {
			return verifyLokiEventHMAC(tc, salt)
		})

	ctx.Step(`^the HMAC in Loki should differ from the HMAC in the capture output$`,
		func() error {
			return assertLokiAndCaptureHMACDiffer(tc)
		})

	ctx.Step(`^both outputs should have "_hmac" fields$`,
		func() error {
			return assertBothOutputsHaveHMAC(tc)
		})

	ctx.Step(`^the HMAC values should differ between Loki and the capture output$`,
		func() error {
			return assertLokiAndCaptureHMACDiffer(tc)
		})

	ctx.Step(`^the capture output should contain the marker$`,
		func() error {
			if tc.CaptureOutput == nil {
				return fmt.Errorf("no capture output configured")
			}
			marker := tc.Markers["default"]
			for _, raw := range tc.CaptureOutput.Events() {
				if containsMarker(raw, marker) {
					return nil
				}
			}
			return fmt.Errorf("capture output does not contain marker %q", marker)
		})

	ctx.Step(`^the capture output event should contain field "([^"]*)" with value "([^"]*)"$`,
		func(field, value string) error {
			if tc.CaptureOutput == nil {
				return fmt.Errorf("no capture output configured")
			}
			marker := tc.Markers["default"]
			for _, raw := range tc.CaptureOutput.Events() {
				if containsMarker(raw, marker) {
					return assertJSONField(raw, field, value)
				}
			}
			return fmt.Errorf("capture output does not contain marker %q", marker)
		})
}

// createLokiLoggerWithHMAC creates a Loki output + logger with HMAC
// enabled. If excludeLabels is non-nil, sensitivity label stripping
// is applied to the Loki output. A captureOutput is also added for
// cross-output comparison when excludeLabels is set.
func createLokiLoggerWithHMAC(tc *AuditTestContext, salt, version, hash string, excludeLabels []string) error {
	cfg := defaultLokiTestConfig(tc)

	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.LokiOutputName = out.Name()

	hmacCfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: version,
		SaltValue:   []byte(salt),
		Algorithm:   hash,
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
	}

	if excludeLabels != nil {
		opts = append(opts, audit.WithNamedOutput(out, nil, nil, excludeLabels...))
		// Also add a capture output with no exclusions for comparison.
		capture := newCaptureOutput("capture-full")
		tc.CaptureOutput = capture
		opts = append(opts,
			audit.WithNamedOutput(capture, nil, nil),
			audit.WithOutputHMAC(capture.Name(), &audit.HMACConfig{
				Enabled:     true,
				SaltVersion: "v-capture",
				SaltValue:   []byte("capture-comparison16"),
				Algorithm:   "HMAC-SHA-256",
			}),
		)
	} else {
		opts = append(opts, audit.WithNamedOutput(out, nil, nil))
	}

	opts = append(opts, audit.WithOutputHMAC(tc.LokiOutputName, hmacCfg))

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		_ = out.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

// createLokiLoggerWithHMACAndCapture creates a Loki+capture logger
// for cross-output HMAC comparison (different salts).
func createLokiLoggerWithHMACAndCapture(tc *AuditTestContext, lokiSalt, lokiVersion string) error {
	cfg := defaultLokiTestConfig(tc)

	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.LokiOutputName = out.Name()

	capture := newCaptureOutput("capture-compare")
	tc.CaptureOutput = capture

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(out, nil, nil),
		audit.WithOutputHMAC(tc.LokiOutputName, &audit.HMACConfig{
			Enabled:     true,
			SaltVersion: lokiVersion,
			SaltValue:   []byte(lokiSalt),
			Algorithm:   "HMAC-SHA-256",
		}),
		audit.WithNamedOutput(capture, nil, nil),
		audit.WithOutputHMAC(capture.Name(), &audit.HMACConfig{
			Enabled:     true,
			SaltVersion: "v-capture",
			SaltValue:   []byte("capture-salt-beta16!"),
			Algorithm:   "HMAC-SHA-256",
		}),
	)
	if err != nil {
		_ = out.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

// verifyLokiEventHMAC queries Loki for the marker event and
// independently recomputes the HMAC to verify integrity.
func verifyLokiEventHMAC(tc *AuditTestContext, salt string) error {
	marker := tc.Markers["default"]
	raw, err := queryLokiForMarkerEvent(tc, marker)
	if err != nil {
		return err
	}
	return verifyEventHMAC(raw, salt)
}

// assertLokiAndCaptureHMACDiffer verifies that the HMAC value in
// the Loki event differs from the HMAC in the capture output.
func assertLokiAndCaptureHMACDiffer(tc *AuditTestContext) error {
	marker := tc.Markers["default"]

	lokiHMAC, err := extractLokiHMACField(tc, marker)
	if err != nil {
		return fmt.Errorf("loki HMAC: %w", err)
	}

	captureHMAC, err := extractCaptureHMACField(tc, marker)
	if err != nil {
		return fmt.Errorf("capture HMAC: %w", err)
	}

	if lokiHMAC == captureHMAC {
		return fmt.Errorf("expected different HMACs but both are %q", lokiHMAC)
	}
	return nil
}

// assertBothOutputsHaveHMAC verifies both Loki and capture events
// contain _hmac fields.
func assertBothOutputsHaveHMAC(tc *AuditTestContext) error {
	marker := tc.Markers["default"]
	if _, err := extractLokiHMACField(tc, marker); err != nil {
		return fmt.Errorf("loki: %w", err)
	}
	if _, err := extractCaptureHMACField(tc, marker); err != nil {
		return fmt.Errorf("capture: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

// defaultLokiTestConfig returns a Loki config with defaults matching
// the existing BDD test infrastructure (same tenant, static labels).
func defaultLokiTestConfig(tc *AuditTestContext) *loki.Config {
	return &loki.Config{
		URL:                tc.LokiURL + "/loki/api/v1/push",
		TenantID:           defaultLokiTenant,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      1e9,
		Timeout:            5e9,
		MaxRetries:         1,
		BufferSize:         1000,
		Compress:           true,
		Labels: loki.LabelConfig{
			Static: map[string]string{"test_suite": "bdd"},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// queryLokiForMarkerEvent polls Loki for an event containing the marker
// and returns the raw JSON log line as bytes.
func queryLokiForMarkerEvent(tc *AuditTestContext, marker string) ([]byte, error) {
	logql := fmt.Sprintf(`{app_name="bdd-audit"} |= %q`, marker)
	var lastErr error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		result, err := queryLokiBDD(tc, logql, "")
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, stream := range result.Data.Result {
			for _, v := range stream.Values {
				if len(v) >= 2 && strings.Contains(v[1], marker) {
					return []byte(v[1]), nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return nil, fmt.Errorf("loki query failed: %w", lastErr)
	}
	return nil, fmt.Errorf("marker %q not found in Loki within timeout", marker)
}

// extractLokiHMACField queries Loki for the marker event and returns
// the value of the _hmac field.
func extractLokiHMACField(tc *AuditTestContext, marker string) (string, error) {
	raw, err := queryLokiForMarkerEvent(tc, marker)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("parse loki event JSON: %w", err)
	}
	hmacVal, ok := m["_hmac"].(string)
	if !ok {
		return "", fmt.Errorf("_hmac field not found in Loki event")
	}
	return hmacVal, nil
}

// extractCaptureHMACField finds the marker event in the capture output
// and returns the value of the _hmac field.
func extractCaptureHMACField(tc *AuditTestContext, marker string) (string, error) {
	if tc.CaptureOutput == nil {
		return "", fmt.Errorf("no capture output configured")
	}
	for _, raw := range tc.CaptureOutput.Events() {
		if !containsMarker(raw, marker) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return "", fmt.Errorf("parse capture event JSON: %w", err)
		}
		hmacVal, ok := m["_hmac"].(string)
		if !ok {
			return "", fmt.Errorf("_hmac field not found in capture event")
		}
		return hmacVal, nil
	}
	return "", fmt.Errorf("marker %q not found in capture output", marker)
}

// containsMarker checks if a raw JSON byte slice contains the marker string.
func containsMarker(raw []byte, marker string) bool {
	return strings.Contains(string(raw), marker)
}

// assertJSONField checks that a raw JSON byte slice contains the given
// field with the expected value.
func assertJSONField(raw []byte, field, want string) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	got, ok := m[field]
	if !ok {
		return fmt.Errorf("field %q not found in event", field)
	}
	if fmt.Sprint(got) != want {
		return fmt.Errorf("field %q: want %q, got %q", field, want, got)
	}
	return nil
}
