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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

func registerHMACSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerHMACGivenSteps(ctx, tc)
	registerHMACWhenSteps(ctx, tc)
	registerHMACThenSteps(ctx, tc)
	registerHMACLabelSteps(ctx, tc)
}

func registerHMACGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with stdout output and HMAC enabled using salt "([^"]*)" version "([^"]*)" and hash "([^"]*)"$`,
		func(salt, version, hash string) error {
			out := newCaptureOutput("stdout")
			tc.CaptureOutput = out

			auditor, err := audit.New(
				audit.WithTaxonomy(tc.Taxonomy),
				audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
					Enabled:     true,
					SaltVersion: version,
					SaltValue:   []byte(salt),
					Algorithm:   hash,
				})),
			)
			if err != nil {
				return fmt.Errorf("create auditor with HMAC: %w", err)
			}
			tc.Auditor = auditor
			return nil
		})
}

func registerHMACWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create an auditor with HMAC salt "([^"]*)" version "([^"]*)" and hash "([^"]*)"$`,
		func(salt, version, hash string) error {
			out := newCaptureOutput("stdout")

			_, err := audit.New(
				audit.WithTaxonomy(tc.Taxonomy),
				audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
					Enabled:     true,
					SaltVersion: version,
					SaltValue:   []byte(salt),
					Algorithm:   hash,
				})),
			)
			tc.LastErr = err
			return nil
		})
}

func registerHMACThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerHMACPresenceSteps(ctx, tc)
	registerHMACVerificationSteps(ctx, tc)
}

func registerHMACPresenceSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the output should contain "_hmac" field$`, func() error { return assertCapturedContainsHMAC(tc) })
	ctx.Step(`^the output should contain "_hmac_v" field with value "([^"]*)"$`, func(want string) error { return assertCapturedHMACVersion(tc, want) })
	ctx.Step(`^the output should not contain "_hmac" field$`, func() error { return assertNoHMACField(tc) })
	ctx.Step(`^the output should not contain "_hmac_v" field$`, func() error { return assertNoHMACVersionField(tc) })
	ctx.Step(`^the captured output should contain field "([^"]*)" with value "([^"]*)"$`,
		func(field, want string) error { return assertCapturedFieldValue(tc, field, want) })
}

// assertCapturedFieldValue asserts every captured event contains a
// JSON field with the given name and string value. Companion to the
// HMAC-specific assertions that also read from CaptureOutput.
// Added for the #508 "consolidated pre-HMAC batch" regression
// scenarios that need to pin event_category presence in captured
// output.
func assertCapturedFieldValue(tc *AuditTestContext, field, want string) error {
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured")
	}
	needle := fmt.Sprintf(`%q:%q`, field, want)
	for i, raw := range events {
		if !strings.Contains(string(raw), needle) {
			return fmt.Errorf("captured event %d does not contain %s (raw=%s)", i, needle, string(raw))
		}
	}
	return nil
}

func assertCapturedContainsHMAC(tc *AuditTestContext) error {
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range events {
		if !strings.Contains(string(raw), `"_hmac"`) {
			return fmt.Errorf("event does not contain _hmac field")
		}
	}
	return nil
}

func assertCapturedHMACVersion(tc *AuditTestContext, want string) error {
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range events {
		if err := assertHMACVersion(raw, want); err != nil {
			return err
		}
	}
	return nil
}

func assertNoHMACField(tc *AuditTestContext) error {
	lines := capturedLines(tc)
	if len(lines) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range lines {
		if strings.Contains(string(raw), `"_hmac"`) {
			return fmt.Errorf("event unexpectedly contains _hmac field")
		}
	}
	return nil
}

func assertNoHMACVersionField(tc *AuditTestContext) error {
	lines := capturedLines(tc)
	if len(lines) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range lines {
		if strings.Contains(string(raw), `"_hmac_v"`) {
			return fmt.Errorf("event unexpectedly contains _hmac_v field")
		}
	}
	return nil
}

func registerHMACVerificationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^independently recomputing HMAC-SHA-256 over the payload with salt "([^"]*)" matches the "_hmac" value$`,
		func(salt string) error { return verifyAllCapturedEvents(tc, salt) })

	ctx.Step(`^auditor creation should fail with an error containing "([^"]*)"$`,
		func(substr string) error { return assertLastErrContains(tc, substr) })

	// Salt-version authentication tamper-detection steps (issue #473).
	//
	// Together these verify that the HMAC covers _hmac_v and the rest of
	// the payload: tamper with a field, recompute the HMAC over the
	// tampered bytes (stripping only _hmac), and assert the HMAC does
	// NOT match.
	ctx.Step(`^I tamper with the "([^"]*)" field in the captured output setting it to "([^"]*)"$`,
		func(fieldName, newValue string) error {
			return tamperCapturedField(tc, fieldName, newValue)
		})

	ctx.Step(`^independently recomputing HMAC-SHA-256 over the tampered payload with salt "([^"]*)" does NOT match the "_hmac" value$`,
		func(salt string) error { return assertAllCapturedEventsTampered(tc, salt) })
}

func verifyAllCapturedEvents(tc *AuditTestContext, salt string) error {
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range events {
		if err := verifyEventHMAC(raw, salt); err != nil {
			return err
		}
	}
	return nil
}

func assertLastErrContains(tc *AuditTestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("error %q does not contain %q", tc.LastErr.Error(), substr)
	}
	return nil
}

func assertAllCapturedEventsTampered(tc *AuditTestContext, salt string) error {
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured")
	}
	for _, raw := range events {
		if err := assertTamperedHMACMismatches(raw, salt); err != nil {
			return err
		}
	}
	return nil
}

// tamperCapturedField replaces the JSON value of the named field in
// every captured event. Pre-condition: newValue must have the same
// length as the existing value (to keep the test simple — byte offsets
// don't shift). Verifier mismatch is the assertion target, not byte
// equality; this is sufficient for tamper-detection scenarios.
func tamperCapturedField(tc *AuditTestContext, fieldName, newValue string) error {
	if tc.CaptureOutput == nil {
		return fmt.Errorf("no capture output set")
	}
	events := tc.CaptureOutput.Events()
	if len(events) == 0 {
		return fmt.Errorf("no events captured to tamper with")
	}
	for i, raw := range events {
		s := string(raw)
		needle := fmt.Sprintf("%q:\"", fieldName)
		idx := strings.Index(s, needle)
		if idx < 0 {
			return fmt.Errorf("field %q not found in captured event %d", fieldName, i)
		}
		valStart := idx + len(needle)
		end := strings.Index(s[valStart:], `"`)
		if end < 0 {
			return fmt.Errorf("field %q value not closed in captured event %d", fieldName, i)
		}
		oldValue := s[valStart : valStart+end]
		if len(oldValue) != len(newValue) {
			return fmt.Errorf("tamper helper requires same-length replacement for field %q: existing %q (%d) vs new %q (%d)",
				fieldName, oldValue, len(oldValue), newValue, len(newValue))
		}
		tampered := s[:valStart] + newValue + s[valStart+end:]
		tc.CaptureOutput.ReplaceEvent(i, []byte(tampered))
	}
	return nil
}

// assertTamperedHMACMismatches strips only _hmac from the tampered raw
// bytes (leaving _hmac_v inside the authenticated region per issue
// #473), recomputes HMAC-SHA-256 with the given salt, and asserts it
// does NOT match the original _hmac value. If verification succeeds
// on tampered bytes, the HMAC has failed to cover the tampered field.
func assertTamperedHMACMismatches(raw []byte, salt string) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse event JSON: %w", err)
	}
	hmacVal, ok := m["_hmac"].(string)
	if !ok {
		return fmt.Errorf("_hmac field not found or not a string")
	}
	payload := stripHMACField(raw)
	verified, err := audit.VerifyHMAC(payload, hmacVal, []byte(salt), "HMAC-SHA-256")
	if err != nil {
		return fmt.Errorf("verify HMAC: %w", err)
	}
	if verified {
		return fmt.Errorf("expected HMAC verification to FAIL on tampered payload, but it succeeded")
	}
	return nil
}

func assertHMACVersion(raw []byte, want string) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse event JSON: %w", err)
	}
	got, ok := m["_hmac_v"]
	if !ok {
		return fmt.Errorf("event does not contain _hmac_v field")
	}
	if fmt.Sprint(got) != want {
		return fmt.Errorf("_hmac_v: want %q, got %q", want, got)
	}
	return nil
}

func verifyEventHMAC(raw []byte, salt string) error {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse event JSON: %w", err)
	}
	hmacVal, ok := m["_hmac"].(string)
	if !ok {
		return fmt.Errorf("_hmac field not found or not a string")
	}

	// Reconstruct the authenticated payload: strip ONLY the `_hmac`
	// field. `_hmac_v` (salt version) is inside the authenticated
	// region per issue #473 and must remain.
	payload := stripHMACField(raw)

	verified, err := audit.VerifyHMAC(payload, hmacVal, []byte(salt), "HMAC-SHA-256")
	if err != nil {
		return fmt.Errorf("verify HMAC: %w", err)
	}
	if !verified {
		return fmt.Errorf("HMAC verification failed — recomputed HMAC does not match")
	}
	return nil
}

// stripHMACField removes the `,"_hmac":"..."` field from a JSON line,
// returning the bytes the HMAC was computed over. `_hmac_v` is left
// intact because it is authenticated by the HMAC (issue #473).
func stripHMACField(line []byte) []byte {
	s := string(line)

	hmacStart := strings.Index(s, `,"_hmac":"`)
	if hmacStart < 0 {
		return line
	}
	// Find the end of the _hmac value (closing quote after hex).
	hmacValStart := hmacStart + len(`,"_hmac":"`)
	hmacEnd := strings.Index(s[hmacValStart:], `"`)
	if hmacEnd < 0 {
		return line
	}
	hmacEnd = hmacValStart + hmacEnd + 1

	return []byte(s[:hmacStart] + s[hmacEnd:])
}

// capturedLines returns raw event lines from CaptureOutput if available,
// otherwise falls back to splitting StdoutBuf by newline.
func capturedLines(tc *AuditTestContext) [][]byte {
	if tc.CaptureOutput != nil {
		return tc.CaptureOutput.Events()
	}
	if tc.StdoutBuf == nil {
		return nil
	}
	var lines [][]byte
	for _, line := range bytes.Split(tc.StdoutBuf.Bytes(), []byte("\n")) {
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

// captureOutput is a simple audit.Output that stores raw event bytes.
type captureOutput struct { //nolint:govet // fieldalignment: readability preferred
	mu     sync.Mutex
	name   string
	events [][]byte
}

func newCaptureOutput(name string) *captureOutput {
	return &captureOutput{name: name}
}

func (o *captureOutput) Write(data []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	o.events = append(o.events, cp)
	return nil
}

func (o *captureOutput) Close() error { return nil }
func (o *captureOutput) Name() string { return o.name }

func (o *captureOutput) Events() [][]byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([][]byte, len(o.events))
	copy(cp, o.events)
	return cp
}

// ReplaceEvent overwrites the i-th captured event's bytes in-place.
// Used by tamper-detection scenarios (issue #473) that mutate captured
// output and then recompute HMAC. Panics on out-of-range index to
// surface test authoring errors immediately.
func (o *captureOutput) ReplaceEvent(i int, data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	o.events[i] = cp
}

// registerHMACLabelSteps registers steps for testing HMAC with
// sensitivity label stripping — same event, different field sets,
// different HMACs.
func registerHMACLabelSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a taxonomy with PII sensitivity labels:$`, func(doc *godog.DocString) error {
		tax, err := audit.ParseTaxonomyYAML([]byte(doc.Content))
		if err != nil {
			return fmt.Errorf("parse taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
	ctx.Step(`^two HMAC-enabled outputs where "([^"]*)" excludes label "([^"]*)" using salts "([^"]*)" and "([^"]*)"$`,
		func(strippedName, label, fullSalt, strippedSalt string) error {
			return createDualHMACAuditor(tc, strippedName, label, fullSalt, strippedSalt)
		})
	ctx.Step(`^output "([^"]*)" should contain field "([^"]*)" with value "([^"]*)"$`,
		func(outputName, field, want string) error {
			return assertNamedOutputField(tc, outputName, field, want)
		})
	ctx.Step(`^output "([^"]*)" should not contain field "([^"]*)"$`,
		func(outputName, field string) error {
			return assertNamedOutputNoField(tc, outputName, field)
		})
	ctx.Step(`^both outputs should have "_hmac" fields$`, func() error {
		return assertAllOutputsHaveHMAC(tc)
	})
	ctx.Step(`^the "_hmac" values should differ between "([^"]*)" and "([^"]*)"$`,
		func(name1, name2 string) error {
			return assertHMACsDiffer(tc, name1, name2)
		})
	ctx.Step(`^output "([^"]*)" HMAC should verify with salt "([^"]*)"$`,
		func(outputName, salt string) error {
			return assertNamedOutputHMACVerifies(tc, outputName, salt)
		})
	ctx.Step(`^output "([^"]*)" HMAC should NOT verify with salt "([^"]*)"$`,
		func(outputName, salt string) error {
			return assertNamedOutputHMACDoesNotVerify(tc, outputName, salt)
		})
}

func assertNamedOutputHMACVerifies(tc *AuditTestContext, outputName, salt string) error {
	out, ok := tc.CaptureOutputs[outputName]
	if !ok {
		return fmt.Errorf("unknown output %q", outputName)
	}
	events := out.Events()
	if len(events) == 0 {
		return fmt.Errorf("output %q has no events", outputName)
	}
	for _, raw := range events {
		if err := verifyEventHMAC(raw, salt); err != nil {
			return fmt.Errorf("output %q: %w", outputName, err)
		}
	}
	return nil
}

func assertNamedOutputHMACDoesNotVerify(tc *AuditTestContext, outputName, salt string) error {
	out, ok := tc.CaptureOutputs[outputName]
	if !ok {
		return fmt.Errorf("unknown output %q", outputName)
	}
	events := out.Events()
	if len(events) == 0 {
		return fmt.Errorf("output %q has no events", outputName)
	}
	for _, raw := range events {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("parse %q event: %w", outputName, err)
		}
		hmacVal, ok := m["_hmac"].(string)
		if !ok {
			return fmt.Errorf("output %q: _hmac missing", outputName)
		}
		payload := stripHMACField(raw)
		verified, err := audit.VerifyHMAC(payload, hmacVal, []byte(salt), "HMAC-SHA-256")
		if err != nil {
			return fmt.Errorf("output %q: verify HMAC: %w", outputName, err)
		}
		if verified {
			return fmt.Errorf("output %q: HMAC unexpectedly verified with foreign salt %q", outputName, salt)
		}
	}
	return nil
}

func createDualHMACAuditor(tc *AuditTestContext, strippedName, label, fullSalt, strippedSalt string) error {
	fullOut := newCaptureOutput("full")
	strippedOut := newCaptureOutput(strippedName)
	tc.CaptureOutputs = map[string]*captureOutput{
		"full":       fullOut,
		strippedName: strippedOut,
	}

	// Different salts per output — proves each output applies its own
	// HMAC config independently, not a shared singleton.
	fullHMACCfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte(fullSalt),
		Algorithm:   "HMAC-SHA-256",
	}
	strippedHMACCfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v2",
		SaltValue:   []byte(strippedSalt),
		Algorithm:   "HMAC-SHA-256",
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(fullOut, audit.WithHMAC(fullHMACCfg)),
		audit.WithNamedOutput(strippedOut, audit.WithExcludeLabels(label), audit.WithHMAC(strippedHMACCfg)),
	)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	return nil
}

func assertAllOutputsHaveHMAC(tc *AuditTestContext) error {
	for name, out := range tc.CaptureOutputs {
		events := out.Events()
		if len(events) == 0 {
			return fmt.Errorf("output %q has no events", name)
		}
		for _, raw := range events {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				return fmt.Errorf("parse %q event: %w", name, err)
			}
			if _, ok := m["_hmac"]; !ok {
				return fmt.Errorf("output %q event missing _hmac", name)
			}
		}
	}
	return nil
}

func assertNamedOutputField(tc *AuditTestContext, outputName, field, want string) error {
	out, ok := tc.CaptureOutputs[outputName]
	if !ok {
		return fmt.Errorf("unknown output %q", outputName)
	}
	events := out.Events()
	if len(events) == 0 {
		return fmt.Errorf("output %q has no events", outputName)
	}
	var m map[string]any
	if err := json.Unmarshal(events[0], &m); err != nil {
		return fmt.Errorf("parse event: %w", err)
	}
	got, ok := m[field]
	if !ok {
		return fmt.Errorf("output %q event missing field %q", outputName, field)
	}
	if fmt.Sprint(got) != want {
		return fmt.Errorf("output %q field %q: want %q, got %q", outputName, field, want, got)
	}
	return nil
}

func assertNamedOutputNoField(tc *AuditTestContext, outputName, field string) error {
	out, ok := tc.CaptureOutputs[outputName]
	if !ok {
		return fmt.Errorf("unknown output %q", outputName)
	}
	events := out.Events()
	if len(events) == 0 {
		return fmt.Errorf("output %q has no events", outputName)
	}
	var m map[string]any
	if err := json.Unmarshal(events[0], &m); err != nil {
		return fmt.Errorf("parse event: %w", err)
	}
	if _, ok := m[field]; ok {
		return fmt.Errorf("output %q unexpectedly contains field %q", outputName, field)
	}
	return nil
}

func assertHMACsDiffer(tc *AuditTestContext, name1, name2 string) error {
	out1, ok := tc.CaptureOutputs[name1]
	if !ok {
		return fmt.Errorf("unknown output %q", name1)
	}
	out2, ok := tc.CaptureOutputs[name2]
	if !ok {
		return fmt.Errorf("unknown output %q", name2)
	}
	events1 := out1.Events()
	events2 := out2.Events()
	if len(events1) == 0 || len(events2) == 0 {
		return fmt.Errorf("both outputs must have at least one event")
	}

	var m1, m2 map[string]any
	if err := json.Unmarshal(events1[0], &m1); err != nil {
		return fmt.Errorf("parse %q event: %w", name1, err)
	}
	if err := json.Unmarshal(events2[0], &m2); err != nil {
		return fmt.Errorf("parse %q event: %w", name2, err)
	}

	hmac1, _ := m1["_hmac"].(string)
	hmac2, _ := m2["_hmac"].(string)

	if hmac1 == "" || hmac2 == "" {
		return fmt.Errorf("both outputs must have _hmac values")
	}
	if hmac1 == hmac2 {
		return fmt.Errorf("HMACs should differ: %q has %q and %q has %q (same payload means stripping did not work)",
			name1, hmac1, name2, hmac2)
	}
	return nil
}
