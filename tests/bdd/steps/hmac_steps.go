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

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

func registerHMACSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerHMACGivenSteps(ctx, tc)
	registerHMACWhenSteps(ctx, tc)
	registerHMACThenSteps(ctx, tc)
}

func registerHMACGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with stdout output and HMAC enabled using salt "([^"]*)" version "([^"]*)" and hash "([^"]*)"$`,
		func(salt, version, hash string) error {
			tc.Taxonomy = newBasicTaxonomy()
			out := newCaptureOutput("stdout")
			tc.CaptureOutput = out

			logger, err := audit.NewLogger(
				audit.Config{Version: 1, Enabled: true},
				audit.WithTaxonomy(tc.Taxonomy),
				audit.WithNamedOutput(out, nil, nil),
				audit.WithOutputHMAC("stdout", &audit.HMACConfig{
					Enabled:     true,
					SaltVersion: version,
					SaltValue:   []byte(salt),
					Algorithm:   hash,
				}),
			)
			if err != nil {
				return fmt.Errorf("create logger with HMAC: %w", err)
			}
			tc.Logger = logger
			return nil
		})
}

func registerHMACWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a logger with HMAC salt "([^"]*)" version "([^"]*)" and hash "([^"]*)"$`,
		func(salt, version, hash string) error {
			tax := newBasicTaxonomy()
			out := newCaptureOutput("stdout")

			_, err := audit.NewLogger(
				audit.Config{Version: 1, Enabled: true},
				audit.WithTaxonomy(tax),
				audit.WithNamedOutput(out, nil, nil),
				audit.WithOutputHMAC("stdout", &audit.HMACConfig{
					Enabled:     true,
					SaltVersion: version,
					SaltValue:   []byte(salt),
					Algorithm:   hash,
				}),
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
	for _, raw := range capturedLines(tc) {
		if strings.Contains(string(raw), `"_hmac"`) {
			return fmt.Errorf("event unexpectedly contains _hmac field")
		}
	}
	return nil
}

func assertNoHMACVersionField(tc *AuditTestContext) error {
	for _, raw := range capturedLines(tc) {
		if strings.Contains(string(raw), `"_hmac_v"`) {
			return fmt.Errorf("event unexpectedly contains _hmac_v field")
		}
	}
	return nil
}

func registerHMACVerificationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^independently recomputing HMAC-SHA-256 over the payload with salt "([^"]*)" matches the "_hmac" value$`,
		func(salt string) error {
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
		})

	ctx.Step(`^logger creation should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("error %q does not contain %q", tc.LastErr.Error(), substr)
		}
		return nil
	})
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

	// Reconstruct the payload WITHOUT _hmac and _hmac_v.
	// The HMAC was computed over the JSON line before these
	// fields were appended.
	payload := stripHMACFields(raw)

	verified, err := audit.VerifyHMAC(payload, hmacVal, []byte(salt), "HMAC-SHA-256")
	if err != nil {
		return fmt.Errorf("verify HMAC: %w", err)
	}
	if !verified {
		return fmt.Errorf("HMAC verification failed — recomputed HMAC does not match")
	}
	return nil
}

// stripHMACFields removes the ,"_hmac":"..." and ,"_hmac_v":"..."
// fields from a JSON line, returning the payload as it was before
// HMAC was appended. This reconstructs the exact bytes the HMAC was
// computed over.
func stripHMACFields(line []byte) []byte {
	s := string(line)

	// Remove ,"_hmac":"hexvalue"
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

	// Remove ,"_hmac_v":"version"
	remaining := s[hmacEnd:]
	hmacvStart := strings.Index(remaining, `,"_hmac_v":"`)
	if hmacvStart < 0 {
		// Try without the comma (might be the only field).
		return []byte(s[:hmacStart] + remaining)
	}
	hmacvValStart := hmacvStart + len(`,"_hmac_v":"`)
	hmacvEnd := strings.Index(remaining[hmacvValStart:], `"`)
	if hmacvEnd < 0 {
		return []byte(s[:hmacStart] + remaining)
	}
	hmacvEnd = hmacvValStart + hmacvEnd + 1

	return []byte(s[:hmacStart] + remaining[hmacvEnd:])
}

// newBasicTaxonomy creates a simple taxonomy for HMAC BDD tests.
func newBasicTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version:           1,
		EmitEventCategory: true,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":  {Required: []string{"outcome"}},
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}
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
type captureOutput struct {
	name   string
	events [][]byte
}

func newCaptureOutput(name string) *captureOutput {
	return &captureOutput{name: name}
}

func (o *captureOutput) Write(data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	o.events = append(o.events, cp)
	return nil
}

func (o *captureOutput) Close() error { return nil }
func (o *captureOutput) Name() string { return o.name }

func (o *captureOutput) Events() [][]byte {
	return o.events
}
