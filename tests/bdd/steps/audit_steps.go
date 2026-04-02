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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

// standardTaxonomyYAML is a realistic taxonomy used across most BDD
// scenarios. Consumers can copy this as a starting point for their own
// taxonomy definitions.
const standardTaxonomyYAML = `
version: 1

categories:
  write:
    - user_create
    - user_update
  security:
    - auth_failure
    - permission_denied

events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
      duration_ms: {}
  user_update:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  permission_denied:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
      resource: {}

`

func registerAuditSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerAuditGivenSteps(ctx, tc)
	registerAuditWhenSteps(ctx, tc)
	registerAuditThenSteps(ctx, tc)
}

func registerAuditGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a standard test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(standardTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse standard taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^a logger with stdout output$`, func() error {
		return createStdoutLogger(tc, audit.Config{
			Version: 1,
			Enabled: true,
		})
	})

	ctx.Step(`^a logger with stdout output and validation mode "([^"]*)"$`, func(mode string) error {
		return createStdoutLogger(tc, audit.Config{
			Version:        1,
			Enabled:        true,
			ValidationMode: audit.ValidationMode(mode),
		})
	})

	ctx.Step(`^a logger with stdout output and OmitEmpty "([^"]*)"$`, func(val string) error {
		cfg := audit.Config{Version: 1, Enabled: true}
		if val == "true" {
			cfg.OmitEmpty = true
		}
		return createStdoutLogger(tc, cfg)
	})

	ctx.Step(`^a disabled logger$`, func() error {
		return createStdoutLogger(tc, audit.Config{
			Version: 1,
			Enabled: false,
		})
	})
}

func registerAuditWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerAuditWhenBasicSteps(ctx, tc)
	registerAuditWhenHandleSteps(ctx, tc)
}

func registerAuditWhenBasicSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit event "([^"]*)" with fields:$`, func(eventType string, table *godog.Table) error {
		fields := tableToFields(table)
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with required fields$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with required fields and an unknown field "([^"]*)"$`, func(eventType, extraField string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields[extraField] = "extra_value"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event$`, func(eventType string) error {
		if tc.Logger == nil {
			return fmt.Errorf("logger is nil (construction may have failed: %w)", tc.LastErr)
		}
		m := marker("BDD")
		tc.Markers["default"] = m
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = m
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with empty fields$`, func(eventType string) error {
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, audit.Fields{}))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with nil fields$`, func(eventType string) error {
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, nil))
		return nil
	})

	ctx.Step(`^I close the logger$`, func() error {
		if tc.Logger == nil {
			return nil
		}
		tc.LastErr = tc.Logger.Close()
		return nil
	})

	ctx.Step(`^I try to audit event "([^"]*)" with required fields$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I get a handle for event type "([^"]*)"$`, func(eventType string) error {
		h, err := tc.Logger.Handle(eventType)
		if err != nil {
			tc.LastErr = err
			return nil //nolint:nilerr // scenario may assert on error
		}
		tc.EventHandle = h
		return nil
	})

	ctx.Step(`^I try to get a handle for event type "([^"]*)"$`, func(eventType string) error {
		_, err := tc.Logger.Handle(eventType)
		tc.LastErr = err
		return nil
	})

}

func registerAuditWhenHandleSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I must-handle event type "([^"]*)"$`, func(eventType string) error {
		defer func() {
			if r := recover(); r != nil {
				tc.LastErr = fmt.Errorf("%v", r)
			}
		}()
		h := tc.Logger.MustHandle(eventType)
		tc.EventHandle = h
		return nil
	})

	ctx.Step(`^the must-handle should have panicked$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected MustHandle to panic, but it did not")
		}
		return nil
	})

	ctx.Step(`^I fill the buffer and audit one more event$`, func() error {
		// The logger has buffer size 1. The drain goroutine processes
		// events async, so we need to fill the buffer faster than drain.
		// Send events in a tight loop until we get ErrBufferFull.
		for range 1000 {
			err := tc.Logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": "overflow",
			}))
			if err != nil {
				tc.LastErr = err
				return nil //nolint:nilerr // scenario asserts on tc.LastErr
			}
		}
		return fmt.Errorf("never got ErrBufferFull after 1000 attempts")
	})

	ctx.Step(`^a logger with stdout output and buffer size (\d+)$`, func(bufSize int) error {
		return createStdoutLogger(tc, audit.Config{
			Version:    1,
			Enabled:    true,
			BufferSize: bufSize,
		})
	})

	ctx.Step(`^I audit via handle with fields:$`, func(table *godog.Table) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no event handle set")
		}
		fields := tableToFields(table)
		tc.LastErr = tc.EventHandle.Audit(fields)
		return nil
	})
}

func registerAuditThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerAuditThenErrorSteps(ctx, tc)
	registerAuditThenHandleSteps(ctx, tc)
	registerAuditThenOutputSteps(ctx, tc)
}

func registerAuditThenErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerAuditThenExactErrorSteps(ctx, tc)
	registerAuditThenContainingErrorSteps(ctx, tc)
}

func registerAuditThenExactErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the event should be delivered successfully$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the audit call should return no error$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the audit call should return an error matching:$`, func(doc *godog.DocString) error {
		expected := strings.TrimSpace(doc.Content)
		if tc.LastErr == nil {
			return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
		}
		if tc.LastErr.Error() != expected {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
		}
		return nil
	})

	ctx.Step(`^the audit call should return error "([^"]*)"$`, func(exact string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error %q, got nil", exact)
		}
		if tc.LastErr.Error() != exact {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", exact, tc.LastErr.Error())
		}
		return nil
	})

}

func registerAuditThenContainingErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the audit call should return an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the error should mention "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error mentioning %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error mentioning %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

}

func registerAuditThenHandleSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the handle should be valid$`, func() error {
		if tc.EventHandle == nil {
			return fmt.Errorf("handle is nil")
		}
		return nil
	})
	ctx.Step(`^the handle name should be "([^"]*)"$`, func(name string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("handle is nil")
		}
		if tc.EventHandle.Name() != name {
			return fmt.Errorf("handle name: want %q, got %q", name, tc.EventHandle.Name())
		}
		return nil
	})
	ctx.Step(`^the handle should return an error$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected handle error, got nil")
		}
		return nil
	})
	ctx.Step(`^the handle should return an error wrapping "([^"]*)"$`, func(sentinel string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected handle error wrapping %q, got nil", sentinel)
		}
		switch sentinel {
		case "ErrHandleNotFound":
			if !errors.Is(tc.LastErr, audit.ErrHandleNotFound) {
				return fmt.Errorf("expected ErrHandleNotFound, got: %q", tc.LastErr.Error())
			}
		default:
			return fmt.Errorf("unknown sentinel: %s", sentinel)
		}
		return nil
	})
	ctx.Step(`^the output event timestamp should be a valid RFC3339 value$`, func() error {
		return assertStdoutTimestampValid(tc)
	})
	ctx.Step(`^the output event should not contain key "([^"]*)"$`, func(key string) error {
		return assertStdoutFirstEventKeyAbsent(tc, key)
	})
	ctx.Step(`^the output event should contain key "([^"]*)"$`, func(key string) error {
		return assertStdoutFirstEventKeyPresent(tc, key)
	})
}

func assertStdoutTimestampValid(tc *AuditTestContext) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in stdout")
	}
	ts, ok := events[0]["timestamp"].(string)
	if !ok {
		return fmt.Errorf("timestamp is not a string: %v", events[0]["timestamp"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		return fmt.Errorf("timestamp %q is not valid RFC3339Nano: %w", ts, err)
	}
	return nil
}

func assertStdoutFirstEventKeyAbsent(tc *AuditTestContext, key string) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in stdout")
	}
	if _, exists := events[0][key]; exists {
		return fmt.Errorf("expected key %q absent, but found with value %v", key, events[0][key])
	}
	return nil
}

func assertStdoutFirstEventKeyPresent(tc *AuditTestContext, key string) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in stdout")
	}
	if _, exists := events[0][key]; !exists {
		return fmt.Errorf("expected key %q present, but not found", key)
	}
	return nil
}

func registerAuditThenOutputSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^no events should be delivered$`, func() error { return assertNoEvents(tc) })
	ctx.Step(`^the output should contain an event with event_type "([^"]*)"$`, func(et string) error { return assertEventType(tc, et) })
	ctx.Step(`^the output should contain an event with field "([^"]*)"$`, func(f string) error { return assertFieldPresent(tc, f) })
	ctx.Step(`^the output should contain field "([^"]*)" with value "([^"]*)"$`, func(f, v string) error { return assertFieldValue(tc, f, v) })
	ctx.Step(`^the output should contain an event matching:$`, func(t *godog.Table) error { return assertEventMatching(tc, t) })
	ctx.Step(`^the audit call should return an error wrapping "([^"]*)"$`, func(s string) error { return assertSentinelError(tc, s) })
}

func assertNoEvents(tc *AuditTestContext) error {
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}
	if tc.StdoutBuf != nil {
		events, _ := parseJSONLines(tc.StdoutBuf.Bytes())
		if len(events) > 0 {
			return fmt.Errorf("expected no events, but got %d", len(events))
		}
	}
	return nil
}

func assertEventType(tc *AuditTestContext, eventType string) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	for _, e := range events {
		if e["event_type"] == eventType {
			return nil
		}
	}
	return fmt.Errorf("no event with event_type %q found in %d events", eventType, len(events))
}

func assertFieldPresent(tc *AuditTestContext, field string) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	for _, e := range events {
		if _, ok := e[field]; ok {
			return nil
		}
	}
	return fmt.Errorf("no event with field %q found in %d events", field, len(events))
}

func assertFieldValue(tc *AuditTestContext, field, value string) error {
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	for _, e := range events {
		if fmt.Sprintf("%v", e[field]) == value {
			return nil
		}
	}
	return fmt.Errorf("no event with field %q=%q found in %d events", field, value, len(events))
}

func assertEventMatching(tc *AuditTestContext, table *godog.Table) error {
	expected := tableToStringMap(table)
	events, err := getStdoutEvents(tc)
	if err != nil {
		return err
	}
	// Auto-populated fields that are allowed but not required in the table.
	autoFields := []string{"timestamp", "severity", "event_category", "pid"}
	for _, e := range events {
		match, mismatch := eventMatchesExactly(e, expected, autoFields)
		if match {
			return nil
		}
		// If only one event, report the mismatch directly.
		if len(events) == 1 {
			return fmt.Errorf("event does not match: %s", mismatch)
		}
	}
	return fmt.Errorf("no event matching expected fields in %d events", len(events))
}

func assertSentinelError(tc *AuditTestContext, sentinel string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error wrapping %q, got nil", sentinel)
	}
	switch sentinel {
	case "ErrClosed":
		if !errors.Is(tc.LastErr, audit.ErrClosed) {
			return fmt.Errorf("expected ErrClosed, got: %w", tc.LastErr)
		}
	case "ErrBufferFull":
		if !errors.Is(tc.LastErr, audit.ErrBufferFull) {
			return fmt.Errorf("expected ErrBufferFull, got: %w", tc.LastErr)
		}
	default:
		return fmt.Errorf("unknown sentinel: %s", sentinel)
	}
	return nil
}

// --- Internal helpers ---

// createStdoutLogger creates a logger with an in-memory stdout output.
func createStdoutLogger(tc *AuditTestContext, cfg audit.Config) error {
	buf := &bytes.Buffer{}
	tc.StdoutBuf = buf

	stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	if err != nil {
		return fmt.Errorf("create stdout output: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(stdoutOut),
	}
	if tc.MockMetrics != nil {
		opts = append(opts, audit.WithMetrics(tc.MockMetrics))
	}
	opts = append(opts, tc.Options...)

	logger, err := audit.NewLogger(cfg, opts...)
	if err != nil {
		// Store the error for scenarios that expect construction failure.
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

// getStdoutEvents closes the logger (to flush the drain) and parses
// JSON events from the stdout buffer. The logger must be closed before
// reading the buffer to avoid a data race with the drain goroutine.
func getStdoutEvents(tc *AuditTestContext) ([]map[string]any, error) {
	if tc.StdoutBuf == nil {
		return nil, fmt.Errorf("no stdout buffer configured")
	}
	// Close the logger to flush all pending events. Close is
	// idempotent, so calling it multiple times is safe.
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}
	return parseJSONLines(tc.StdoutBuf.Bytes())
}

// tableToFields converts a Godog table (field | value rows) to audit.Fields.
func tableToFields(table *godog.Table) audit.Fields {
	fields := make(audit.Fields)
	for _, row := range table.Rows[1:] { // skip header
		key := row.Cells[0].Value
		val := row.Cells[1].Value
		fields[key] = val
	}
	return fields
}

// tableToStringMap converts a Godog table to map[string]string.
func tableToStringMap(table *godog.Table) map[string]string {
	m := make(map[string]string)
	for _, row := range table.Rows[1:] { // skip header
		m[row.Cells[0].Value] = row.Cells[1].Value
	}
	return m
}

// defaultRequiredFields returns fields satisfying all required fields
// for the given event type, with sensible defaults.
func defaultRequiredFields(tax audit.Taxonomy, eventType string) audit.Fields {
	fields := make(audit.Fields)
	def, ok := tax.Events[eventType]
	if !ok {
		return fields
	}
	for _, f := range def.Required {
		switch f {
		case "outcome":
			fields[f] = "success"
		case "actor_id":
			fields[f] = "test-actor"
		default:
			fields[f] = "test-" + f
		}
	}
	return fields
}
