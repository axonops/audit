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
    category: write
    required: [outcome, actor_id]
    optional: [marker, target_id, target_type, reason, source_ip, user_agent, request_id, duration_ms]
  user_update:
    category: write
    required: [outcome, actor_id]
    optional: [marker, target_id]
  auth_failure:
    category: security
    required: [outcome, actor_id]
    optional: [marker, source_ip, reason]
  permission_denied:
    category: security
    required: [outcome, actor_id]
    optional: [marker, resource]

default_enabled:
  - write
  - security
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
	ctx.Step(`^I audit event "([^"]*)" with fields:$`, func(eventType string, table *godog.Table) error {
		fields := tableToFields(table)
		tc.LastErr = tc.Logger.Audit(eventType, fields)
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with required fields$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.Logger.Audit(eventType, fields)
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with required fields and an unknown field "([^"]*)"$`, func(eventType, extraField string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields[extraField] = "extra_value"
		tc.LastErr = tc.Logger.Audit(eventType, fields)
		return nil
	})

	ctx.Step(`^I audit a uniquely marked "([^"]*)" event$`, func(eventType string) error {
		m := marker("BDD")
		tc.Markers["default"] = m
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = m
		tc.LastErr = tc.Logger.Audit(eventType, fields)
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
		tc.LastErr = tc.Logger.Audit(eventType, fields)
		return nil
	})
}

func registerAuditThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerAuditThenErrorSteps(ctx, tc)
	registerAuditThenOutputSteps(ctx, tc)
}

func registerAuditThenErrorSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
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
	for _, e := range events {
		if match, _ := eventContainsAllFields(e, expected); match {
			return nil
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
