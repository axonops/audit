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
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

func registerLifecycleSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLifecycleGivenSteps(ctx, tc)
	registerLifecycleWhenSteps(ctx, tc)
	registerLifecycleThenSteps(ctx, tc)
}

func registerLifecycleGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output at a temporary path and buffer size (\d+)$`, func(bufSize int) error {
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true, BufferSize: bufSize}, file.Config{})
	})
}

func registerLifecycleWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I emit startup with app name "([^"]*)"$`, func(appName string) error {
		tc.LastErr = tc.Logger.EmitStartup(audit.Fields{"app_name": appName})
		return nil
	})
	ctx.Step(`^I fill the buffer and emit startup with app name "([^"]*)"$`, func(appName string) error {
		// Fill the buffer to capacity then try EmitStartup.
		for range 100 {
			err := tc.Logger.Audit("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": "filler",
			})
			if err != nil {
				break // buffer full
			}
		}
		tc.LastErr = tc.Logger.EmitStartup(audit.Fields{"app_name": appName})
		return nil
	})

	ctx.Step(`^I emit startup without app name$`, func() error {
		tc.LastErr = tc.Logger.EmitStartup(audit.Fields{})
		return nil
	})
	ctx.Step(`^I try to emit startup with app name "([^"]*)"$`, func(appName string) error {
		tc.LastErr = tc.Logger.EmitStartup(audit.Fields{"app_name": appName})
		return nil
	})
}

func registerLifecycleThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should contain an event with event_type "([^"]*)" and field "([^"]*)" with value "([^"]*)"$`,
		func(et, f, v string) error { return assertFileEventTypeAndField(tc, et, f, v) })
	ctx.Step(`^the file should not contain an event with event_type "([^"]*)"$`,
		func(et string) error { return assertFileEventTypeAbsent(tc, et) })
	ctx.Step(`^the startup call should return an error matching:$`,
		func(doc *godog.DocString) error { return assertStartupExactError(tc, strings.TrimSpace(doc.Content)) })
	ctx.Step(`^the startup call should return an error containing "([^"]*)"$`,
		func(s string) error { return assertStartupErrorContaining(tc, s) })
	ctx.Step(`^the startup call should return an error wrapping "([^"]*)"$`,
		func(s string) error { return assertStartupSentinel(tc, s) })
}

func assertFileEventTypeAndField(tc *AuditTestContext, eventType, field, value string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	for _, e := range events {
		if e["event_type"] == eventType && formatFieldValue(e[field]) == value {
			return nil
		}
	}
	return fmt.Errorf("no event with event_type=%q and %s=%q in file (%d events)", eventType, field, value, len(events))
}

func assertFileEventTypeAbsent(tc *AuditTestContext, eventType string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	for _, e := range events {
		if e["event_type"] == eventType {
			return fmt.Errorf("found unexpected event with event_type %q", eventType)
		}
	}
	return nil
}

func assertStartupExactError(tc *AuditTestContext, expected string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
	}
	if tc.LastErr.Error() != expected {
		return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
	}
	return nil
}

func assertStartupErrorContaining(tc *AuditTestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected startup error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}

func assertStartupSentinel(tc *AuditTestContext, sentinel string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected startup error wrapping %q, got nil", sentinel)
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
