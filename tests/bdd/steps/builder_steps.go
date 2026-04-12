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

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

func registerBuilderSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit via NewEvent "([^"]*)" with fields:$`,
		func(eventType string, table *godog.Table) error {
			fields := tableToFields(table)
			tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
			return nil
		})

	ctx.Step(`^I audit a nil event$`, func() error {
		tc.LastErr = tc.Logger.AuditEvent(nil)
		return nil
	})

	ctx.Step(`^the last error should contain "([^"]*)"$`,
		func(substr string) error {
			if tc.LastErr == nil {
				return fmt.Errorf("expected error containing %q, got nil", substr)
			}
			if !strings.Contains(tc.LastErr.Error(), substr) {
				return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
			}
			return nil
		})

	ctx.Step(`^the stdout output should contain event_type "([^"]*)"$`,
		func(eventType string) error {
			return assertStdoutContainsField(tc, "event_type", eventType)
		})

	ctx.Step(`^the stdout output should contain field "([^"]*)" with value "([^"]*)"$`,
		func(field, value string) error {
			return assertStdoutContainsField(tc, field, value)
		})
}

func assertStdoutContainsField(tc *AuditTestContext, field, value string) error {
	if tc.Logger != nil {
		_ = tc.Logger.Close()
		tc.Logger = nil
	}
	if tc.StdoutBuf == nil {
		return fmt.Errorf("no stdout buffer configured")
	}
	lines := strings.Split(strings.TrimSpace(tc.StdoutBuf.String()), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if v, ok := m[field]; ok && fmt.Sprintf("%v", v) == value {
			return nil
		}
	}
	return fmt.Errorf("no event with %q=%q in output:\n%s", field, value, tc.StdoutBuf.String())
}
