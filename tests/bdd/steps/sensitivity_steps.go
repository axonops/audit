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

func registerSensitivitySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSensitivityGivenSteps(ctx, tc)
	registerSensitivityWhenSteps(ctx, tc)
	registerSensitivityThenSteps(ctx, tc)
}

func registerSensitivityGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a taxonomy without sensitivity labels:$`, func(doc *godog.DocString) error {
		return parseSensitivityTaxonomy(tc, doc.Content)
	})
	ctx.Step(`^a taxonomy with sensitivity labels:$`, func(doc *godog.DocString) error {
		return parseSensitivityTaxonomy(tc, doc.Content)
	})
}

func registerSensitivityWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with stdout output$`, func() error {
		return createSensitivityLogger(tc)
	})
}

func createSensitivityLogger(tc *AuditTestContext) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout output: %w", err)
	}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func registerSensitivityThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the taxonomy should have field "([^"]*)" labeled "([^"]*)" on event "([^"]*)"$`,
		func(field, label, eventType string) error {
			return assertFieldLabeled(tc, eventType, field, label)
		})
	ctx.Step(`^the taxonomy should not have field "([^"]*)" labeled on event "([^"]*)"$`,
		func(field, eventType string) error {
			return assertFieldNotLabeled(tc, eventType, field)
		})
	ctx.Step(`^the output should contain an event with field "([^"]*)" value "([^"]*)"$`,
		func(field, value string) error {
			return assertOutputContainsFieldValue(tc, field, value)
		})
}

func parseSensitivityTaxonomy(tc *AuditTestContext, yamlContent string) error {
	tax, err := audit.ParseTaxonomyYAML([]byte(yamlContent))
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Taxonomy = tax
	tc.LastErr = nil
	return nil
}

func assertFieldLabeled(tc *AuditTestContext, eventType, field, label string) error {
	def, ok := tc.Taxonomy.Events[eventType]
	if !ok {
		return fmt.Errorf("event type %q not found in taxonomy", eventType)
	}
	if def.FieldLabels == nil {
		return fmt.Errorf("event %q has no FieldLabels (nil)", eventType)
	}
	fieldLabels, ok := def.FieldLabels[field]
	if !ok {
		return fmt.Errorf("event %q field %q has no labels", eventType, field)
	}
	if _, ok := fieldLabels[label]; !ok {
		labels := make([]string, 0, len(fieldLabels))
		for l := range fieldLabels {
			labels = append(labels, l)
		}
		return fmt.Errorf("event %q field %q does not have label %q (has: %v)",
			eventType, field, label, labels)
	}
	return nil
}

func assertOutputContainsFieldValue(tc *AuditTestContext, field, value string) error {
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
	return fmt.Errorf("no event found with field %q = %q in output:\n%s",
		field, value, tc.StdoutBuf.String())
}

func assertFieldNotLabeled(tc *AuditTestContext, eventType, field string) error {
	def, ok := tc.Taxonomy.Events[eventType]
	if !ok {
		return fmt.Errorf("event type %q not found in taxonomy", eventType)
	}
	if def.FieldLabels == nil {
		return nil // no labels at all — pass
	}
	if _, ok := def.FieldLabels[field]; ok {
		return fmt.Errorf("event %q field %q has labels but should not", eventType, field)
	}
	return nil
}
