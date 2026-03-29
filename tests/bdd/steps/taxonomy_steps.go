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
)

func registerTaxonomySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerTaxonomyGivenSteps(ctx, tc)
	registerTaxonomyWhenSteps(ctx, tc)
	registerTaxonomyThenSteps(ctx, tc)
}

func registerTaxonomyGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a taxonomy from YAML:$`, func(yamlDoc *godog.DocString) error {
		tax, err := audit.ParseTaxonomyYAML([]byte(yamlDoc.Content))
		if err != nil {
			tc.LastErr = err
			return nil //nolint:nilerr // scenario may assert on tc.LastErr
		}
		tc.Taxonomy = tax
		return nil
	})
}

func registerTaxonomyWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to parse taxonomy from YAML:$`, func(yamlDoc *godog.DocString) error {
		_, err := audit.ParseTaxonomyYAML([]byte(yamlDoc.Content))
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to parse taxonomy from empty YAML$`, func() error {
		_, err := audit.ParseTaxonomyYAML(nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to parse taxonomy YAML with trailing garbage$`, func() error {
		yamlWithGarbage := `version: 1
categories:
  write:
    - user_create
events:
  user_create:
    category: write
    required: [outcome]
default_enabled:
  - write
` + "\nsome trailing garbage that is not valid YAML"
		_, err := audit.ParseTaxonomyYAML([]byte(yamlWithGarbage))
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to parse taxonomy from YAML exceeding 1 MiB$`, func() error {
		oversized := make([]byte, 1<<20+1)
		for i := range oversized {
			oversized[i] = 'x'
		}
		_, err := audit.ParseTaxonomyYAML(oversized)
		tc.LastErr = err
		return nil
	})
}

func registerTaxonomyThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the taxonomy parse should fail with exact error:$`, func(doc *godog.DocString) error {
		return assertTaxonomyParseExactError(tc, strings.TrimSpace(doc.Content))
	})
	ctx.Step(`^the taxonomy parse should fail wrapping "([^"]*)"$`, func(sentinel string) error {
		return assertTaxonomyParseSentinel(tc, sentinel)
	})
	ctx.Step(`^the taxonomy parse should fail with an error$`, func() error { return assertTaxonomyParseError(tc) })
	ctx.Step(`^the taxonomy parse should fail with an error containing "([^"]*)"$`, func(s string) error { return assertTaxonomyParseErrorContaining(tc, s) })
	ctx.Step(`^the taxonomy should contain event type "([^"]*)"$`, func(et string) error { return assertTaxonomyHasEvent(tc, et) })
	ctx.Step(`^the taxonomy should contain category "([^"]*)"$`, func(c string) error { return assertTaxonomyHasCategory(tc, c) })
	ctx.Step(`^the taxonomy default enabled should include "([^"]*)"$`, func(c string) error { return assertTaxonomyDefaultEnabledIncludes(tc, c) })
	ctx.Step(`^the taxonomy event "([^"]*)" should require field "([^"]*)"$`, func(et, f string) error { return assertTaxonomyEventRequires(tc, et, f) })
}

func assertTaxonomyParseSentinel(tc *AuditTestContext, sentinel string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error wrapping %q, got nil", sentinel)
	}
	switch sentinel {
	case "ErrInvalidInput":
		if !errors.Is(tc.LastErr, audit.ErrInvalidInput) {
			return fmt.Errorf("expected ErrInvalidInput, got:\n  %q", tc.LastErr.Error())
		}
	case "ErrTaxonomyInvalid":
		if !errors.Is(tc.LastErr, audit.ErrTaxonomyInvalid) {
			return fmt.Errorf("expected ErrTaxonomyInvalid, got:\n  %q", tc.LastErr.Error())
		}
	default:
		return fmt.Errorf("unknown sentinel: %s", sentinel)
	}
	return nil
}

func assertTaxonomyParseExactError(tc *AuditTestContext, expected string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
	}
	if tc.LastErr.Error() != expected {
		return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
	}
	return nil
}

func assertTaxonomyParseError(tc *AuditTestContext) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected taxonomy parse error, got nil")
	}
	return nil
}

func assertTaxonomyParseErrorContaining(tc *AuditTestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected taxonomy parse error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}

func assertTaxonomyHasEvent(tc *AuditTestContext, eventType string) error {
	if _, ok := tc.Taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("taxonomy does not contain event type %q", eventType)
	}
	return nil
}

func assertTaxonomyHasCategory(tc *AuditTestContext, category string) error {
	if _, ok := tc.Taxonomy.Categories[category]; !ok {
		return fmt.Errorf("taxonomy does not contain category %q", category)
	}
	return nil
}

func assertTaxonomyDefaultEnabledIncludes(tc *AuditTestContext, category string) error {
	for _, c := range tc.Taxonomy.DefaultEnabled {
		if c == category {
			return nil
		}
	}
	return fmt.Errorf("DefaultEnabled does not include %q (enabled: %v)", category, tc.Taxonomy.DefaultEnabled)
}

func assertTaxonomyEventRequires(tc *AuditTestContext, eventType, field string) error {
	def, ok := tc.Taxonomy.Events[eventType]
	if !ok {
		return fmt.Errorf("event type %q not found in taxonomy", eventType)
	}
	for _, f := range def.Required {
		if f == field {
			return nil
		}
	}
	return fmt.Errorf("event %q does not require field %q (required: %v)", eventType, field, def.Required)
}
