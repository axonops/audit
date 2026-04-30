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

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
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

	// Step used to exercise the 128-byte length cap (#477). A 200-byte
	// event-type name is assembled programmatically and wrapped in the
	// smallest valid-shape YAML that references it. Keeping the name
	// generation in Go — rather than a literal in the feature file —
	// keeps the scenario text readable.
	ctx.Step(`^a taxonomy from YAML with a 200-byte event type name$`, func() error {
		longName := strings.Repeat("a", 200)
		yml := "version: 1\ncategories:\n  write:\n    - " + longName +
			"\nevents:\n  " + longName + ":\n    fields:\n      outcome: {required: true}\n"
		tax, err := audit.ParseTaxonomyYAML([]byte(yml))
		if err != nil {
			tc.LastErr = err
			return nil //nolint:nilerr // scenario asserts on tc.LastErr
		}
		tc.Taxonomy = tax
		return nil
	})

	// Step used to exercise the 128-byte boundary as an accept case.
	ctx.Step(`^a taxonomy from YAML with a 128-byte event type name$`, func() error {
		name := strings.Repeat("a", 128)
		yml := "version: 1\ncategories:\n  write:\n    - " + name +
			"\nevents:\n  " + name + ":\n    fields:\n      outcome: {required: true}\n"
		tax, err := audit.ParseTaxonomyYAML([]byte(yml))
		if err != nil {
			tc.LastErr = err
			return nil //nolint:nilerr // scenario asserts on tc.LastErr
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
    fields:
      outcome: {required: true}
` + "\nsome trailing garbage that is not valid YAML"
		_, err := audit.ParseTaxonomyYAML([]byte(yamlWithGarbage))
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to parse a valid taxonomy that exceeds 1 MiB$`, func() error {
		// Build a syntactically valid taxonomy that crosses the old
		// 1 MiB ceiling by a margin (#646). Locks the post-cap-
		// removal contract: large taxonomies parse, no "exceeds
		// maximum" error is produced.
		data := testhelper.BuildLargeTaxonomyYAML(20000, false)
		_, err := audit.ParseTaxonomyYAML(data)
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
	ctx.Step(`^the taxonomy parse should succeed$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected taxonomy parse to succeed, got: %w", tc.LastErr)
		}
		return nil
	})
	ctx.Step(`^the taxonomy parse should fail with an error$`, func() error { return assertTaxonomyParseError(tc) })
	ctx.Step(`^the taxonomy parse should fail with an error containing "([^"]*)"$`, func(s string) error { return assertTaxonomyParseErrorContaining(tc, s) })
	ctx.Step(`^the taxonomy should contain event type "([^"]*)"$`, func(et string) error { return assertTaxonomyHasEvent(tc, et) })
	ctx.Step(`^the taxonomy should contain category "([^"]*)"$`, func(c string) error { return assertTaxonomyHasCategory(tc, c) })
	ctx.Step(`^the taxonomy event "([^"]*)" should require field "([^"]*)"$`, func(et, f string) error { return assertTaxonomyEventRequires(tc, et, f) })

	// Assert that the parse error does not re-render bidi or control
	// bytes verbatim. Uses %q-style escaping so CVE-2021-42574 class
	// terminal-output hijacking is prevented when errors are printed.
	ctx.Step(`^the taxonomy parse error should not contain raw bidi bytes$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected an error, got nil")
		}
		msg := tc.LastErr.Error()
		for _, r := range []rune{'\u202e', '\u202d', '\u2066', '\u2067', '\u2068', '\u2069'} {
			if strings.ContainsRune(msg, r) {
				return fmt.Errorf("error message contains raw bidi rune %q; expected %%q escape", r)
			}
		}
		return nil
	})

	// Assert that the parse error renders bidi chars as Go escape
	// sequences. The argument is the Go escape form (e.g. "\u202e").
	ctx.Step(`^the taxonomy parse error should contain escaped "([^"]*)"$`, func(escape string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected an error, got nil")
		}
		if !strings.Contains(tc.LastErr.Error(), escape) {
			return fmt.Errorf("error message does not contain escape %q; got:\n  %q", escape, tc.LastErr.Error())
		}
		return nil
	})
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
	case "ErrInvalidTaxonomyName":
		if !errors.Is(tc.LastErr, audit.ErrInvalidTaxonomyName) {
			return fmt.Errorf("expected ErrInvalidTaxonomyName, got:\n  %q", tc.LastErr.Error())
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
