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
	"fmt"
	"strings"

	audit "github.com/axonops/go-audit"
	"github.com/cucumber/godog"
)

// registerSeverityRoutingSteps registers BDD step definitions for
// severity-based event routing scenarios.
func registerSeverityRoutingSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSeverityTaxonomySteps(ctx, tc)
	registerSeverityLoggerSteps(ctx, tc)
	registerSeverityValidationSteps(ctx, tc)
	registerSeverityRuntimeSteps(ctx, tc)
}

func registerSeverityTaxonomySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a severity routing taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  security:
    severity: 8
    events: [auth_failure, permission_denied]
  write:
    severity: 4
    events: [user_create, config_update]
  read:
    severity: 2
    events: [user_get]
  critical:
    severity: 10
    events: [system_breach]
  info:
    severity: 1
    events: [health_check]
events:
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
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  config_update:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  user_get:
    fields:
      outcome: {required: true}
      marker: {}
  system_breach:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      marker: {}
  health_check:
    fields:
      outcome: {required: true}
      marker: {}
  custom_event:
    severity: 6
    fields:
      outcome: {required: true}
      marker: {}
`))
		if err != nil {
			return fmt.Errorf("parse severity routing taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
}

func registerSeverityLoggerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with stdout output routed with min_severity (\d+)$`, func(minSev int) error {
		return createSeverityRoutedLogger(tc, &minSev, nil, nil, nil)
	})

	ctx.Step(`^a logger with stdout output routed with max_severity (\d+)$`, func(maxSev int) error {
		return createSeverityRoutedLogger(tc, nil, &maxSev, nil, nil)
	})

	ctx.Step(`^a logger with stdout output routed with min_severity (\d+) and max_severity (\d+)$`, func(minSev, maxSev int) error {
		return createSeverityRoutedLogger(tc, &minSev, &maxSev, nil, nil)
	})

	ctx.Step(`^a logger with stdout output routed to include only "([^"]*)" with min_severity (\d+)$`, func(cat string, minSev int) error {
		include := []string{cat}
		return createSeverityRoutedLogger(tc, &minSev, nil, include, nil)
	})

	ctx.Step(`^a logger with stdout output routed to exclude "([^"]*)" with min_severity (\d+)$`, func(cat string, minSev int) error {
		exclude := []string{cat}
		return createSeverityRoutedLogger(tc, &minSev, nil, nil, exclude)
	})

	ctx.Step(`^a logger with named stdout output "([^"]*)" receiving all events$`, func(name string) error {
		tc.StdoutBuf = &bytes.Buffer{}
		stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}
		logger, err := audit.NewLogger(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(audit.WrapOutput(stdout, name)),
		)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		return nil
	})

	// Note: "the logger should be created successfully" is registered
	// in config_steps.go. Do not duplicate here.
}

func createSeverityRoutedLogger(tc *AuditTestContext, minSev, maxSev *int, includeCats, excludeCats []string) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		MinSeverity:       minSev,
		MaxSeverity:       maxSev,
		IncludeCategories: includeCats,
		ExcludeCategories: excludeCats,
	}
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(stdout, audit.OutputRoute(route)),
	)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	return nil
}

func registerSeverityValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a logger with route min_severity (\-?\d+)$`, func(minSev int) error {
		return trySeverityLoggerCreation(tc, &minSev, nil)
	})

	ctx.Step(`^I try to create a logger with route max_severity (\-?\d+)$`, func(maxSev int) error {
		return trySeverityLoggerCreation(tc, nil, &maxSev)
	})

	ctx.Step(`^I try to create a logger with route min_severity (\d+) and max_severity (\d+)$`, func(minSev, maxSev int) error {
		return trySeverityLoggerCreation(tc, &minSev, &maxSev)
	})

	ctx.Step(`^the logger creation should fail with error containing "([^"]*)"$`, func(expected string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", expected)
		}
		if !strings.Contains(tc.LastErr.Error(), expected) {
			return fmt.Errorf("error %q does not contain %q", tc.LastErr.Error(), expected)
		}
		return nil
	})
}

func trySeverityLoggerCreation(tc *AuditTestContext, minSev, maxSev *int) error {
	tc.StdoutBuf = &bytes.Buffer{}
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: tc.StdoutBuf})
	if err != nil {
		return fmt.Errorf("create stdout: %w", err)
	}
	route := &audit.EventRoute{
		MinSeverity: minSev,
		MaxSeverity: maxSev,
	}
	logger, lErr := audit.NewLogger(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(stdout, audit.OutputRoute(route)),
	)
	tc.LastErr = lErr
	if logger != nil {
		tc.Logger = logger
	}
	return nil
}

func registerSeverityRuntimeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I set output "([^"]*)" route to min_severity (\d+)$`, func(name string, minSev int) error {
		if tc.Logger == nil {
			return fmt.Errorf("logger not created")
		}
		route := &audit.EventRoute{MinSeverity: &minSev}
		return tc.Logger.SetOutputRoute(name, route)
	})
}
