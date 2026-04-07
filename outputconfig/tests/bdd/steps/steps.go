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

// Package steps provides Godog step definitions for outputconfig BDD tests.
package steps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	_ "github.com/axonops/go-audit/file" // register file factory
	"github.com/axonops/go-audit/outputconfig"
)

func init() {
	// Register a stub "loki" factory for BDD tests that validate
	// outputconfig formatter behaviour without depending on the real
	// Loki module. The stub ignores the raw config and returns a
	// minimal output.
	audit.RegisterOutputFactory("loki", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return &lokiStub{}, nil
	})
}

// lokiStub is a minimal output stub for Loki formatter BDD tests.
type lokiStub struct{}

func (l *lokiStub) Write([]byte) error { return nil }
func (l *lokiStub) Close() error       { return nil }
func (l *lokiStub) Name() string       { return "loki-stub" }

// TestContext holds mutable state for a single BDD scenario.
type TestContext struct { //nolint:govet // fieldalignment: readability preferred
	Taxonomy   audit.Taxonomy
	Logger     *audit.Logger
	Options    []audit.Option
	LoadResult *outputconfig.LoadResult
	LastErr    error
	FileDir    string
}

// Reset prepares the context for a new scenario.
func (tc *TestContext) Reset() {
	tc.Logger = nil
	tc.Options = nil
	tc.LoadResult = nil
	tc.LastErr = nil
	tc.FileDir = ""
}

// InitializeScenario wires all step definitions.
func InitializeScenario(ctx *godog.ScenarioContext) {
	tc := &TestContext{}

	ctx.Before(func(goctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc.Reset()
		return goctx, nil
	})

	ctx.After(func(goctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		if tc.FileDir != "" {
			_ = os.RemoveAll(tc.FileDir)
		}
		_ = os.Unsetenv("AUDIT_BDD_DIR")
		return goctx, nil
	})

	registerGivenSteps(ctx, tc)
	registerWhenSteps(ctx, tc)
	registerThenSteps(ctx, tc)
}

func registerGivenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^a test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
    - user_delete
  security:
    - auth_failure
  read:
    - user_read
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  user_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
  user_read:
    fields:
      outcome: {required: true}
`))
		if err != nil {
			return fmt.Errorf("parse taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^the following output configuration YAML:$`, func(doc *godog.DocString) error {
		dir, err := os.MkdirTemp("", "bdd-outputconfig-*")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		tc.FileDir = dir
		_ = os.Setenv("AUDIT_BDD_DIR", dir)

		result, loadErr := outputconfig.Load([]byte(doc.Content), &tc.Taxonomy, nil)
		if loadErr != nil {
			tc.LastErr = loadErr
			return nil //nolint:nilerr // scenario may assert on tc.LastErr
		}
		tc.Options = result.Options
		tc.LoadResult = result
		return nil
	})
}

func registerWhenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^I create a logger from the YAML config$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("config load already failed: %w", tc.LastErr)
		}
		opts := []audit.Option{audit.WithTaxonomy(tc.Taxonomy)}
		opts = append(opts, tc.Options...)
		logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		return nil
	})

	ctx.Step(`^I try to create a logger from the YAML config$`, func() error {
		if tc.LastErr != nil {
			return nil //nolint:nilerr // Load already set tc.LastErr
		}
		opts := []audit.Option{audit.WithTaxonomy(tc.Taxonomy)}
		opts = append(opts, tc.Options...)
		logger, logErr := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
		if logErr != nil {
			tc.LastErr = logErr
			return nil //nolint:nilerr // scenario asserts on tc.LastErr
		}
		tc.Logger = logger
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with fields:$`, func(eventType string, table *godog.Table) error {
		if tc.Logger == nil {
			return fmt.Errorf("no logger created")
		}
		fields := audit.Fields{}
		for _, row := range table.Rows[1:] { // skip header
			fields[row.Cells[0].Value] = row.Cells[1].Value
		}
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I close the logger$`, func() error {
		if tc.Logger == nil {
			return nil
		}
		tc.LastErr = tc.Logger.Close()
		return nil
	})
}

func registerThenSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^the audit call should have succeeded$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the config load should fail with an error containing "([^"]*)"$`, func(substr string) error {
		return assertError(tc, substr)
	})

	ctx.Step(`^the config load should succeed$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected config load to succeed, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the config load error should contain "([^"]*)"$`, func(substr string) error {
		return assertError(tc, substr)
	})

	ctx.Step(`^the loki output formatter should be JSON$`, func() error {
		return assertLokiFormatterJSON(tc)
	})

	registerFileAssertionSteps(ctx, tc)
}

func registerFileAssertionSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(`^the file "([^"]*)" should contain "([^"]*)"$`, func(filename, text string) error {
		path := filepath.Join(tc.FileDir, filename)
		data, err := os.ReadFile(path) //nolint:gosec // test fixture path
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}
		if !strings.Contains(string(data), text) {
			return fmt.Errorf("file %s does not contain %q", filename, text)
		}
		return nil
	})

	ctx.Step(`^the file "([^"]*)" should not contain "([^"]*)"$`, func(filename, text string) error {
		path := filepath.Join(tc.FileDir, filename)
		data, err := os.ReadFile(path) //nolint:gosec // test fixture path
		if err != nil {
			return nil //nolint:nilerr // missing file = no content
		}
		if strings.Contains(string(data), text) {
			return fmt.Errorf("file %s unexpectedly contains %q", filename, text)
		}
		return nil
	})
}

// assertLokiFormatterJSON verifies the loki_out output has a JSON formatter.
func assertLokiFormatterJSON(tc *TestContext) error {
	if tc.LoadResult == nil {
		return fmt.Errorf("no load result available")
	}
	for _, o := range tc.LoadResult.Outputs {
		if o.Name == "loki_out" {
			if o.Formatter == nil {
				return fmt.Errorf("loki output formatter is nil (would inherit default)")
			}
			if _, ok := o.Formatter.(*audit.JSONFormatter); !ok {
				return fmt.Errorf("loki output formatter is %T, want *audit.JSONFormatter", o.Formatter)
			}
			return nil
		}
	}
	return fmt.Errorf("no output named 'loki_out' found")
}

func assertError(tc *TestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}
