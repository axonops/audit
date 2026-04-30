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
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// nonReportingBDDOutput is an [audit.Output] that does NOT implement
// [audit.LastDeliveryReporter]. Used to exercise the "telemetry
// unavailable" arm of [audit.Auditor.LastDeliveryAge].
type nonReportingBDDOutput struct {
	name string
}

func (o *nonReportingBDDOutput) Write([]byte) error { return nil }
func (o *nonReportingBDDOutput) Close() error       { return nil }
func (o *nonReportingBDDOutput) Name() string       { return o.name }

// registerLastDeliveryAgeSteps wires the #753 BDD scenarios that
// assert [audit.Auditor.LastDeliveryAge] semantics — the per-output
// staleness signal driving /healthz liveness probes.
//
//nolint:gocognit,gocyclo,cyclop // step-registration block: flat list of ctx.Step closures, not branching logic
func registerLastDeliveryAgeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with a non-reporting mock output named "([^"]*)"$`, func(name string) error {
		out := &nonReportingBDDOutput{name: name}
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
		}
		opts = append(opts, tc.Options...)
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor with non-reporting mock: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^an auditor with a YAML-named stdout output called "([^"]*)"$`, func(name string) error {
		// WithNamedOutput goes through the namedOutput wrapper, the
		// same path YAML-driven outputs follow. This is the path
		// that verifies the wrapper transparently forwards
		// LastDeliveryReporter to the inner output.
		buf := &bytes.Buffer{}
		tc.StdoutBuf = buf
		stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
		if err != nil {
			return fmt.Errorf("create stdout output: %w", err)
		}
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(audit.WrapOutput(stdoutOut, name)),
		}
		opts = append(opts, tc.Options...)
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create named-output auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^I read LastDeliveryAge for "([^"]*)"$`, func(name string) error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor is nil")
		}
		tc.LastDeliveryAge = tc.Auditor.LastDeliveryAge(name)
		tc.LastDeliveryAgeName = name
		return nil
	})

	ctx.Step(`^the auditor drains pending events$`, func() error {
		if tc.Auditor == nil {
			return fmt.Errorf("auditor is nil")
		}
		// Close drains the queue and waits for the drain goroutine to
		// exit; LastDeliveryNanos will have been advanced before
		// Close returns. This is the canonical way to flush in tests.
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close auditor to drain: %w", err)
		}
		return nil
	})

	ctx.Step(`^the reported delivery age should be the zero duration$`, func() error {
		if tc.LastDeliveryAge != 0 {
			return fmt.Errorf("LastDeliveryAge(%q) want 0, got %v",
				tc.LastDeliveryAgeName, tc.LastDeliveryAge)
		}
		return nil
	})

	ctx.Step(`^LastDeliveryAge for "([^"]*)" should be a positive duration under (\d+) seconds$`,
		func(name string, upperSeconds int) error {
			if tc.Auditor == nil {
				return fmt.Errorf("auditor is nil")
			}
			age := tc.Auditor.LastDeliveryAge(name)
			if age <= 0 {
				return fmt.Errorf("LastDeliveryAge(%q): want positive duration, got %v",
					name, age)
			}
			upper := time.Duration(upperSeconds) * time.Second
			if age >= upper {
				return fmt.Errorf("LastDeliveryAge(%q): want < %v, got %v",
					name, upper, age)
			}
			return nil
		})
}
