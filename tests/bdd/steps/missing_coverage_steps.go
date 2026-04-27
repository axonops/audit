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
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

// destKeyOutput is a mock output that returns a configured destination
// key. Used by F-27 DestinationKey duplicate-detection scenarios.
type destKeyOutput struct {
	name   string
	dest   string
	closed bool
}

func (d *destKeyOutput) Write(_ []byte) error   { return nil }
func (d *destKeyOutput) Close() error           { d.closed = true; return nil }
func (d *destKeyOutput) Name() string           { return d.name }
func (d *destKeyOutput) DestinationKey() string { return d.dest }

// emptyNameOutput is a mock output whose Name() returns "". Used by
// F-28 to verify the construction-time validation rejects it.
type emptyNameOutput struct{}

func (e *emptyNameOutput) Write(_ []byte) error { return nil }
func (e *emptyNameOutput) Close() error         { return nil }
func (e *emptyNameOutput) Name() string         { return "" }

// registerMissingCoverageSteps registers BDD step definitions for #561
// (the bundle of previously-missing BDD coverage: F-21 EventHandle,
// F-22 audittest options, F-23 webhook/loki buffer_size, F-24
// drain_timeout deprecation, F-25 ValidationMode warn, F-26 CEF
// OmitEmpty, F-27 DestinationKey, F-28 empty Name policy).
//
//nolint:gocognit,gocyclo,cyclop,maintidx // BDD step registration: many closures inline; splitting hurts readability
func registerMissingCoverageSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// F-27/F-28 construction state — local closure.
	var (
		dkOut1, dkOut2  *destKeyOutput
		emptyOut        *emptyNameOutput
		constructResult error
	)

	// =========================================================
	// F-21 EventHandle.AuditEvent
	// =========================================================

	ctx.Step(`^I call EventHandle\.AuditEvent with a NewEvent for "([^"]*)"$`, func(eventType string) error {
		if tc.EventHandle == nil {
			return errors.New("no EventHandle — precede with 'I get a handle for event type ...'")
		}
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.EventHandle.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	// F-22 audittest WithSync / WithVerbose / RequireEvents step
	// definitions live in sync_delivery_steps.go where they share the
	// audittestAuditor / audittestRecorder closure with the other
	// audittest scenarios.

	// =========================================================
	// F-23, F-24: extra outputconfig assertion step
	// =========================================================

	ctx.Step(`^the config load error should also contain "([^"]*)"$`, func(needle string) error {
		if tc.LastErr == nil {
			return errors.New("no error — load did not fail")
		}
		if !strings.Contains(tc.LastErr.Error(), needle) {
			return fmt.Errorf("error %q does not also contain %q", tc.LastErr.Error(), needle)
		}
		return nil
	})

	// =========================================================
	// F-25 ValidationMode warn / strict auditor builders
	// =========================================================

	// F-25 ValidationMode scenarios live in isolation_steps.go (they
	// reuse the recOut1 closure shared with the existing
	// `received exactly N events` assertion step).

	ctx.Step(`^I try to audit event "([^"]*)" with required fields and an unknown field "([^"]*)"$`, func(eventType, extraField string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields[extraField] = "extra_value"
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	// =========================================================
	// F-26 CEF formatter OmitEmpty
	// =========================================================

	ctx.Step(`^an auditor with file output and a CEF formatter with OmitEmpty (true|false)$`, func(omit string) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "cef.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(&file.Config{Path: path})
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		tc.AddCleanup(func() { _ = fileOut.Close() })

		cefFmt := &audit.CEFFormatter{
			Vendor:    "axonops",
			Product:   "audit",
			Version:   "test",
			OmitEmpty: omit == "true",
		}

		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithFormatter(cefFmt),
			audit.WithNamedOutput(fileOut),
			audit.WithSynchronousDelivery(),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.AddCleanup(func() { _ = tc.Auditor.Close() })
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with an empty optional field "([^"]*)"$`, func(eventType, fieldName string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields[fieldName] = ""
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^the file should not contain CEF extension key "([^"]*)"$`, func(key string) error {
		path := tc.FilePaths["default"]
		data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		// CEF extension keys appear as ` <key>=` (space-prefixed).
		needle := " " + key + "="
		if bytes.Contains(data, []byte(needle)) {
			return fmt.Errorf("file unexpectedly contains CEF extension key %q in %q", key, string(data))
		}
		return nil
	})

	ctx.Step(`^the file should contain CEF extension key "([^"]*)"$`, func(key string) error {
		path := tc.FilePaths["default"]
		data, err := os.ReadFile(path) //nolint:gosec // test-controlled path
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		needle := " " + key + "="
		if !bytes.Contains(data, []byte(needle)) {
			return fmt.Errorf("file does not contain CEF extension key %q; got %q", key, string(data))
		}
		return nil
	})

	// =========================================================
	// F-27 DestinationKey duplicate detection
	// =========================================================

	ctx.Step(`^two outputs with destination keys "([^"]*)" and "([^"]*)"$`, func(k1, k2 string) error {
		dkOut1 = &destKeyOutput{name: "dk-1", dest: k1}
		dkOut2 = &destKeyOutput{name: "dk-2", dest: k2}
		return nil
	})

	ctx.Step(`^I construct an auditor with those two outputs via WithNamedOutput$`, func() error {
		// Sync delivery so a successful construction doesn't leak a
		// drain goroutine when the test discards the auditor.
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(dkOut1),
			audit.WithNamedOutput(dkOut2),
			audit.WithSynchronousDelivery(),
		)
		if auditor != nil {
			tc.AddCleanup(func() { _ = auditor.Close() })
		}
		constructResult = err
		return nil
	})

	ctx.Step(`^I construct an auditor with those two outputs via WithOutputs$`, func() error {
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(dkOut1, dkOut2),
			audit.WithSynchronousDelivery(),
		)
		if auditor != nil {
			tc.AddCleanup(func() { _ = auditor.Close() })
		}
		constructResult = err
		return nil
	})

	ctx.Step(`^the construction should succeed$`, func() error {
		if constructResult != nil {
			return fmt.Errorf("expected construction to succeed, got: %w", constructResult)
		}
		return nil
	})

	ctx.Step(`^the construction should fail with an error wrapping "([^"]*)"$`, func(sentinel string) error {
		if constructResult == nil {
			return errors.New("expected construction to fail, but it succeeded")
		}
		var target error
		switch sentinel {
		case "ErrDuplicateDestination":
			target = audit.ErrDuplicateDestination
		default:
			return fmt.Errorf("unknown sentinel %q in step", sentinel)
		}
		if !errors.Is(constructResult, target) {
			return fmt.Errorf("expected error wrapping %s, got: %w", sentinel, constructResult)
		}
		return nil
	})

	ctx.Step(`^the construction should fail with a message containing "([^"]*)"$`, func(needle string) error {
		if constructResult == nil {
			return errors.New("expected construction to fail, but it succeeded")
		}
		if !strings.Contains(constructResult.Error(), needle) {
			return fmt.Errorf("expected error message to contain %q, got: %w", needle, constructResult)
		}
		return nil
	})

	// =========================================================
	// F-28 Output.Name() empty-string policy
	// =========================================================

	ctx.Step(`^an output whose Name returns the empty string$`, func() error {
		emptyOut = &emptyNameOutput{}
		return nil
	})

	ctx.Step(`^I construct an auditor with that output via WithNamedOutput$`, func() error {
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(emptyOut),
			audit.WithSynchronousDelivery(),
		)
		if auditor != nil {
			tc.AddCleanup(func() { _ = auditor.Close() })
		}
		constructResult = err
		return nil
	})

	ctx.Step(`^I construct an auditor with that output via WithOutputs$`, func() error {
		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(emptyOut),
			audit.WithSynchronousDelivery(),
		)
		if auditor != nil {
			tc.AddCleanup(func() { _ = auditor.Close() })
		}
		constructResult = err
		return nil
	})
}
