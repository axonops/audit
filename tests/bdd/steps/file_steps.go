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
	"fmt"
	"os"
	"path/filepath"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

func registerFileSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output at a temporary path$`, func() error {
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{})
	})
	ctx.Step(`^a logger with no outputs$`, func() error { return createNoOutputLogger(tc) })
	ctx.Step(`^I audit (\d+) events rapidly$`, func(n int) error { return auditNEvents(tc, n) })
	ctx.Step(`^the file should contain exactly (\d+) events$`, func(n int) error { return assertFileEventCount(tc, "default", n) })
	ctx.Step(`^the file should contain an event with event_type "([^"]*)"$`, func(et string) error { return assertFileHasEventType(tc, et) })
	ctx.Step(`^every event in the file should be valid JSON$`, func() error { return assertFileAllValidJSON(tc) })
	ctx.Step(`^I close the logger again$`, func() error { return closeLoggerAgain(tc) })
	ctx.Step(`^the second close should return no error$`, func() error { return assertLastErrNil(tc) })
}

func createNoOutputLogger(tc *AuditTestContext) error {
	opts := []audit.Option{audit.WithTaxonomy(tc.Taxonomy)}
	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func auditNEvents(tc *AuditTestContext, count int) error {
	for i := range count {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = fmt.Sprintf("rapid_%d", i)
		if err := tc.Logger.Audit("user_create", fields); err != nil {
			return fmt.Errorf("audit event %d: %w", i, err)
		}
	}
	return nil
}

func assertFileHasEventType(tc *AuditTestContext, eventType string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	for _, e := range events {
		if e["event_type"] == eventType {
			return nil
		}
	}
	return fmt.Errorf("no event with event_type %q in file (%d events)", eventType, len(events))
}

func assertFileAllValidJSON(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("file contains no events")
	}
	return nil // parseJSONLines already validates JSON
}

func closeLoggerAgain(tc *AuditTestContext) error {
	if tc.Logger != nil {
		tc.LastErr = tc.Logger.Close()
	}
	return nil
}

func assertLastErrNil(tc *AuditTestContext) error {
	if tc.LastErr != nil {
		return fmt.Errorf("expected no error, got: %w", tc.LastErr)
	}
	return nil
}

// createFileLogger creates a logger with a file output in a temp directory.
func createFileLogger(tc *AuditTestContext, cfg audit.Config, fileCfg file.Config) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	if fileCfg.Path == "" {
		fileCfg.Path = filepath.Join(dir, "audit.log")
	}
	tc.FilePaths["default"] = fileCfg.Path

	fileOut, err := file.New(fileCfg, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(fileOut),
	}
	if tc.MockMetrics != nil {
		opts = append(opts, audit.WithMetrics(tc.MockMetrics))
	}
	opts = append(opts, tc.Options...)

	logger, err := audit.NewLogger(cfg, opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

// readFileEvents reads and parses JSON events from a named file output.
func readFileEvents(tc *AuditTestContext, name string) ([]map[string]any, error) {
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}
	path, ok := tc.FilePaths[name]
	if !ok {
		return nil, fmt.Errorf("no file output named %q", name)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test helper reads from controlled temp path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	return parseJSONLines(data)
}

// assertFileEventCount reads and counts events in a named file output.
func assertFileEventCount(tc *AuditTestContext, name string, expected int) error {
	events, err := readFileEvents(tc, name)
	if err != nil {
		return err
	}
	if len(events) != expected {
		return fmt.Errorf("expected %d events in file %q, got %d", expected, name, len(events))
	}
	return nil
}
