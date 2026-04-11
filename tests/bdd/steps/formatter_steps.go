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
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

func registerFormatterSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFormatterGivenSteps(ctx, tc)
	registerFormatterGivenExtraSteps(ctx, tc)
	registerFormatterGivenCustomSeveritySteps(ctx, tc)
	registerFormatterGivenInvalidKeySteps(ctx, tc)
	registerFormatterGivenSeveritySteps(ctx, tc)
	registerFormatterWhenSteps(ctx, tc)
	registerFormatterThenSteps(ctx, tc)
}

func registerFormatterGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFormatterGivenJSONSteps(ctx, tc)
	registerFormatterGivenCEFSteps(ctx, tc)
	registerFormatterGivenMultiSteps(ctx, tc)
}

func registerFormatterGivenJSONSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using JSON formatter$`, func() error {
		return createFileLogger(tc, file.Config{})
	})

	ctx.Step(`^a logger with file output using JSON formatter with unix millis timestamps$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithFormatter(&audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis}),
			audit.WithOutputs(fileOut),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

	ctx.Step(`^a logger with file output using JSON formatter and OmitEmpty (true|false)$`, func(val string) error {
		if val == "true" {
			tc.Options = append(tc.Options, audit.WithOmitEmpty())
		}
		return createFileLogger(tc, file.Config{})
	})

}

func registerFormatterGivenCEFSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using CEF formatter with vendor "([^"]*)" product "([^"]*)" version "([^"]*)"$`, func(vendor, product, version string) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file output: %w", err)
		}

		cefFmt := &audit.CEFFormatter{
			Vendor:  vendor,
			Product: product,
			Version: version,
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(fileOut, nil, cefFmt),
		}
		opts = append(opts, tc.Options...)

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

}

func registerFormatterGivenMultiSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with two file outputs using JSON and CEF formatters$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		jsonPath := filepath.Join(dir, "json.log")
		cefPath := filepath.Join(dir, "cef.log")
		tc.FilePaths["json"] = jsonPath
		tc.FilePaths["cef"] = cefPath

		jsonOut, err := file.New(file.Config{Path: jsonPath}, nil)
		if err != nil {
			return fmt.Errorf("create json file: %w", err)
		}

		cefOut, err := file.New(file.Config{Path: cefPath}, nil)
		if err != nil {
			return fmt.Errorf("create cef file: %w", err)
		}

		cefFmt := &audit.CEFFormatter{Vendor: "Test", Product: "BDD", Version: "1.0"}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(jsonOut, nil, nil),   // default JSON
			audit.WithNamedOutput(cefOut, nil, cefFmt), // CEF
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerFormatterGivenCustomSeveritySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using CEF formatter with custom severity function$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		cefFmt := &audit.CEFFormatter{
			Vendor: "Test", Product: "Test", Version: "1.0",
			SeverityFunc: func(eventType string) int {
				if eventType == "auth_failure" {
					return 8
				}
				return 5
			},
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(fileOut, nil, cefFmt),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerFormatterGivenInvalidKeySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using CEF formatter with invalid field mapping$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		cefFmt := &audit.CEFFormatter{
			Vendor: "Test", Product: "Test", Version: "1.0",
			FieldMapping: map[string]string{
				"actor_id": "invalid key with spaces", // invalid CEF ext key
			},
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(fileOut, nil, cefFmt),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerFormatterGivenSeveritySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using CEF formatter with severity below (\d+)$`, func(_ int) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		cefFmt := &audit.CEFFormatter{
			Vendor: "Test", Product: "Test", Version: "1.0",
			SeverityFunc: func(_ string) int { return -5 },
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(fileOut, nil, cefFmt),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerFormatterGivenExtraSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file output using CEF formatter with severity above (\d+)$`, func(above int) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file output: %w", err)
		}

		cefFmt := &audit.CEFFormatter{
			Vendor:  "Test",
			Product: "Test",
			Version: "1.0",
			SeverityFunc: func(_ string) int {
				return above + 5 // Always returns above 10
			},
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(fileOut, nil, cefFmt),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerFormatterWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit event "([^"]*)" with a duration field$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["duration_ms"] = 150 * time.Millisecond
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing a tab character$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\ttab\tafter"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a (\d+)-character field value$`, func(eventType string, length int) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = strings.Repeat("a", length)
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing control characters$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\x01\x02\x03after"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing invalid UTF-8$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "bad\xfe\xffbyte"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing null bytes$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\x00after"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing U\+2028$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\u2028after"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing U\+2029$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\u2029after"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with a field containing a newline$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = "before\n{\"injected\":true}"
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})
}

func registerFormatterThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFormatterFileAssertionSteps(ctx, tc)
	registerFormatterJSONSteps(ctx, tc)
	registerFormatterEdgeCaseSteps(ctx, tc)
	registerFormatterCEFSteps(ctx, tc)
}

func registerFormatterFileAssertionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should contain an event matching:$`, func(t *godog.Table) error { return assertFileEventMatching(tc, t) })
	ctx.Step(`^the first JSON event should have "([^"]*)" before "([^"]*)"$`, func(a, b string) error { return assertJSONFieldOrder(tc, a, b) })
}

func registerFormatterJSONSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the first JSON event timestamp should match RFC3339Nano format$`, func() error { return assertTimestampRFC3339Nano(tc) })
	ctx.Step(`^the first JSON event timestamp should be a numeric value$`, func() error { return assertTimestampNumeric(tc) })
	ctx.Step(`^the first JSON event should not contain key "([^"]*)"$`, func(k string) error { return assertFirstEventKeyAbsent(tc, k) })
	ctx.Step(`^the first JSON event should contain key "([^"]*)"$`, func(k string) error { return assertFirstEventKeyPresent(tc, k) })
	ctx.Step(`^the first JSON event "([^"]*)" field should be an integer$`, func(f string) error { return assertFirstEventFieldIsInt(tc, f) })
	ctx.Step(`^the file should contain exactly (\d+) event$`, func(n int) error { return assertFileEventCount(tc, "default", n) })
	ctx.Step(`^the file should contain a line starting with "([^"]*)"$`, func(p string) error { return assertFileLineStartsWith(tc, "default", p) })
	ctx.Step(`^every event in the file should have exactly (\d+) line$`, func(n int) error { return assertFileExactlyNLines(tc, "default", n) })
	ctx.Step(`^the file should be empty$`, func() error { return assertFileEventCount(tc, "default", 0) })
}

func registerFormatterEdgeCaseSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should not contain raw "([^"]*)"$`, func(text string) error {
		raw, err := readRawFile(tc, "default")
		if err != nil {
			return err
		}
		if strings.Contains(raw, text) {
			return fmt.Errorf("file contains raw %q which should have been escaped", text)
		}
		return nil
	})
}

func registerFormatterCEFSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the CEF line should contain "([^"]*)"$`, func(s string) error { return assertCEFContains(tc, s) })
	ctx.Step(`^the CEF line should not contain "([^"]*)"$`, func(s string) error { return assertCEFNotContains(tc, s) })
	ctx.Step(`^the CEF line should have severity (\d+)$`, func(s int) error { return assertCEFSeverity(tc, s) })
	ctx.Step(`^the JSON file should contain valid JSON$`, func() error { return assertNamedFileHasJSON(tc, "json") })
	ctx.Step(`^the CEF file should contain a line starting with "([^"]*)"$`, func(p string) error { return assertFileLineStartsWith(tc, "cef", p) })
}

// --- Formatter assertion helpers ---

func assertFileEventMatching(tc *AuditTestContext, table *godog.Table) error {
	expected := tableToStringMap(table)
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	autoFields := []string{"timestamp", "severity", "event_category", "pid", "timezone"}
	for _, e := range events {
		match, mismatch := eventMatchesExactly(e, expected, autoFields)
		if match {
			return nil
		}
		if len(events) == 1 {
			return fmt.Errorf("file event does not match: %s", mismatch)
		}
	}
	return fmt.Errorf("no event matching expected fields in file (%d events)", len(events))
}

func assertJSONFieldOrder(tc *AuditTestContext, first, second string) error {
	raw, err := readFirstLine(tc, "default")
	if err != nil {
		return err
	}
	firstIdx := strings.Index(raw, `"`+first+`"`)
	secondIdx := strings.Index(raw, `"`+second+`"`)
	if firstIdx < 0 {
		return fmt.Errorf("field %q not found in JSON", first)
	}
	if secondIdx < 0 {
		return fmt.Errorf("field %q not found in JSON", second)
	}
	if firstIdx >= secondIdx {
		return fmt.Errorf("field %q (pos %d) should appear before %q (pos %d)", first, firstIdx, second, secondIdx)
	}
	return nil
}

func assertTimestampNumeric(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	ts := events[0]["timestamp"]
	// Unix millis timestamps are JSON numbers (float64 after decode).
	if _, ok := ts.(float64); !ok {
		return fmt.Errorf("timestamp should be numeric (unix millis), got %T: %v", ts, ts)
	}
	return nil
}

func assertTimestampRFC3339Nano(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	ts, ok := events[0]["timestamp"].(string)
	if !ok {
		return fmt.Errorf("timestamp field is not a string: %v", events[0]["timestamp"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		return fmt.Errorf("timestamp %q does not match RFC3339Nano: %w", ts, err)
	}
	return nil
}

func assertFirstEventKeyAbsent(tc *AuditTestContext, key string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	if _, exists := events[0][key]; exists {
		return fmt.Errorf("expected key %q to be absent, but it exists with value %v", key, events[0][key])
	}
	return nil
}

func assertFirstEventKeyPresent(tc *AuditTestContext, key string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	if _, exists := events[0][key]; !exists {
		return fmt.Errorf("expected key %q to be present, but it is absent", key)
	}
	return nil
}

func assertFirstEventFieldIsInt(tc *AuditTestContext, field string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	val, ok := events[0][field]
	if !ok {
		return fmt.Errorf("field %q not found", field)
	}
	f, ok := val.(float64)
	if !ok {
		return fmt.Errorf("field %q is %T, not a number", field, val)
	}
	if f != float64(int64(f)) {
		return fmt.Errorf("field %q is %v, not an integer", field, f)
	}
	return nil
}

func assertFileExactlyNLines(tc *AuditTestContext, name string, n int) error {
	raw, err := readRawFile(tc, name)
	if err != nil {
		return err
	}
	lines := 0
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	if lines != n {
		return fmt.Errorf("expected %d non-empty lines in file %q, got %d", n, name, lines)
	}
	return nil
}

func assertFileLineStartsWith(tc *AuditTestContext, name, prefix string) error {
	raw, err := readRawFile(tc, name)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return nil
		}
	}
	return fmt.Errorf("no line starting with %q in file %q", prefix, name)
}

func assertCEFContains(tc *AuditTestContext, substr string) error {
	raw, err := readRawFile(tc, "default")
	if err != nil {
		return err
	}
	if !strings.Contains(raw, substr) {
		return fmt.Errorf("CEF output does not contain %q", substr)
	}
	return nil
}

func assertCEFNotContains(tc *AuditTestContext, substr string) error {
	raw, err := readRawFile(tc, "default")
	if err != nil {
		return err
	}
	if strings.Contains(raw, substr) {
		return fmt.Errorf("CEF output should not contain %q but does", substr)
	}
	return nil
}

func assertCEFSeverity(tc *AuditTestContext, severity int) error {
	raw, err := readRawFile(tc, "default")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "CEF:0|") {
			continue
		}
		parts := strings.SplitN(line, "|", 8)
		if len(parts) < 8 {
			return fmt.Errorf("CEF line has fewer than 8 pipe-delimited parts")
		}
		if parts[6] == fmt.Sprintf("%d", severity) {
			return nil
		}
		return fmt.Errorf("CEF severity is %q, expected %d", parts[6], severity)
	}
	return fmt.Errorf("no CEF line found in output")
}

func assertNamedFileHasJSON(tc *AuditTestContext, name string) error {
	events, err := readFileEvents(tc, name)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("%s file contains no events", name)
	}
	return nil
}

// --- File reading helpers ---

// readFirstLine reads the first line of a named file output.
func readFirstLine(tc *AuditTestContext, name string) (string, error) {
	raw, err := readRawFile(tc, name)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("file is empty")
}

// readRawFile reads the raw content of a named file output.
func readRawFile(tc *AuditTestContext, name string) (string, error) {
	// Close logger to flush pending events.
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}

	path, ok := tc.FilePaths[name]
	if !ok {
		return "", fmt.Errorf("no file output named %q", name)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: test helper reads from controlled temp path
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read file %q: %w", path, err)
	}
	return string(data), nil
}
