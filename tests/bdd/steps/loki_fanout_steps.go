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
	"os"
	"strings"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/loki"
	"github.com/cucumber/godog"
)

// registerLokiFanoutSteps registers BDD steps for multi-output
// fan-out scenarios involving Loki alongside file, syslog, and webhook.
func registerLokiFanoutSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// --- Given steps ---

	ctx.Step(`^a logger with file and loki outputs$`,
		func() error {
			return createFileAndLokiLogger(tc, nil, nil)
		})

	ctx.Step(`^a logger with file receiving all events and loki receiving only "([^"]*)"$`,
		func(category string) error {
			lokiRoute := &audit.EventRoute{IncludeCategories: []string{category}}
			return createFileAndLokiLogger(tc, nil, lokiRoute)
		})

	ctx.Step(`^a logger with file and loki outputs both HMAC-enabled with salt "([^"]*)" version "([^"]*)"$`,
		func(salt, version string) error {
			hmacCfg := &audit.HMACConfig{
				Enabled:     true,
				SaltVersion: version,
				SaltValue:   []byte(salt),
				Algorithm:   "HMAC-SHA-256",
			}
			return createFileAndLokiLogger(tc, hmacCfg, nil)
		})

	ctx.Step(`^a logger with file output keeping all fields and loki output excluding label "([^"]*)"$`,
		func(label string) error {
			return createFileAndLokiLoggerWithExclusion(tc, label)
		})

	ctx.Step(`^a logger with file output and loki output to unreachable server$`,
		func() error {
			return createFileAndLokiLoggerUnreachable(tc)
		})

	// --- Then steps ---

	ctx.Step(`^the file should contain the marker$`,
		func() error {
			return assertFileContainsMarkerDefault(tc, tc.Markers["default"])
		})

	ctx.Step(`^the file should contain "([^"]*)"$`,
		func(text string) error {
			return assertFileContainsText(tc, "default", text)
		})

	ctx.Step(`^the file should contain both markers$`,
		func() error {
			for _, marker := range tc.Markers {
				if err := assertFileContainsText(tc, "default", marker); err != nil {
					return err
				}
			}
			return nil
		})

	ctx.Step(`^the file should contain all (\d+) markers$`,
		func(n int) error {
			count := 0
			for _, marker := range tc.Markers {
				if err := assertFileContainsText(tc, "default", marker); err == nil {
					count++
				}
			}
			if count < n {
				return fmt.Errorf("file contains %d of %d expected markers", count, n)
			}
			return nil
		})

	ctx.Step(`^the file event should contain "_hmac" field$`,
		func() error {
			return assertFileEventHasField(tc, tc.Markers["default"], "_hmac")
		})

	ctx.Step(`^the file and Loki "_hmac" values should match for the same event$`,
		func() error {
			return assertFileAndLokiHMACMatch(tc)
		})

	ctx.Step(`^the file event should contain:$`,
		func(table *godog.Table) error {
			return assertFileEventPayload(tc, tc.Markers["default"], table)
		})

	ctx.Step(`^querying Loki by label event_type = "([^"]*)" should return the (\w+) marker within (\d+) seconds$`,
		func(eventType, markerName string, timeout int) error {
			marker := tc.Markers[markerName]
			if marker == "" {
				marker = tc.Markers["default"]
			}
			return assertLokiLabelQueryReturnsMarker(tc, "event_type", eventType, marker, timeout)
		})

	ctx.Step(`^querying Loki by label event_type = "([^"]*)" should return no events within (\d+) seconds$`,
		func(eventType string, timeout int) error {
			return assertLokiLabelQueryReturnsNoEvents(tc, "event_type", eventType, timeout)
		})

	ctx.Step(`^the loki server should have at least (\d+) events within (\d+) seconds$`,
		func(minEvents, _ int) error {
			logql := `{app_name="bdd-audit"}`
			result, err := queryLokiBDD(tc, logql, "")
			if err != nil {
				return err
			}
			n := countLokiLines(result)
			if n < minEvents {
				return fmt.Errorf("expected at least %d events, got %d", minEvents, n)
			}
			return nil
		})

	ctx.Step(`^I audit (\d+) uniquely marked "([^"]*)" events with actor "([^"]*)" and outcome "([^"]*)"$`,
		func(count int, eventType, actor, outcome string) error {
			for i := range count {
				m := marker("BDD")
				tc.Markers[fmt.Sprintf("multi_%d", i)] = m
				fields := audit.Fields{
					"actor_id": actor,
					"outcome":  outcome,
					"marker":   m,
				}
				if err := tc.Logger.AuditEvent(audit.NewEvent(eventType, fields)); err != nil {
					return fmt.Errorf("audit event %d: %w", i, err)
				}
			}
			return nil
		})
}

// ---------------------------------------------------------------------------
// Logger construction helpers
// ---------------------------------------------------------------------------

func createFileAndLokiLogger(tc *AuditTestContext, hmacCfg *audit.HMACConfig, lokiRoute *audit.EventRoute) error {
	// Create temp file for file output.
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	}, nil)
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}

	lokiCfg := &loki.Config{
		URL:                tc.LokiURL + "/loki/api/v1/push",
		TenantID:           "bdd-fanout",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      1e9,
		Timeout:            5e9,
		MaxRetries:         1,
		BufferSize:         1000,
		Compress:           true,
	}

	lokiOut, err := loki.New(lokiCfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.LokiOutputName = lokiOut.Name()

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(fileOut, nil, nil),
		audit.WithNamedOutput(lokiOut, lokiRoute, nil),
	}

	if hmacCfg != nil {
		opts = append(opts,
			audit.WithOutputHMAC(fileOut.Name(), hmacCfg),
			audit.WithOutputHMAC(tc.LokiOutputName, hmacCfg),
		)
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		_ = fileOut.Close()
		_ = lokiOut.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func createFileAndLokiLoggerWithExclusion(tc *AuditTestContext, excludeLabel string) error {
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-pii-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	}, nil)
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}

	lokiCfg := &loki.Config{
		URL:                tc.LokiURL + "/loki/api/v1/push",
		TenantID:           "bdd-fanout-pii",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      1e9,
		Timeout:            5e9,
		MaxRetries:         1,
		BufferSize:         1000,
		Compress:           true,
	}

	lokiOut, err := loki.New(lokiCfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}
	tc.LokiOutputName = lokiOut.Name()

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(fileOut, nil, nil),                      // no exclusions
		audit.WithNamedOutput(lokiOut, nil, nil, excludeLabel), // strip PII
	)
	if err != nil {
		_ = fileOut.Close()
		_ = lokiOut.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func createFileAndLokiLoggerUnreachable(tc *AuditTestContext) error {
	tmpFile, err := os.CreateTemp(tc.FileDir, "fanout-unreachable-*.log")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	_ = tmpFile.Close()
	tc.FilePaths["default"] = tmpFile.Name()

	fileOut, err := file.New(file.Config{
		Path:       tmpFile.Name(),
		MaxSizeMB:  10,
		MaxBackups: 1,
	}, nil)
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}

	// Unreachable Loki — connect to a port nothing is listening on.
	lokiCfg := &loki.Config{
		URL:                "http://localhost:39999/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      1e9,
		Timeout:            1e9, // 1 second timeout
		MaxRetries:         1,
		BufferSize:         100,
		Compress:           false,
	}

	lokiOut, err := loki.New(lokiCfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithNamedOutput(fileOut, nil, nil),
		audit.WithNamedOutput(lokiOut, nil, nil),
	)
	if err != nil {
		_ = fileOut.Close()
		_ = lokiOut.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

// ---------------------------------------------------------------------------
// File assertion helpers
// ---------------------------------------------------------------------------

func assertFileContainsMarkerDefault(tc *AuditTestContext, markerVal string) error {
	return assertFileContainsText(tc, "default", markerVal)
}

func assertFileEventHasField(tc *AuditTestContext, marker, field string) error {
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse file event: %w", err)
	}
	if _, ok := m[field]; !ok {
		return fmt.Errorf("file event does not contain field %q", field)
	}
	return nil
}

func assertFileEventPayload(tc *AuditTestContext, marker string, table *godog.Table) error {
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse file event: %w", err)
	}
	for _, row := range table.Rows[1:] { // skip header
		field := row.Cells[0].Value
		want := row.Cells[1].Value
		got := fmt.Sprint(m[field])
		if got != want {
			return fmt.Errorf("file event field %q: want %q, got %q", field, want, got)
		}
	}
	return nil
}

func assertFileAndLokiHMACMatch(tc *AuditTestContext) error {
	marker := tc.Markers["default"]

	// Extract HMAC from file.
	raw, err := findFileEventByMarker(tc, marker)
	if err != nil {
		return fmt.Errorf("file: %w", err)
	}
	var fileMap map[string]any
	if err := json.Unmarshal(raw, &fileMap); err != nil {
		return fmt.Errorf("parse file event: %w", err)
	}
	fileHMAC, ok := fileMap["_hmac"].(string)
	if !ok {
		return fmt.Errorf("file event does not contain _hmac field")
	}

	// Extract HMAC from Loki.
	lokiHMAC, err := extractLokiHMACField(tc, marker)
	if err != nil {
		return fmt.Errorf("loki: %w", err)
	}

	if fileHMAC != lokiHMAC {
		return fmt.Errorf("HMAC mismatch: file=%q, loki=%q", fileHMAC, lokiHMAC)
	}
	return nil
}

func assertLokiLabelQueryReturnsMarker(tc *AuditTestContext, label, value, marker string, _ int) error {
	logql := fmt.Sprintf(`{%s=%q, app_name="bdd-audit"}`, label, value)
	result, err := queryLokiBDD(tc, logql, "")
	if err != nil {
		return err
	}
	for _, stream := range result.Data.Result {
		for _, v := range stream.Values {
			if len(v) >= 2 && strings.Contains(v[1], marker) {
				return nil
			}
		}
	}
	return fmt.Errorf("marker %q not found in Loki query {%s=%q}", marker, label, value)
}

func assertLokiLabelQueryReturnsNoEvents(tc *AuditTestContext, label, value string, _ int) error {
	logql := fmt.Sprintf(`{%s=%q, app_name="bdd-audit"}`, label, value)
	result, err := queryLokiBDD(tc, logql, "")
	if err != nil {
		return err
	}
	n := countLokiLines(result)
	if n > 0 {
		return fmt.Errorf("expected no events for {%s=%q} but found %d", label, value, n)
	}
	return nil
}

// findFileEventByMarker reads the file output and returns the raw JSON
// line containing the marker.
func findFileEventByMarker(tc *AuditTestContext, marker string) ([]byte, error) {
	path := tc.FilePaths["default"]
	if path == "" {
		return nil, fmt.Errorf("no file output configured")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, marker) {
			return []byte(line), nil
		}
	}
	return nil, fmt.Errorf("marker %q not found in file", marker)
}
