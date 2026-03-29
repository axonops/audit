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
	"sync"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

func registerFileSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Given steps
	ctx.Step(`^a logger with file output at a temporary path$`, func() error {
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{})
	})
	ctx.Step(`^a logger with file output with permissions "([^"]*)"$`, func(perms string) error {
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{Permissions: perms})
	})
	ctx.Step(`^a logger with file output configured for (\d+) MB max size$`, func(mb int) error {
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{MaxSizeMB: mb})
	})
	ctx.Step(`^a logger with file output configured for (\d+) MB max size with compression$`, func(mb int) error {
		compress := true
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{MaxSizeMB: mb, Compress: &compress})
	})
	ctx.Step(`^a logger with file output configured for (\d+) MB max size without compression$`, func(mb int) error {
		compress := false
		return createFileLogger(tc, audit.Config{Version: 1, Enabled: true}, file.Config{MaxSizeMB: mb, Compress: &compress})
	})
	ctx.Step(`^a logger with file output configured for (\d+) MB max size with file metrics$`, func(mb int) error {
		tc.FileMetrics = &MockFileMetrics{}
		return createFileLoggerWithMetrics(tc, audit.Config{Version: 1, Enabled: true}, file.Config{MaxSizeMB: mb}, tc.FileMetrics)
	})
	ctx.Step(`^mock file metrics are configured$`, func() error {
		tc.FileMetrics = &MockFileMetrics{}
		return nil
	})
	ctx.Step(`^a logger with no outputs$`, func() error { return createNoOutputLogger(tc) })

	// When steps
	ctx.Step(`^I audit (\d+) events rapidly$`, func(n int) error { return auditNEvents(tc, n) })
	ctx.Step(`^I audit (\d+) events from (\d+) concurrent goroutines$`, func(total, goroutines int) error {
		return auditConcurrent(tc, total, goroutines)
	})
	ctx.Step(`^I write enough events to exceed (\d+) MB$`, func(mb int) error { return writeEventsExceeding(tc, mb) })
	ctx.Step(`^I try to create a file output with a symlink path$`, func() error { return trySymlinkFileOutput(tc) })
	ctx.Step(`^I try to create a file output with empty path$`, func() error { return tryFileOutputWithPath(tc, "") })
	ctx.Step(`^I try to create a file output with MaxSizeMB (\d+)$`, func(mb int) error {
		_, err := file.New(file.Config{Path: "/tmp/test.log", MaxSizeMB: mb}, nil)
		tc.LastErr = err
		return nil
	})
	ctx.Step(`^I try to create a file output at "([^"]*)"$`, func(path string) error { return tryFileOutputWithPath(tc, path) })
	ctx.Step(`^I try to create a file output with MaxBackups (\d+)$`, func(mb int) error {
		_, err := file.New(file.Config{Path: "/tmp/test.log", MaxBackups: mb}, nil)
		tc.LastErr = err
		return nil
	})
	ctx.Step(`^I try to create a file output with permissions "([^"]*)"$`, func(perms string) error {
		dir, dirErr := tc.EnsureFileDir()
		if dirErr != nil {
			return dirErr
		}
		_, err := file.New(file.Config{Path: filepath.Join(dir, "test.log"), Permissions: perms}, nil)
		tc.LastErr = err
		return nil
	})

	// Then steps
	ctx.Step(`^the file should contain exactly (\d+) events$`, func(n int) error { return assertFileEventCount(tc, "default", n) })
	ctx.Step(`^the file should contain an event with event_type "([^"]*)"$`, func(et string) error { return assertFileHasEventType(tc, et) })
	ctx.Step(`^every event in the file should be valid JSON$`, func() error { return assertFileAllValidJSON(tc) })
	ctx.Step(`^the file should contain events$`, func() error { return assertFileHasAnyEvents(tc) })
	ctx.Step(`^I close the logger again$`, func() error { return closeLoggerAgain(tc) })
	ctx.Step(`^the second close should return no error$`, func() error { return assertLastErrNil(tc) })
	ctx.Step(`^the file should have permissions "([^"]*)"$`, func(perms string) error { return assertFilePermissions(tc, perms) })
	ctx.Step(`^the file output construction should fail with error:$`, func(doc *godog.DocString) error {
		expected := strings.TrimSpace(doc.Content)
		if tc.LastErr == nil {
			return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
		}
		if tc.LastErr.Error() != expected {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
		}
		return nil
	})
	ctx.Step(`^the file output construction should fail with an error$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected file output construction error, got nil")
		}
		return nil
	})
	ctx.Step(`^more than one file should exist in the output directory$`, func() error { return assertMultipleFilesInDir(tc) })
	ctx.Step(`^a \.gz backup file should exist in the output directory$`, func() error { return assertGzFileExists(tc) })
	ctx.Step(`^no \.gz files should exist in the output directory$`, func() error { return assertNoGzFiles(tc) })
	ctx.Step(`^the file event should have field "([^"]*)" present$`, func(field string) error { return assertFileEventFieldPresent(tc, field) })
	ctx.Step(`^the file metrics should have recorded at least (\d+) rotation$`, func(n int) error { return assertFileRotationCount(tc, n) })
}

// --- Extracted step implementations ---

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

func auditConcurrent(tc *AuditTestContext, total, goroutines int) error {
	perGoroutine := total / goroutines
	var wg sync.WaitGroup
	errCh := make(chan error, total)
	for g := range goroutines {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for i := range perGoroutine {
				fields := defaultRequiredFields(tc.Taxonomy, "user_create")
				fields["marker"] = fmt.Sprintf("g%d_e%d", gID, i)
				if err := tc.Logger.Audit("user_create", fields); err != nil {
					errCh <- fmt.Errorf("goroutine %d event %d: %w", gID, i, err)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func writeEventsExceeding(tc *AuditTestContext, mb int) error {
	// Each event is roughly 200 bytes. Write enough to exceed target.
	targetBytes := mb * 1024 * 1024
	eventSize := 200
	count := (targetBytes / eventSize) + 100
	for i := range count {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = fmt.Sprintf("rot_%d_padding_data_for_size", i)
		if err := tc.Logger.Audit("user_create", fields); err != nil {
			return fmt.Errorf("write event %d: %w", i, err)
		}
	}
	return nil
}

func trySymlinkFileOutput(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	realPath := filepath.Join(dir, "real.log")
	linkPath := filepath.Join(dir, "link.log")
	if writeErr := os.WriteFile(realPath, nil, 0o600); writeErr != nil {
		return fmt.Errorf("create real file: %w", writeErr)
	}
	if linkErr := os.Symlink(realPath, linkPath); linkErr != nil {
		return fmt.Errorf("create symlink: %w", linkErr)
	}
	// file.New may succeed (lazy open), but the symlink is rejected
	// at write time by the rotate package's safeOpen. Create the
	// output and attempt a write to trigger the rejection.
	out, err := file.New(file.Config{Path: linkPath}, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // construction rejected it
	}
	// Try writing — the symlink should be rejected by safeOpen.
	writeErr := out.Write([]byte(`{"test":"symlink"}\n`))
	_ = out.Close()
	if writeErr != nil {
		tc.LastErr = writeErr
		return nil //nolint:nilerr // write rejected the symlink
	}
	// If neither construction nor write rejected it, that's unexpected
	// but we store nil error so the Then step can report failure.
	tc.LastErr = nil
	return nil
}

func tryFileOutputWithPath(tc *AuditTestContext, path string) error {
	_, err := file.New(file.Config{Path: path}, nil)
	tc.LastErr = err
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
	return nil
}

func assertFileHasAnyEvents(tc *AuditTestContext) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("file contains no events")
	}
	return nil
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

func assertFilePermissions(tc *AuditTestContext, expected string) error {
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}
	path := tc.FilePaths["default"]
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	got := fmt.Sprintf("%04o", info.Mode().Perm())
	if got != expected {
		return fmt.Errorf("expected permissions %s, got %s", expected, got)
	}
	return nil
}

func assertMultipleFilesInDir(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	if count <= 1 {
		return fmt.Errorf("expected more than 1 file in dir, got %d", count)
	}
	return nil
}

func assertGzFileExists(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			return nil
		}
	}
	return fmt.Errorf("no .gz file found in %s", dir)
}

func assertNoGzFiles(tc *AuditTestContext) error {
	dir := tc.FileDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			return fmt.Errorf("unexpected .gz file found: %s", e.Name())
		}
	}
	return nil
}

func assertFileEventFieldPresent(tc *AuditTestContext, field string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	if _, ok := events[0][field]; !ok {
		return fmt.Errorf("field %q not present in file event", field)
	}
	return nil
}

func assertFileRotationCount(tc *AuditTestContext, minCount int) error {
	if tc.FileMetrics == nil {
		return fmt.Errorf("no file metrics configured")
	}
	tc.FileMetrics.mu.Lock()
	defer tc.FileMetrics.mu.Unlock()
	if tc.FileMetrics.rotations < minCount {
		return fmt.Errorf("expected at least %d rotations, got %d", minCount, tc.FileMetrics.rotations)
	}
	return nil
}

// --- Logger construction helpers ---

func createFileLogger(tc *AuditTestContext, cfg audit.Config, fileCfg file.Config) error {
	return createFileLoggerWithMetrics(tc, cfg, fileCfg, nil)
}

func createFileLoggerWithMetrics(tc *AuditTestContext, cfg audit.Config, fileCfg file.Config, fileMetrics file.Metrics) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	if fileCfg.Path == "" {
		fileCfg.Path = filepath.Join(dir, "audit.log")
	}
	tc.FilePaths["default"] = fileCfg.Path

	fileOut, err := file.New(fileCfg, fileMetrics)
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

// --- Mock file metrics ---

// MockFileMetrics captures file.Metrics calls.
type MockFileMetrics struct {
	mu        sync.Mutex
	rotations int
}

// RecordFileRotation satisfies file.Metrics.
func (m *MockFileMetrics) RecordFileRotation(_ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotations++
}
