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

//go:build integration

package integration_test

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFileOutput_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:       path,
		MaxSizeMB:  1, // 1 MB to trigger rotation quickly
		MaxBackups: 3,
		MaxAgeDays: 30,
	})
	require.NoError(t, err)

	// Write >1MB of data to trigger at least one rotation.
	line := strings.Repeat("x", 1024) + "\n" // ~1KB per line
	for range 1100 {                         // ~1.1MB total
		require.NoError(t, out.Write([]byte(line)))
	}

	// Close before inspecting the directory to ensure the rotation
	// goroutine has completed.
	require.NoError(t, out.Close())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var backups int
	for _, e := range entries {
		if e.Name() != "audit.log" && strings.HasPrefix(e.Name(), "audit") {
			backups++
		}
	}
	assert.Greater(t, backups, 0, "expected at least one rotated backup file")
}

func TestFileOutput_Compression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := true
	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 3,
		MaxAgeDays: 30,
		Compress:   &compress,
	})
	require.NoError(t, err)

	// Write >1MB to trigger rotation.
	line := strings.Repeat("x", 1024) + "\n"
	for range 1100 {
		require.NoError(t, out.Write([]byte(line)))
	}

	// Close to allow compression to complete.
	require.NoError(t, out.Close())

	// Look for .gz backup files.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var gzFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			gzFiles = append(gzFiles, e.Name())
		}
	}
	require.NotEmpty(t, gzFiles, "expected at least one .gz backup file")

	// Verify the .gz file is valid gzip.
	f, err := os.Open(filepath.Join(dir, gzFiles[0]))
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	require.NoError(t, err)
	require.NoError(t, gr.Close())
}

func TestFileOutput_CompressionDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := false
	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 3,
		MaxAgeDays: 30,
		Compress:   &compress,
	})
	require.NoError(t, err)

	// Write >1MB to trigger rotation.
	line := strings.Repeat("x", 1024) + "\n"
	for range 1100 {
		require.NoError(t, out.Write([]byte(line)))
	}

	require.NoError(t, out.Close())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".gz"),
			"found unexpected .gz file when compression is disabled: %s", e.Name())
	}
}

func TestFileOutput_MaxBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := false
	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 2, // Keep only 2 backups
		MaxAgeDays: 30,
		Compress:   &compress,
	})
	require.NoError(t, err)

	// Write enough data for several rotations (~5MB).
	line := strings.Repeat("x", 1024) + "\n"
	for range 5500 {
		require.NoError(t, out.Write([]byte(line)))
	}

	require.NoError(t, out.Close())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var fileCount int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "audit") {
			fileCount++
		}
	}
	// Current file + at most MaxBackups (2).
	assert.LessOrEqual(t, fileCount, 3,
		"expected at most 3 files (current + 2 backups), got %d", fileCount)
}

func TestFileOutput_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	const goroutines = 50
	const eventsPerGoroutine = 100

	var writeErrors atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(gID int) {
			defer wg.Done()
			for e := range eventsPerGoroutine {
				data := fmt.Sprintf(`{"goroutine":%d,"event":%d}`+"\n", gID, e)
				if err := out.Write([]byte(data)); err != nil {
					writeErrors.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()

	assert.Zero(t, writeErrors.Load(), "expected no write errors")

	// Read the file and verify every line is valid JSON.
	content, err := os.ReadFile(path)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Len(t, lines, goroutines*eventsPerGoroutine)

	for i, line := range lines {
		assert.True(t, json.Valid([]byte(line)),
			"line %d is not valid JSON: %s", i+1, line)
	}
}
