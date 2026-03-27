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

package rotate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTimestamp_Invalid(t *testing.T) {
	t.Parallel()

	w := &Writer{prefix: "audit-", ext: ".log"}

	tests := []struct {
		name string
		file string
	}{
		{"no timestamp", "audit-.log"},
		{"bad format", "audit-not-a-date.log"},
		{"partial timestamp", "audit-2026-01-02.log"},
		{"gz with bad timestamp", "audit-bad.log.gz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, ok := w.parseTimestamp(tc.file)
			assert.False(t, ok)
		})
	}
}

func TestParseTimestamp_Valid(t *testing.T) {
	t.Parallel()

	w := &Writer{prefix: "audit-", ext: ".log"}

	ts, ok := w.parseTimestamp("audit-2026-03-27T15-30-45.123.log")
	assert.True(t, ok)
	assert.Equal(t, 2026, ts.Year())

	// Also test .gz variant.
	ts, ok = w.parseTimestamp("audit-2026-03-27T15-30-45.123.log.gz")
	assert.True(t, ok)
	assert.Equal(t, 2026, ts.Year())
}

func TestOldLogFiles_EmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w := &Writer{
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
	}

	files, err := w.oldLogFiles()
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestOldLogFiles_SkipsDirectories(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Create a directory with matching name pattern.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "audit-2026-01-01T00-00-00.000.log"), 0o755))

	w := &Writer{
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
	}

	files, err := w.oldLogFiles()
	require.NoError(t, err)
	assert.Empty(t, files, "directories should be skipped")
}

func TestOldLogFiles_BadDir(t *testing.T) {
	t.Parallel()

	w := &Writer{
		dir:    "/nonexistent/directory/path",
		prefix: "audit-",
		ext:    ".log",
	}

	_, err := w.oldLogFiles()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read dir")
}

func TestOldLogFiles_SortOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Create backups with different timestamps.
	names := []string{
		"audit-2026-01-01T00-00-00.000.log",
		"audit-2026-03-01T00-00-00.000.log",
		"audit-2026-02-01T00-00-00.000.log",
	}
	for _, n := range names {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600))
	}

	w := &Writer{
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
	}

	files, err := w.oldLogFiles()
	require.NoError(t, err)
	require.Len(t, files, 3)
	// Should be newest first.
	assert.Equal(t, "audit-2026-03-01T00-00-00.000.log", files[0].Name())
	assert.Equal(t, "audit-2026-02-01T00-00-00.000.log", files[1].Name())
	assert.Equal(t, "audit-2026-01-01T00-00-00.000.log", files[2].Name())
}

func TestOldLogFiles_SkipsNonMatching(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Create files that share prefix but have wrong extension or format.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-notes.txt"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other-2026-01-01T00-00-00.000.log"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-badformat.log"), []byte("x"), 0o600))

	w := &Writer{
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
	}

	files, err := w.oldLogFiles()
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestBackupName_Format(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w := &Writer{
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
	}

	ts := time.Date(2026, 3, 27, 15, 30, 45, 123_000_000, time.Local)
	name := w.backupName(ts)
	expected := filepath.Join(dir, "audit-2026-03-27T15-30-45.123.log")
	assert.Equal(t, expected, name)
}

func TestSafeStat_RegularFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "regular.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	info, err := safeStat(path)
	require.NoError(t, err)
	assert.False(t, info.IsDir())
}

func TestSafeStat_NonExistent(t *testing.T) {
	t.Parallel()

	_, err := safeStat("/nonexistent/file")
	assert.True(t, os.IsNotExist(err))
}

func TestCloseFile_NilFile(t *testing.T) {
	t.Parallel()

	w := &Writer{}
	assert.NoError(t, w.closeFile())
}

func TestCloseFile_ClosedFd_ReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "test.log"))
	require.NoError(t, err)

	// Close fd manually so the subsequent closeFile call fails.
	require.NoError(t, f.Close())

	w := &Writer{file: f, size: 5}
	err = w.closeFile()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "close file")
	// File handle must be cleared even after Close error.
	assert.Nil(t, w.file)
	assert.Equal(t, int64(0), w.size)
}

func TestRotate_CloseFileError_ReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := os.Create(path)
	require.NoError(t, err)

	// Close the fd manually so rotate → closeFile returns an error.
	require.NoError(t, f.Close())

	w := &Writer{
		cfg:      Config{MaxSize: 100, Mode: 0o600},
		filename: path,
		dir:      dir,
		prefix:   "audit-",
		ext:      ".log",
		file:     f,
		size:     10,
		now:      time.Now,
	}

	err = w.rotate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close file")
}

func TestMillRunOnce_NoBackups(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w := &Writer{
		cfg:    Config{MaxBackups: 5, MaxSize: 100, Mode: 0o600},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	// Should not panic on empty directory.
	w.millRunOnce()
}

func TestMillRunOnce_BadDir_Returns(t *testing.T) {
	t.Parallel()

	w := &Writer{
		cfg:    Config{MaxSize: 100, Mode: 0o600},
		dir:    "/nonexistent/path/that/cannot/be/read",
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	// Must not panic; error is silently discarded (best-effort cleanup).
	w.millRunOnce()
}

func TestMillRunOnce_CompressError_Continues(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission restrictions")
	}
	t.Parallel()

	dir := t.TempDir()

	// Create backup files matching the naming pattern.
	ts := time.Now().Add(-time.Minute).Format("2006-01-02T15-04-05.000")
	backup := filepath.Join(dir, "audit-"+ts+".log")
	require.NoError(t, os.WriteFile(backup, []byte("log data"), 0o600))

	// Make the directory read-only so compressFile cannot create .gz files.
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	w := &Writer{
		cfg:    Config{MaxSize: 100, Mode: 0o600, Compress: true},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	// Must not panic; compressFile error is silently ignored.
	w.millRunOnce()
}
