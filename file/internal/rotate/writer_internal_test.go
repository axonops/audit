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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit/iouring"
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
	name, err := w.backupName(ts)
	require.NoError(t, err)
	expected := filepath.Join(dir, "audit-2026-03-27T15-30-45.123.log")
	assert.Equal(t, expected, name)
}

func TestBackupName_Collision(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w := &Writer{dir: dir, prefix: "audit-", ext: ".log"}

	ts := time.Date(2026, 3, 27, 15, 30, 45, 123_000_000, time.Local)

	// Create the base backup name so it collides.
	base := filepath.Join(dir, "audit-2026-03-27T15-30-45.123.log")
	require.NoError(t, os.WriteFile(base, []byte("x"), 0o600))

	name, err := w.backupName(ts)
	require.NoError(t, err)
	expected := filepath.Join(dir, "audit-2026-03-27T15-30-45.123-1.log")
	assert.Equal(t, expected, name)
}

func TestBackupName_MultipleCollisions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w := &Writer{dir: dir, prefix: "audit-", ext: ".log"}

	ts := time.Date(2026, 3, 27, 15, 30, 45, 123_000_000, time.Local)

	// Create base and -1 so the next free slot is -2.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-2026-03-27T15-30-45.123.log"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-2026-03-27T15-30-45.123-1.log"), []byte("x"), 0o600))

	name, err := w.backupName(ts)
	require.NoError(t, err)
	expected := filepath.Join(dir, "audit-2026-03-27T15-30-45.123-2.log")
	assert.Equal(t, expected, name)
}

func TestParseTimestamp_WithCounter(t *testing.T) {
	t.Parallel()

	w := &Writer{prefix: "audit-", ext: ".log"}

	ts, ok := w.parseTimestamp("audit-2026-03-27T15-30-45.123-1.log")
	assert.True(t, ok)
	assert.Equal(t, 2026, ts.Year())
	assert.Equal(t, time.Month(3), ts.Month())
}

func TestParseTimestamp_WithCounterGz(t *testing.T) {
	t.Parallel()

	w := &Writer{prefix: "audit-", ext: ".log"}

	ts, ok := w.parseTimestamp("audit-2026-03-27T15-30-45.123-2.log.gz")
	assert.True(t, ok)
	assert.Equal(t, 2026, ts.Year())
}

func TestOldLogFiles_IncludesCounterSuffix(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create backups with and without counter suffixes.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-2026-03-27T15-30-45.123.log"), []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-2026-03-27T15-30-45.123-1.log"), []byte("b"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audit-2026-03-27T15-30-45.123-2.log"), []byte("c"), 0o600))

	w := &Writer{dir: dir, prefix: "audit-", ext: ".log"}

	files, err := w.oldLogFiles()
	require.NoError(t, err)
	assert.Len(t, files, 3, "should find all backups including counter variants")
}

func TestWriter_SameMillisecondCollision(t *testing.T) {
	// Freeze time so all rotations produce the same millisecond timestamp.
	// Verify no data is lost — total bytes across all files = total written.
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	frozen := time.Date(2026, 3, 27, 12, 0, 0, 0, time.Local)

	w := &Writer{
		cfg:      Config{MaxSize: 50, Mode: 0o600},
		filename: path,
		dir:      dir,
		prefix:   "audit-",
		ext:      ".log",
		now:      func() time.Time { return frozen },
	}

	// Write 5 payloads that each trigger rotation (each > MaxSize).
	payload := strings.Repeat("x", 55) + "\n" // 56 bytes > 50
	totalWritten := 0
	for range 5 {
		n, err := w.Write([]byte(payload))
		require.NoError(t, err)
		totalWritten += n
	}
	require.NoError(t, w.Close())

	// Count total bytes across active file + all backups.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	totalOnDisk := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		totalOnDisk += len(data)
	}

	assert.Equal(t, totalWritten, totalOnDisk, "no audit data should be lost due to timestamp collision")
	// Should have multiple backup files (collision counters).
	assert.Greater(t, len(entries), 1, "should have created backups with counter suffixes")
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

	w.millRunOnce()
}

func TestMillRunOnce_CompressError_Continues(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission restrictions")
	}
	t.Parallel()

	dir := t.TempDir()

	ts := time.Now().Add(-time.Minute).Format("2006-01-02T15-04-05.000")
	backup := filepath.Join(dir, "audit-"+ts+".log")
	require.NoError(t, os.WriteFile(backup, []byte("log data"), 0o600))

	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	w := &Writer{
		cfg:    Config{MaxSize: 100, Mode: 0o600, Compress: true},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	w.millRunOnce()
}

// ---------------------------------------------------------------------------
// OnError callback tests
// ---------------------------------------------------------------------------

func TestMillRunOnce_OnError_OldLogFilesError(t *testing.T) {
	t.Parallel()

	var received error
	w := &Writer{
		cfg: Config{
			MaxSize: 100, Mode: 0o600,
			OnError: func(err error) { received = err },
		},
		dir:    "/nonexistent/path",
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	w.millRunOnce()
	require.Error(t, received)
	assert.Contains(t, received.Error(), "read dir")
}

func TestMillRunOnce_OnError_CompressError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission restrictions")
	}
	t.Parallel()

	dir := t.TempDir()
	ts := time.Now().Add(-time.Minute).Format("2006-01-02T15-04-05.000")
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "audit-"+ts+".log"), []byte("data"), 0o600))

	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var received error
	w := &Writer{
		cfg: Config{
			MaxSize: 100, Mode: 0o600, Compress: true,
			OnError: func(err error) { received = err },
		},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	w.millRunOnce()
	require.Error(t, received)
	assert.Contains(t, received.Error(), "compress")
}

func TestMillRunOnce_OnError_Nil_NoPanic(t *testing.T) {
	t.Parallel()

	w := &Writer{
		cfg:    Config{MaxSize: 100, Mode: 0o600, OnError: nil},
		dir:    "/nonexistent/path",
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	// Must not panic with nil OnError.
	assert.NotPanics(t, func() { w.millRunOnce() })
}

func TestMillRunOnce_OnError_RemoveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission restrictions")
	}
	t.Parallel()

	dir := t.TempDir()

	// Create more backups than MaxBackups allows.
	for i := range 3 {
		ts := time.Now().Add(-time.Duration(i+1) * time.Minute).Format("2006-01-02T15-04-05.000")
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "audit-"+ts+".log"), []byte("data"), 0o600))
	}

	// Make directory read-only so removes fail.
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var received []error
	w := &Writer{
		cfg: Config{
			MaxSize: 100, Mode: 0o600, MaxBackups: 1,
			OnError: func(err error) { received = append(received, err) },
		},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	w.millRunOnce()
	assert.NotEmpty(t, received, "should receive remove errors")
	for _, err := range received {
		assert.Contains(t, err.Error(), "remove")
	}
}

func TestMillRunOnce_OnError_MaxAgeRemoveError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission restrictions")
	}
	t.Parallel()

	dir := t.TempDir()

	// Create an expired backup.
	old := time.Now().Add(-48 * time.Hour)
	ts := old.Format("2006-01-02T15-04-05.000")
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "audit-"+ts+".log"), []byte("expired"), 0o600))

	// Make directory read-only so remove fails.
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var received []error
	w := &Writer{
		cfg: Config{
			MaxSize: 100, Mode: 0o600,
			MaxAge:  24 * time.Hour,
			OnError: func(err error) { received = append(received, err) },
		},
		dir:    dir,
		prefix: "audit-",
		ext:    ".log",
		now:    time.Now,
	}

	w.millRunOnce()
	assert.NotEmpty(t, received, "should receive MaxAge remove error")
	assert.Contains(t, received[0].Error(), "remove expired backup")
}

func TestOpenNew_BackupDestSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows CI")
	}
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Create the active file.
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

	// Pre-create symlinks at ALL possible backup names so the collision
	// avoidance loop exhausts and backupName returns an error.
	frozen := time.Date(2026, 6, 15, 12, 0, 0, 0, time.Local)
	tsStr := frozen.Format("2006-01-02T15-04-05.000")
	trap := filepath.Join(dir, "trap.log")
	require.NoError(t, os.WriteFile(trap, []byte{}, 0o600))

	// Create base name and first few counter variants as symlinks.
	// backupName will skip all of them (they exist per Lstat) and
	// eventually try counter names that don't exist.
	baseName := filepath.Join(dir, "audit-"+tsStr+".log")
	require.NoError(t, os.Symlink(trap, baseName))
	for i := 1; i <= 5; i++ {
		require.NoError(t, os.Symlink(trap, fmt.Sprintf("%s/audit-%s-%d.log", dir, tsStr, i)))
	}

	w := &Writer{
		cfg:      Config{MaxSize: 100, Mode: 0o600},
		filename: path,
		dir:      dir,
		prefix:   "audit-",
		ext:      ".log",
		now:      func() time.Time { return frozen },
	}

	// openNew should succeed — backupName skips symlinks (they exist)
	// and finds a free counter slot. The rename goes to the free slot.
	err := w.openNew()
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// The active file should have been recreated.
	_, err = os.Stat(path)
	require.NoError(t, err)

	// The symlinks should still exist (not overwritten by rename).
	info, err := os.Lstat(baseName)
	require.NoError(t, err)
	assert.True(t, info.Mode()&os.ModeSymlink != 0,
		"symlink at base backup path should not be overwritten")
}

// TestWriter_Writev_BufioFallback exercises the Windows / no-
// vectored-primitive fallback path. A writevFn that always
// returns ErrUnsupported simulates the Windows build; the Writer
// probes it at construction, flips vectoredSupported to false,
// and routes every subsequent Writev through bufio per-buffer
// writes. Without this fallback, file output on Windows would
// return ErrUnsupported from every call.
func TestWriter_Writev_BufioFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := New(path, Config{
		MaxSize: 1 << 20,
		Mode:    0o600,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	// Swap in the unsupported stub to simulate Windows behaviour.
	// The probe's cache must also be flipped (probe already ran
	// with the real iouring.Writev during New).
	w.writevFn = func(int, [][]byte) (int, error) {
		return 0, iouringErrUnsupported
	}
	w.vectoredSupported = false

	bufs := [][]byte{
		[]byte("alpha\n"),
		[]byte("beta\n"),
		[]byte("gamma\n"),
	}
	want := []byte("alpha\nbeta\ngamma\n")

	n, err := w.Writev(bufs)
	if err != nil {
		t.Fatalf("Writev: %v", err)
	}
	if n != len(want) {
		t.Fatalf("n = %d, want %d", n, len(want))
	}
	if closeErr := w.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

// TestWriter_Writev_BufioFallback_EmptyBufsSkipped confirms
// zero-length entries are skipped in the fallback path too.
func TestWriter_Writev_BufioFallback_EmptyBufsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	w, err := New(path, Config{MaxSize: 1 << 20, Mode: 0o600})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	w.writevFn = func(int, [][]byte) (int, error) { return 0, iouringErrUnsupported }
	w.vectoredSupported = false

	bufs := [][]byte{{}, []byte("a"), {}, []byte("bc"), {}}
	n, err := w.Writev(bufs)
	if err != nil {
		t.Fatalf("Writev: %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	_ = w.Close()
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("file = %q, want %q", got, "abc")
	}
}

// iouringErrUnsupported is a local alias of iouring.ErrUnsupported
// so the fallback test does not need to import the submodule
// from an internal test file — the imports are already
// constrained by writer.go.
var iouringErrUnsupported = iouring.ErrUnsupported
