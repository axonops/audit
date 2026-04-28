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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// gzipCopy tests
// ---------------------------------------------------------------------------

type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }

type errorWriter struct{ err error }

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }

// errorAfterNWriter succeeds for the first n bytes, then returns err.
type errorAfterNWriter struct {
	err error
	w   io.Writer
	n   int
}

func (w *errorAfterNWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, w.err
	}
	if len(p) > w.n {
		n, _ := w.w.Write(p[:w.n])
		w.n = 0
		return n, w.err
	}
	n, writeErr := w.w.Write(p)
	w.n -= n
	if writeErr != nil {
		return n, fmt.Errorf("test write: %w", writeErr)
	}
	return n, nil
}

func TestGzipCopy_Success(t *testing.T) {
	t.Parallel()

	src := bytes.NewReader([]byte("hello world\n"))
	var dst bytes.Buffer

	require.NoError(t, gzipCopy(&dst, src))

	gr, err := gzip.NewReader(&dst)
	require.NoError(t, err)
	data, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello world\n"), data)
}

func TestGzipCopy_ReadError(t *testing.T) {
	t.Parallel()

	readErr := errors.New("disk read failure")
	src := &errorReader{err: readErr}
	var dst bytes.Buffer

	err := gzipCopy(&dst, src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compress copy")
	assert.ErrorIs(t, err, readErr)
}

func TestGzipCopy_WriteError(t *testing.T) {
	t.Parallel()

	src := bytes.NewReader([]byte("data to compress"))
	writeErr := errors.New("disk write failure")
	dst := &errorWriter{err: writeErr}

	err := gzipCopy(dst, src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compress copy")
	assert.ErrorIs(t, err, writeErr)
}

func TestGzipCopy_FlushError(t *testing.T) {
	t.Parallel()

	// Use a large input so gzip must flush multiple times. The
	// errorAfterNWriter accepts the gzip header and initial compressed
	// data, then fails on a subsequent write — triggering an error
	// during either io.Copy or gz.Close.
	src := bytes.NewReader(bytes.Repeat([]byte("x"), 64*1024))
	flushErr := errors.New("flush failure")
	dst := &errorAfterNWriter{
		w:   &bytes.Buffer{},
		n:   20, // accept gzip header (~10 bytes) + a few compressed bytes
		err: flushErr,
	}

	err := gzipCopy(dst, src)
	require.Error(t, err)
	// Error surfaces during io.Copy or gz.Close depending on buffer timing.
	assert.True(t,
		containsAny(err.Error(), "compress copy", "gzip close"),
		"error should mention compress copy or gzip close, got: %v", err)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// compressFile tests
// ---------------------------------------------------------------------------

func TestCompressFile_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file-locking semantics + POSIX permission bits combine to break compressFile's unlink-after-gzip + chmod 0o640 sequence; see #760 family")
	}
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "input.log")
	dst := filepath.Join(dir, "input.log.gz")

	content := []byte("hello world\n")
	require.NoError(t, os.WriteFile(src, content, 0o644))

	require.NoError(t, compressFile(src, dst, 0o640))

	// Source should be removed.
	_, err := os.Stat(src)
	assert.True(t, os.IsNotExist(err))

	// Dest should exist with correct mode.
	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())

	// Dest should be valid gzip with correct content.
	f, err := os.Open(dst)
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck // test cleanup
	gr, err := gzip.NewReader(f)
	require.NoError(t, err)
	data, err := io.ReadAll(gr)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestCompressFile_SourceMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "missing.log")
	dst := filepath.Join(dir, "missing.log.gz")

	err := compressFile(src, dst, 0o600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compress open source")
}

func TestCompressFile_DestDirMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "input.log")
	dst := filepath.Join(dir, "nodir", "input.log.gz")

	require.NoError(t, os.WriteFile(src, []byte("data"), 0o644))

	err := compressFile(src, dst, 0o600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create dest")

	// Source should be left intact on error.
	_, err = os.Stat(src)
	assert.NoError(t, err)
}

func TestCompressFile_SourceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests unreliable on Windows CI")
	}
	t.Parallel()

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "link.log")
	dst := filepath.Join(dir, "link.log.gz")

	require.NoError(t, os.WriteFile(realFile, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(realFile, link))

	err := compressFile(link, dst, 0o600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compress open source")

	// Destination should not have been created.
	_, err = os.Stat(dst)
	assert.True(t, os.IsNotExist(err))
}

func TestCompressFile_RemoveSourceFails_ErrorReturned(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can remove files from read-only dirs; test requires non-root")
	}
	t.Parallel()

	dir := t.TempDir()
	subdir := filepath.Join(dir, "logs")
	require.NoError(t, os.Mkdir(subdir, 0o755))

	src := filepath.Join(subdir, "input.log")
	dst := filepath.Join(dir, "input.log.gz") // dst in parent dir (writable)

	require.NoError(t, os.WriteFile(src, []byte("data to compress\n"), 0o644))

	// Make the source's parent directory non-writable so os.Remove(src) fails,
	// but dst lives in a writable directory so compression itself succeeds.
	require.NoError(t, os.Chmod(subdir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o755) })

	err := compressFile(src, dst, 0o600)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove source")
}
