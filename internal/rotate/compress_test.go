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
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressFile_Success(t *testing.T) {
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
	defer f.Close()
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
	assert.Contains(t, err.Error(), "compress source")
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
	real := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "link.log")
	dst := filepath.Join(dir, "link.log.gz")

	require.NoError(t, os.WriteFile(real, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(real, link))

	err := compressFile(link, dst, 0o600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")

	// Destination should not have been created.
	_, err = os.Stat(dst)
	assert.True(t, os.IsNotExist(err))
}
