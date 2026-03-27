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

package audit_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileOutput_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	require.NoError(t, out.Write(data))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(data), string(content))
}

func TestFileOutput_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
}

func TestFileOutput_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestFileOutput_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data\n"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestFileOutput_Name(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "file:"+path, out.Name())
}

func TestFileOutput_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// File is created lazily on first Write.
	require.NoError(t, out.Write([]byte("test\n")))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileOutput_CustomPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:        path,
		Permissions: "0644",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// File is created lazily on first Write.
	require.NoError(t, out.Write([]byte("test\n")))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestFileOutput_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// All zero-value fields should get sensible defaults.
	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Verify the output is functional.
	require.NoError(t, out.Write([]byte("test\n")))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test\n", string(content))
}

func TestFileOutput_InvalidConfig(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		wantErr string
		cfg     audit.FileConfig
	}{
		{
			name:    "empty path",
			cfg:     audit.FileConfig{Path: ""},
			wantErr: "must not be empty",
		},
		{
			name:    "missing parent directory",
			cfg:     audit.FileConfig{Path: "/nonexistent/dir/audit.log"},
			wantErr: "parent directory",
		},
		{
			name: "invalid permissions",
			cfg: audit.FileConfig{
				Path:        filepath.Join(dir, "invalid-perm.log"),
				Permissions: "not-octal",
			},
			wantErr: "permissions",
		},
		{
			name: "permissions out of range",
			cfg: audit.FileConfig{
				Path:        filepath.Join(dir, "out-of-range.log"),
				Permissions: "1777",
			},
			wantErr: "exceeds maximum",
		},
		{
			name: "MaxSizeMB exceeds limit",
			cfg: audit.FileConfig{
				Path:      filepath.Join(dir, "big.log"),
				MaxSizeMB: audit.MaxFileSizeMB + 1,
			},
			wantErr: "max_size_mb",
		},
		{
			name: "MaxBackups exceeds limit",
			cfg: audit.FileConfig{
				Path:       filepath.Join(dir, "backups.log"),
				MaxBackups: audit.MaxFileBackups + 1,
			},
			wantErr: "max_backups",
		},
		{
			name: "MaxAgeDays exceeds limit",
			cfg: audit.FileConfig{
				Path:       filepath.Join(dir, "age.log"),
				MaxAgeDays: audit.MaxFileAgeDays + 1,
			},
			wantErr: "max_age_days",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := audit.NewFileOutput(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestFileOutput_MaxBoundaryValues_Accepted(t *testing.T) {
	dir := t.TempDir()
	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:       filepath.Join(dir, "boundary.log"),
		MaxSizeMB:  audit.MaxFileSizeMB,
		MaxBackups: audit.MaxFileBackups,
		MaxAgeDays: audit.MaxFileAgeDays,
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestFileOutput_MaxExceeded_WrapsErrConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	_, err := audit.NewFileOutput(audit.FileConfig{
		Path:      filepath.Join(dir, "test.log"),
		MaxSizeMB: audit.MaxFileSizeMB + 1,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestFileOutput_ImplementsOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	var _ audit.Output = out
}

func TestFileOutput_MultipleWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	for i := range 10 {
		data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", i))
		require.NoError(t, out.Write(data))
	}

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Len(t, lines, 10)
}

func TestFileOutput_ConcurrentWriteClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := audit.NewFileOutput(audit.FileConfig{Path: path})
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", n))
			// Errors are expected after Close; just exercise the race detector.
			_ = out.Write(data)
		}(i)
	}

	// Close while writes are in-flight.
	assert.NoError(t, out.Close())
	wg.Wait()

	// Verify no panic occurred. The file may not exist if Close() won
	// the race against all write goroutines — the writer is lazy-open,
	// so if no write succeeded before close, no file is created.
	if _, statErr := os.Stat(path); statErr == nil {
		_, err = os.ReadFile(path)
		require.NoError(t, err)
	}
}

func TestFileOutput_CompressFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := false
	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:     path,
		Compress: &compress,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Just verify construction succeeds with Compress=false.
	require.NoError(t, out.Write([]byte("test\n")))
}

func TestFileOutput_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "symlink.log")

	// Create a real file, then a symlink pointing to it.
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink(target, link))

	// Construction succeeds — symlink check happens on first Write.
	out, err := audit.NewFileOutput(audit.FileConfig{Path: link})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	err = out.Write([]byte("test\n"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
}
