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

package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/file"
)

// TestProvider_Resolve_WholeFile reads the entire file content (no
// fragment) and trims a single trailing newline.
func TestProvider_Resolve_WholeFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("s3cret-value\n"), 0o644))

	p := file.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
	})
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", got)
}

// TestProvider_Resolve_WholeFile_NoTrailingNewline confirms trim is
// "rstrip one \n" not "all whitespace".
func TestProvider_Resolve_WholeFile_NoTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(path, []byte("s3cret"), 0o644))

	p := file.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
	})
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got)
}

// TestProvider_Resolve_JSONFragment parses JSON and extracts the
// dotted-fragment path.
func TestProvider_Resolve_JSONFragment(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	body := `{"db":{"password":"top-secret"},"misc":42}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	p := file.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
		Key:    "db.password",
	})
	require.NoError(t, err)
	assert.Equal(t, "top-secret", got)
}

// TestProvider_Resolve_JSONFragmentNotFound returns ErrSecretResolveFailed.
func TestProvider_Resolve_JSONFragmentNotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"db":{"password":"x"}}`), 0o644))

	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
		Key:    "db.missing",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_JSONNonStringTerminal rejects numeric / object
// terminals (only string leaves are valid secrets).
func TestProvider_Resolve_JSONNonStringTerminal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"port":5432,"obj":{"x":1}}`), 0o644))

	p := file.New()
	for _, key := range []string{"port", "obj"} {
		_, err := p.Resolve(context.Background(), secrets.Ref{
			Scheme: file.Scheme,
			Path:   path,
			Key:    key,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
	}
}

// TestProvider_Resolve_JSONInvalid rejects unparseable JSON when a
// fragment is requested.
func TestProvider_Resolve_JSONInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(path, []byte("not-json"), 0o644))

	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
		Key:    "any.key",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_MissingFile reports ErrSecretResolveFailed.
func TestProvider_Resolve_MissingFile(t *testing.T) {
	t.Parallel()
	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   "/nonexistent/path/abcd-1234",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_RelativePathRejected — locked S1 contract.
func TestProvider_Resolve_RelativePathRejected(t *testing.T) {
	t.Parallel()
	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   "relative/path",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
}

// TestProvider_Resolve_DotDotRejected — locked S1 contract.
func TestProvider_Resolve_DotDotRejected(t *testing.T) {
	t.Parallel()
	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   "/etc/../etc/passwd",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
}

// TestProvider_Resolve_NULByteRejected — locked S1 contract; defends
// against C-string truncation in any consumer that prints the path.
func TestProvider_Resolve_NULByteRejected(t *testing.T) {
	t.Parallel()
	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   "/etc/secret\x00.txt",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
}

// TestProvider_Resolve_OversizedFile — locked S2 contract: 1 MiB cap.
func TestProvider_Resolve_OversizedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")
	// 1 MiB + 1 byte → over the cap.
	require.NoError(t, os.WriteFile(path, make([]byte, 1<<20+1), 0o644))

	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   path,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_FollowsSymlink — the locked Q4/S4 contract.
// K8s mounted secrets use a `..data` symlink pointing at a timestamped
// directory; rotation atomically swaps the symlink. The provider
// MUST follow the symlink so consumers see the current value.
func TestProvider_Resolve_FollowsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real-secret.txt")
	require.NoError(t, os.WriteFile(target, []byte("via-symlink\n"), 0o644))
	link := filepath.Join(dir, "alias.txt")
	require.NoError(t, os.Symlink(target, link))

	p := file.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   link,
	})
	require.NoError(t, err)
	assert.Equal(t, "via-symlink", got)
}

// TestProvider_Resolve_K8sAtomicSwap simulates the K8s
// `..data → ..data_NEW` atomic rename pattern. After re-pointing
// the symlink, the next Resolve sees the new content.
func TestProvider_Resolve_K8sAtomicSwap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	require.NoError(t, os.WriteFile(old, []byte("v1\n"), 0o644))
	link := filepath.Join(dir, "current")
	require.NoError(t, os.Symlink(old, link))

	p := file.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   link,
	})
	require.NoError(t, err)
	require.Equal(t, "v1", got)

	// Atomic-swap simulation.
	newp := filepath.Join(dir, "new.txt")
	require.NoError(t, os.WriteFile(newp, []byte("v2\n"), 0o644))
	tmp := link + ".tmp"
	require.NoError(t, os.Symlink(newp, tmp))
	require.NoError(t, os.Rename(tmp, link))

	got, err = p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   link,
	})
	require.NoError(t, err)
	assert.Equal(t, "v2", got, "post-swap Resolve must see new content (no caching)")
}

// TestProvider_Resolve_PathRedaction — the path MUST NOT appear in
// any error message (locked Extra contract).
func TestProvider_Resolve_PathRedaction(t *testing.T) {
	t.Parallel()
	const sentinel = "/var/run/secrets/UNIQUE-REDACT-SENTINEL/token"
	p := file.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: file.Scheme,
		Path:   sentinel,
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "UNIQUE-REDACT-SENTINEL",
		"error message MUST NOT contain any path substring")
}

// TestProvider_Scheme returns "file".
func TestProvider_Scheme(t *testing.T) {
	t.Parallel()
	p := file.New()
	assert.Equal(t, "file", p.Scheme())
	assert.Equal(t, "file", file.Scheme)
}

// TestProvider_Close is a no-op idempotent.
func TestProvider_Close(t *testing.T) {
	t.Parallel()
	p := file.New()
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
}

// TestProvider_Concurrent — Resolve from many goroutines under
// -race. Provider is stateless; verifies zero shared state.
func TestProvider_Concurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.txt")
	require.NoError(t, os.WriteFile(path, []byte("shared"), 0o644))

	p := file.New()
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			val, err := p.Resolve(context.Background(), secrets.Ref{
				Scheme: file.Scheme,
				Path:   path,
			})
			assert.NoError(t, err)
			assert.Equal(t, "shared", val)
		}()
	}
	wg.Wait()
}

// TestProvider_ParseRef_Integration verifies the documented URI
// shape end-to-end via [secrets.ParseRef].
func TestProvider_ParseRef_Integration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "via-parseref.txt")
	require.NoError(t, os.WriteFile(path, []byte("ok\n"), 0o644))

	ref, err := secrets.ParseRef("ref+file://" + path)
	require.NoError(t, err)
	assert.Equal(t, "file", ref.Scheme)
	// ParseRef preserves the leading slash for file:// schemes.
	assert.True(t, strings.HasPrefix(ref.Path, "/"), "file:// path must retain leading slash")

	p := file.New()
	got, err := p.Resolve(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "ok", got)
}
