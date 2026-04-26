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

package file

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/axonops/audit/secrets"
)

// Scheme is the URI scheme this provider handles. Use it as the
// scheme component in `ref+file:///path/to/secret` references.
const Scheme = "file"

// maxFileSize is the maximum bytes accepted from a single Resolve.
// Mirrors the openbao provider's response cap; large enough for any
// realistic secret (e.g. a multi-line PEM bundle ~ 20 KiB) yet small
// enough to bound memory if a misconfigured ref points at /dev/zero
// or a runaway log file.
const maxFileSize = 1 << 20 // 1 MiB

// Provider implements [secrets.SecretProvider] for filesystem
// secret references. The zero value is ready to use; the provider
// is stateless and safe for concurrent use by multiple goroutines.
type Provider struct{}

// Compile-time interface satisfaction check.
var _ secrets.Provider = (*Provider)(nil)

// Option configures a [Provider]. Reserved for future per-provider
// settings; no options exist today.
type Option func(*Provider)

// New returns a new file:// secret provider. Accepts a variadic
// list of [Option] for forward compatibility; no options are
// currently defined.
func New(opts ...Option) *Provider {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Scheme returns the URI scheme this provider handles ("file").
func (*Provider) Scheme() string { return Scheme }

// Close is a no-op. The file provider holds no resources to release;
// each Resolve call opens and closes its own file descriptor.
// Idempotent; safe to call multiple times.
func (*Provider) Close() error { return nil }

// Resolve reads the file referenced by ref and returns its contents
// as the secret value. The file path MUST be absolute, MUST NOT
// contain `..` segments, and MUST NOT contain a NUL byte; symlinks
// are followed (Kubernetes `..data` atomic-swap pattern). The file
// MUST be at most 1 MiB ([maxFileSize]).
//
// If ref.Key is empty, the entire file content is returned (a
// single trailing newline is trimmed). If ref.Key is set, the file
// is parsed as JSON and the key is interpreted as a dotted path
// into nested objects. Only scalar string leaves are returned;
// numeric / boolean / object terminals return
// [secrets.ErrSecretResolveFailed].
//
// The path is NEVER echoed in error messages — knowing the secret
// path leaks deployment topology that a log scraper should not
// gain. Use the auditor's slog diagnostic output (typically
// stderr, not shipped to a log aggregator) for local debugging
// and inspect the returned error chain via [errors.Is] for
// programmatic handling.
func (*Provider) Resolve(_ context.Context, ref secrets.Ref) (string, error) {
	if err := ref.Valid(); err != nil {
		return "", fmt.Errorf("audit/secrets/file: %w", err)
	}
	if ref.Scheme != Scheme {
		return "", fmt.Errorf("audit/secrets/file: unexpected scheme: %w", secrets.ErrMalformedRef)
	}
	if err := validatePath(ref.Path); err != nil {
		return "", fmt.Errorf("audit/secrets/file: %w", err)
	}

	content, err := readBounded(ref.Path)
	if err != nil {
		return "", fmt.Errorf("audit/secrets/file: %w", err)
	}

	if ref.Key == "" {
		return strings.TrimRight(string(content), "\n"), nil
	}
	return extractJSONKey(content, ref.Key)
}

// validatePath enforces the security S1 contract: absolute path,
// no `..` segments after Clean, no NUL byte. The path itself is
// never echoed in the returned error.
func validatePath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path must be absolute (redacted): %w", secrets.ErrMalformedRef)
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("path contains NUL byte (redacted): %w", secrets.ErrMalformedRef)
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(cleaned, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("path contains parent-directory segment (redacted): %w", secrets.ErrMalformedRef)
		}
	}
	return nil
}

// readBounded opens path and reads at most [maxFileSize] bytes. A
// file that exceeds the cap returns [secrets.ErrSecretResolveFailed]
// with no path in the message.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path validated by validatePath; operator-controlled config is the trust boundary (#604 S1)
	if err != nil {
		// Don't echo the OS error verbatim — `os.PathError.Error()`
		// includes the path. Wrap with a fixed message.
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found (redacted): %w", secrets.ErrSecretResolveFailed)
		}
		return nil, fmt.Errorf("open failed (redacted): %w", secrets.ErrSecretResolveFailed)
	}
	defer func() { _ = f.Close() }()

	// Read up to maxFileSize+1 bytes so we can detect oversize
	// (read exactly maxFileSize → still potentially-larger-but-
	// truncated; read maxFileSize+1 → definitely oversize).
	content, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read failed (redacted): %w", secrets.ErrSecretResolveFailed)
	}
	if len(content) > maxFileSize {
		return nil, fmt.Errorf("file exceeds %d bytes (redacted): %w", maxFileSize, secrets.ErrSecretResolveFailed)
	}
	return content, nil
}

// extractJSONKey parses content as JSON and traverses the dotted
// path in key, returning the scalar string leaf. Anything else —
// non-object intermediate node, missing key, non-string terminal —
// returns [secrets.ErrSecretResolveFailed]. The key itself is not
// echoed in errors (it is consumer-controlled config and not
// inherently sensitive, but consistent redaction is the safer
// default).
func extractJSONKey(content []byte, key string) (string, error) {
	var root any
	if err := json.Unmarshal(content, &root); err != nil {
		return "", fmt.Errorf("audit/secrets/file: invalid JSON (redacted): %w", secrets.ErrSecretResolveFailed)
	}
	cur := root
	for _, seg := range strings.Split(key, ".") {
		if seg == "" {
			return "", fmt.Errorf("audit/secrets/file: empty key segment: %w", secrets.ErrMalformedRef)
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("audit/secrets/file: key path traverses non-object: %w", secrets.ErrSecretResolveFailed)
		}
		cur, ok = obj[seg]
		if !ok {
			return "", fmt.Errorf("audit/secrets/file: key not found: %w", secrets.ErrSecretResolveFailed)
		}
	}
	leaf, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("audit/secrets/file: terminal value is not a string: %w", secrets.ErrSecretResolveFailed)
	}
	return leaf, nil
}
