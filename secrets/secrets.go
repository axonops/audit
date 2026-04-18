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

package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// refPrefix is the required prefix for all secret references.
const refPrefix = "ref+"

// schemeSep is the separator between scheme and path.
const schemeSep = "://"

// Sentinel errors for secret provider operations. Consumers use
// [errors.Is] to distinguish error categories.
var (
	// ErrMalformedRef indicates a string starts with "ref+" but is
	// structurally invalid (missing scheme, path, key, or contains
	// path traversal).
	ErrMalformedRef = errors.New("secrets: malformed secret reference")

	// ErrProviderNotRegistered indicates no provider is registered
	// for the scheme in a ref URI.
	ErrProviderNotRegistered = errors.New("secrets: no provider registered for scheme")

	// ErrSecretNotFound indicates the secret path exists but the
	// requested key was not found.
	ErrSecretNotFound = errors.New("secrets: secret not found at path")

	// ErrSecretResolveFailed indicates a transient or permanent
	// failure during secret resolution (network error, auth failure).
	ErrSecretResolveFailed = errors.New("secrets: secret resolution failed")

	// ErrUnresolvedRef indicates that after all resolution passes, a
	// string in the config still contains a ref+ URI.
	ErrUnresolvedRef = errors.New("secrets: unresolved secret reference in config")
)

// Provider resolves secret references to their plaintext values.
// Implementations must be safe for sequential use within a single
// goroutine (the outputconfig load pipeline is single-threaded).
//
// Providers carry credentials and must redact them in [fmt.Stringer]
// output. Construction (New) must not perform network I/O — connection
// is deferred to the first [Resolve] call.
type Provider interface {
	// Scheme returns the URI scheme this provider handles (e.g.
	// "openbao", "vault"). Must be lowercase and match the scheme
	// used in ref+ URIs.
	Scheme() string

	// Resolve fetches the secret value for the given reference.
	// The ctx controls timeout and cancellation for network I/O.
	// Returns the plaintext secret value as a string.
	//
	// Implementations should call [Ref.Valid] before using the ref
	// path to guard against manually-constructed invalid refs.
	//
	// Errors should wrap the appropriate sentinel:
	//   - [ErrSecretNotFound] when the path or key does not exist
	//   - [ErrSecretResolveFailed] for transient or auth failures
	//
	// Memory retention: the returned string is a Go string and
	// cannot be zeroed. Providers SHOULD store their authentication
	// material as `[]byte` and zero it in [Close] to reduce the
	// retention window for bootstrap credentials, but the resolved
	// VALUE returned from Resolve persists in memory until GC
	// reclaims it. Callers (notably [outputconfig.Load]) embed
	// resolved values in long-lived config structs; see SECURITY.md
	// §Secrets and Memory Retention for the full model.
	Resolve(ctx context.Context, ref Ref) (string, error)

	// Close releases resources held by the provider (HTTP clients,
	// connection pools). Errors are informational — the caller
	// cannot recover from a close failure but should log it.
	// Close is idempotent.
	//
	// Memory retention: implementations SHOULD zero any `[]byte`
	// storage of authentication material (e.g. the provider token)
	// to minimise the retention window. This is best-effort —
	// Go strings derived from the bytes (e.g. HTTP header copies)
	// cannot be zeroed and persist until GC. See SECURITY.md
	// §Secrets and Memory Retention.
	Close() error
}

// BatchProvider is an optional extension of [Provider] for backends
// that can fetch all keys at a path in a single API call (e.g. Vault
// KV v2, OpenBao KV v2). The outputconfig resolver uses this to
// enable path-level caching — same path with different #key fragments
// results in one API call.
//
// Providers that do not implement BatchProvider fall back to per-key
// [Provider.Resolve] calls with ref-level caching.
type BatchProvider interface {
	Provider

	// ResolvePath fetches all key-value pairs at the given path.
	// Returns the full map; the caller extracts individual keys.
	// The caller guarantees that path has passed [Ref.Valid]
	// validation (no traversal, no empty segments).
	//
	// Returns [ErrSecretNotFound] when the path does not exist.
	// Returns [ErrSecretResolveFailed] for transient/auth failures.
	ResolvePath(ctx context.Context, path string) (map[string]string, error)
}

// Ref is a parsed secret reference. The zero value indicates that
// [ParseRef] determined the input was not a secret reference.
//
// Fields are exported for use by [Provider.Resolve] implementations.
// The Path field contains the vault path and MUST NOT appear in logs
// or error messages — use [Ref.String] for safe formatting.
type Ref struct {
	// Scheme is the provider identifier (e.g. "openbao", "vault").
	Scheme string

	// Path is the secret path within the provider. Never contains
	// ".." segments, "." segments, empty segments, or percent-encoded
	// characters. MUST NOT be included in logs or error messages.
	Path string

	// Key is the field name within the secret (from the URI fragment).
	Key string
}

// IsZero reports whether r is the zero value, indicating that
// [ParseRef] determined the input was not a secret reference.
func (r Ref) IsZero() bool {
	return r == Ref{}
}

// Valid reports whether r is structurally valid. Returns nil if all
// fields are non-empty and the path passes validation. Provider
// implementations should call this before using r.Path to guard
// against manually-constructed invalid refs.
func (r Ref) Valid() error {
	if r.Scheme == "" {
		return fmt.Errorf("%w: empty scheme", ErrMalformedRef)
	}
	if !isValidScheme(r.Scheme) {
		return fmt.Errorf("%w: invalid scheme %q", ErrMalformedRef, r.Scheme)
	}
	if r.Path == "" {
		return fmt.Errorf("%w: empty path", ErrMalformedRef)
	}
	if r.Key == "" {
		return fmt.Errorf("%w: empty key", ErrMalformedRef)
	}
	return validatePath(r.Path)
}

// String returns a safe representation that redacts the secret path
// to prevent infrastructure topology leakage in logs and error
// messages. Use the struct fields directly for internal operations.
func (r Ref) String() string {
	if r.IsZero() {
		return "<not a ref>"
	}
	return fmt.Sprintf("ref+%s://[REDACTED]#%s", r.Scheme, r.Key)
}

// GoString implements [fmt.GoStringer] to prevent path leakage via %#v.
func (r Ref) GoString() string {
	return r.String()
}

// Format implements [fmt.Formatter] to ensure path redaction across
// all format verbs (%v, %+v, %#v, %s). Without this, %+v would
// print the struct fields directly, leaking the vault path.
func (r Ref) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, r.String())
}

// ParseRef parses "ref+SCHEME://PATH#KEY" into a [Ref].
//
// Returns (zero, nil) if s does not start with "ref+" — the input is
// not a secret reference and callers should treat it as a literal value.
//
// Returns (zero, [ErrMalformedRef]) if s starts with "ref+" but is
// structurally invalid. Invalid cases include: empty scheme, empty
// path, leading slash in path, path containing ".." or "." segments,
// path containing empty segments (consecutive slashes), trailing
// slash, percent-encoded characters, empty or missing key fragment,
// key containing "#".
//
// Returns (ref, nil) on success.
func ParseRef(s string) (Ref, error) {
	if !strings.HasPrefix(s, refPrefix) {
		return Ref{}, nil
	}

	// Everything after "ref+"
	rest := s[len(refPrefix):]

	// Find "://" separator.
	sepIdx := strings.Index(rest, schemeSep)
	if sepIdx < 0 {
		return Ref{}, fmt.Errorf("%w: missing %q separator in %q", ErrMalformedRef, schemeSep, redactRef(s))
	}

	scheme := rest[:sepIdx]
	if scheme == "" {
		return Ref{}, fmt.Errorf("%w: empty scheme", ErrMalformedRef)
	}
	if !isValidScheme(scheme) {
		return Ref{}, fmt.Errorf("%w: invalid scheme %q", ErrMalformedRef, scheme)
	}

	// Everything after "://"
	pathAndKey := rest[sepIdx+len(schemeSep):]

	// Find "#" fragment separator.
	hashIdx := strings.Index(pathAndKey, "#")
	if hashIdx < 0 {
		return Ref{}, fmt.Errorf("%w: missing key fragment (#key)", ErrMalformedRef)
	}

	path := pathAndKey[:hashIdx]
	key := pathAndKey[hashIdx+1:]

	if path == "" {
		return Ref{}, fmt.Errorf("%w: empty path", ErrMalformedRef)
	}
	if key == "" {
		return Ref{}, fmt.Errorf("%w: empty key fragment", ErrMalformedRef)
	}
	if strings.Contains(key, "#") {
		return Ref{}, fmt.Errorf("%w: key fragment must not contain \"#\"", ErrMalformedRef)
	}

	if err := validatePath(path); err != nil {
		return Ref{}, err
	}

	return Ref{Scheme: scheme, Path: path, Key: key}, nil
}

// ContainsRef reports whether s contains a ref+ URI pattern anywhere
// in the string. Used by the safety-net scanner to detect unresolved
// references, including those embedded in larger strings.
//
// This function intentionally over-matches (false positives are
// acceptable). It checks for "ref+" followed by at least one
// lowercase letter and "://" — but does not validate the full ref
// structure. Callers should follow up with [ParseRef] for full
// validation when needed.
func ContainsRef(s string) bool {
	for i := 0; ; {
		idx := strings.Index(s[i:], refPrefix)
		if idx < 0 {
			return false
		}
		pos := i + idx + len(refPrefix)
		if pos >= len(s) {
			return false
		}
		// Require at least one lowercase alpha before "://".
		rest := s[pos:]
		if isLowerAlpha(rest[0]) && strings.Contains(rest, schemeSep) {
			return true
		}
		i = pos
	}
}

// ValidatePath checks that a secret path has no traversal, empty
// segments, or percent-encoded characters. Intended for
// [BatchProvider] implementations to validate paths received
// from external callers.
func ValidatePath(path string) error {
	return validatePath(path)
}

// validatePath is the internal implementation of [ValidatePath].
func validatePath(path string) error {
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w: path must not start with \"/\"", ErrMalformedRef)
	}
	if strings.HasSuffix(path, "/") {
		return fmt.Errorf("%w: path must not end with \"/\"", ErrMalformedRef)
	}
	if strings.Contains(path, "%") {
		return fmt.Errorf("%w: path must not contain percent-encoded characters", ErrMalformedRef)
	}

	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if seg == "" {
			return fmt.Errorf("%w: path contains empty segment", ErrMalformedRef)
		}
		if seg == ".." {
			return fmt.Errorf("%w: path contains \"..\" traversal segment", ErrMalformedRef)
		}
		if seg == "." {
			return fmt.Errorf("%w: path contains \".\" segment", ErrMalformedRef)
		}
	}
	return nil
}

// isValidScheme checks that a scheme contains only lowercase
// alphanumeric characters and hyphens, per RFC 3986 (simplified).
// First character must be a lowercase letter.
func isValidScheme(s string) bool {
	if s == "" {
		return false
	}
	if !isLowerAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isLowerAlpha(c) && !isDigit(c) && c != '-' {
			return false
		}
	}
	return true
}

func isLowerAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool      { return c >= '0' && c <= '9' }

// redactRef returns a redacted version of a ref string for use in
// error messages. Only called when the "://" separator is missing,
// so it always returns the malformed form.
func redactRef(_ string) string {
	return "ref+[malformed]"
}
