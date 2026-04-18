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

package secrets_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/secrets"
)

// ---------------------------------------------------------------------------
// ParseRef — not-a-ref cases (returns zero, nil)
// ---------------------------------------------------------------------------

func TestParseRef_NotARef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"plain literal value", "my-secret-salt"},
		{"environment variable reference", "${HMAC_SALT}"},
		{"URL without ref+ prefix", "https://vault.example.com/secret#key"},
		{"ref+ substring not at start", "prefixref+openbao://path#key"},
		{"uppercase REF+ prefix", "REF+openbao://path#key"},
		{"mixed case Ref+ prefix", "Ref+openbao://path#key"},
		{"ref without plus sign", "refopenbao://path#key"},
		{"whitespace only", " "},
		{"ref- with wrong delimiter", "ref-openbao://path#key"},
		{"literal true", "true"},
		{"literal false", "false"},
		{"numeric value", "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ref, err := secrets.ParseRef(tt.input)
			require.NoError(t, err)
			assert.True(t, ref.IsZero(), "expected zero Ref for input %q", tt.input)
		})
	}
}

// ---------------------------------------------------------------------------
// ParseRef — malformed ref cases (starts with ref+, returns ErrMalformedRef)
// ---------------------------------------------------------------------------

func TestParseRef_Malformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		errHint string // substring expected in error message
	}{
		{"ref+ prefix only", "ref+", "://"},
		{"missing scheme", "ref+://path#key", "empty scheme"},
		{"missing :// separator", "ref+openbao/path#key", "://"},
		{"missing path", "ref+openbao://#key", "empty path"},
		{"missing key fragment", "ref+openbao://secret/data/hmac", "key fragment"},
		{"empty key after hash", "ref+openbao://secret/data/hmac#", "empty key"},
		{"path with .. traversal", "ref+openbao://secret/../etc/passwd#key", ".."},
		{"path starting with ..", "ref+openbao://../etc/passwd#key", ".."},
		{"path ending with ..", "ref+openbao://secret/data/..#key", ".."},
		{"path that is only ..", "ref+openbao://..#key", ".."},
		{"path with . segment", "ref+openbao://secret/./data#key", "."},
		{"path that is only .", "ref+openbao://.#key", "."},
		{"path with empty segment (double slash)", "ref+openbao://secret//data/hmac#key", "empty segment"},
		{"path with leading slash", "ref+openbao:///secret/data/hmac#key", "must not start"},
		{"path with trailing slash", "ref+openbao://secret/data/hmac/#key", "must not end"},
		{"scheme with colon only", "ref+openbao:path#key", "://"},
		{"scheme with single slash", "ref+openbao:/path#key", "://"},
		{"key contains hash", "ref+openbao://path#key1#key2", "#"},
		{"scheme starts with digit", "ref+1openbao://path#key", "invalid scheme"},
		{"scheme starts with hyphen", "ref+-openbao://path#key", "invalid scheme"},
		{"scheme with uppercase", "ref+OpenBao://path#key", "invalid scheme"},
		{"scheme with underscore", "ref+open_bao://path#key", "invalid scheme"},
		{"triple slash path", "ref+openbao:////#key", "must not start"},
		{"percent-encoded path", "ref+openbao://secret/data%2Fhmac#key", "percent-encoded"},
		{"percent-encoded traversal", "ref+openbao://secret/%2e%2e/etc/passwd#key", "percent-encoded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ref, err := secrets.ParseRef(tt.input)
			require.Error(t, err)
			assert.ErrorIs(t, err, secrets.ErrMalformedRef)
			assert.True(t, ref.IsZero(), "expected zero Ref for malformed input")
			assert.Contains(t, err.Error(), tt.errHint,
				"error message should contain %q for input %q", tt.errHint, tt.input)
		})
	}
}

// ---------------------------------------------------------------------------
// ParseRef — valid ref cases
// ---------------------------------------------------------------------------

func TestParseRef_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		scheme string
		path   string
		key    string
	}{
		{
			name:   "openbao standard path",
			input:  "ref+openbao://secret/data/audit/hmac#salt",
			scheme: "openbao", path: "secret/data/audit/hmac", key: "salt",
		},
		{
			name:   "vault scheme",
			input:  "ref+vault://secret/data/audit/hmac#salt",
			scheme: "vault", path: "secret/data/audit/hmac", key: "salt",
		},
		{
			name:   "single path segment",
			input:  "ref+openbao://mypath#mykey",
			scheme: "openbao", path: "mypath", key: "mykey",
		},
		{
			name:   "deeply nested path",
			input:  "ref+openbao://a/b/c/d/e/f/g#key",
			scheme: "openbao", path: "a/b/c/d/e/f/g", key: "key",
		},
		{
			name:   "key with underscores",
			input:  "ref+openbao://secret/data/hmac#salt_value",
			scheme: "openbao", path: "secret/data/hmac", key: "salt_value",
		},
		{
			name:   "key with hyphens",
			input:  "ref+openbao://secret/data/hmac#my-key",
			scheme: "openbao", path: "secret/data/hmac", key: "my-key",
		},
		{
			name:   "path with hyphens and underscores",
			input:  "ref+openbao://secret/my-app/audit_config#key",
			scheme: "openbao", path: "secret/my-app/audit_config", key: "key",
		},
		{
			name:   "numeric path segments",
			input:  "ref+openbao://secret/data/v2/hmac#version",
			scheme: "openbao", path: "secret/data/v2/hmac", key: "version",
		},
		{
			name:   "single character scheme",
			input:  "ref+x://path#key",
			scheme: "x", path: "path", key: "key",
		},
		{
			name:   "scheme with digits",
			input:  "ref+vault2://path#key",
			scheme: "vault2", path: "path", key: "key",
		},
		{
			name:   "scheme with hyphens",
			input:  "ref+my-provider://path#key",
			scheme: "my-provider", path: "path", key: "key",
		},
		{
			name:   "single character key",
			input:  "ref+openbao://path#k",
			scheme: "openbao", path: "path", key: "k",
		},
		{
			name:   "HMAC enabled field from spec",
			input:  "ref+openbao://secret/data/audit/hmac#enabled",
			scheme: "openbao", path: "secret/data/audit/hmac", key: "enabled",
		},
		{
			name:   "HMAC version field from spec",
			input:  "ref+openbao://secret/data/audit/hmac#version",
			scheme: "openbao", path: "secret/data/audit/hmac", key: "version",
		},
		{
			name:   "HMAC algorithm field from spec",
			input:  "ref+openbao://secret/data/audit/hmac#algorithm",
			scheme: "openbao", path: "secret/data/audit/hmac", key: "algorithm",
		},
		{
			name:   "path with dots in segment names (not ..)",
			input:  "ref+openbao://secret/data/v1.2/hmac#key",
			scheme: "openbao", path: "secret/data/v1.2/hmac", key: "key",
		},
		{
			name:   "three dots segment is valid",
			input:  "ref+openbao://secret/...#key",
			scheme: "openbao", path: "secret/...", key: "key",
		},
		{
			name:   "..hidden segment is valid",
			input:  "ref+openbao://secret/..hidden#key",
			scheme: "openbao", path: "secret/..hidden", key: "key",
		},
		{
			name:   "key with dots",
			input:  "ref+openbao://path#my.key.name",
			scheme: "openbao", path: "path", key: "my.key.name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ref, err := secrets.ParseRef(tt.input)
			require.NoError(t, err)
			assert.False(t, ref.IsZero(), "expected non-zero Ref")
			assert.Equal(t, tt.scheme, ref.Scheme)
			assert.Equal(t, tt.path, ref.Path)
			assert.Equal(t, tt.key, ref.Key)
		})
	}
}

// ---------------------------------------------------------------------------
// Ref.String() and GoString()
// ---------------------------------------------------------------------------

func TestRef_String_RedactsPath(t *testing.T) {
	t.Parallel()

	ref := secrets.Ref{Scheme: "openbao", Path: "secret/data/audit/hmac", Key: "salt"}
	s := ref.String()

	assert.Contains(t, s, "openbao")
	assert.Contains(t, s, "salt")
	assert.Contains(t, s, "[REDACTED]")
	assert.NotContains(t, s, "secret/data/audit/hmac")
}

func TestRef_GoString_RedactsPath(t *testing.T) {
	t.Parallel()

	ref := secrets.Ref{Scheme: "vault", Path: "secret/data/prod/hmac", Key: "version"}
	gs := ref.GoString()

	assert.NotContains(t, gs, "secret/data/prod/hmac")
	assert.Contains(t, gs, "[REDACTED]")

	// Also verify that fmt verbs route through these methods.
	//nolint:gocritic // intentionally testing fmt routing
	fmtResult := fmt.Sprint(ref)
	assert.NotContains(t, fmtResult, "secret/data/prod/hmac")
}

func TestRef_String_ZeroValue(t *testing.T) {
	t.Parallel()

	var ref secrets.Ref
	assert.Equal(t, "<not a ref>", ref.String())
}

// ---------------------------------------------------------------------------
// Ref.IsZero()
// ---------------------------------------------------------------------------

func TestRef_IsZero(t *testing.T) {
	t.Parallel()

	assert.True(t, secrets.Ref{}.IsZero())
	assert.False(t, secrets.Ref{Scheme: "openbao"}.IsZero())
	assert.False(t, secrets.Ref{Path: "path"}.IsZero())
	assert.False(t, secrets.Ref{Key: "key"}.IsZero())
	assert.False(t, secrets.Ref{Scheme: "x", Path: "p", Key: "k"}.IsZero())
}

// ---------------------------------------------------------------------------
// ContainsRef
// ---------------------------------------------------------------------------

func TestContainsRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"empty string", "", false},
		{"plain literal", "hello world", false},
		{"env var", "${HMAC_SALT}", false},
		{"valid ref", "ref+openbao://path#key", true},
		{"ref embedded in string", "prefix ref+vault://path#key suffix", true},
		{"ref+ without ://", "ref+openbao", false},
		{"partial ref+ with ://", "ref+openbao://", true},
		{"just ref+", "ref+", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, secrets.ContainsRef(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Sentinel errors are distinct
// ---------------------------------------------------------------------------

func TestSentinelErrors_AreDistinct(t *testing.T) {
	t.Parallel()

	errs := []error{
		secrets.ErrMalformedRef,
		secrets.ErrProviderNotRegistered,
		secrets.ErrSecretNotFound,
		secrets.ErrSecretResolveFailed,
		secrets.ErrUnresolvedRef,
	}
	for i, a := range errs {
		for j, b := range errs {
			if i != j {
				assert.NotErrorIs(t, a, b, "%v and %v should be distinct", a, b)
			}
		}
	}
}

func TestSentinelErrors_HaveSecretsPrefix(t *testing.T) {
	t.Parallel()

	errs := []error{
		secrets.ErrMalformedRef,
		secrets.ErrProviderNotRegistered,
		secrets.ErrSecretNotFound,
		secrets.ErrSecretResolveFailed,
		secrets.ErrUnresolvedRef,
	}
	for _, e := range errs {
		assert.Contains(t, e.Error(), "secrets:", "error %q should have secrets: prefix", e)
	}
}

// ---------------------------------------------------------------------------
// ParseRef error wrapping
// ---------------------------------------------------------------------------

func TestParseRef_MalformedError_WrapsErrMalformedRef(t *testing.T) {
	t.Parallel()

	// Every malformed ref should wrap ErrMalformedRef.
	malformed := []string{
		"ref+",
		"ref+://path#key",
		"ref+openbao://path",
		"ref+openbao://path#",
		"ref+openbao://../etc/passwd#key",
		"ref+openbao://path//double#key",
	}
	for _, input := range malformed {
		_, err := secrets.ParseRef(input)
		require.Error(t, err, "input: %q", input)
		assert.ErrorIs(t, err, secrets.ErrMalformedRef, "input: %q", input)
	}
}

func TestParseRef_ErrorMessages_DoNotContainFullPath(t *testing.T) {
	t.Parallel()

	// Error messages for malformed refs should not leak the full vault path.
	_, err := secrets.ParseRef("ref+openbao://secret/very/deep/path/to/sensitive/data#key")
	// This is a valid ref, so no error:
	require.NoError(t, err)

	// But for a malformed one with a full path, verify no path leakage:
	_, err = secrets.ParseRef("ref+openbao://secret/very/deep/../../../etc/passwd#key")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret/very/deep/../../../etc/passwd")
}

// TestParseRef_NeverLeaksInputInErrorMessage is the comprehensive
// non-leakage contract for ParseRef (#486). For every malformed-input
// class, the returned error message MUST NOT contain any substring of
// the scheme, path, or key portions of the input. A single byte of
// user-controlled content in a diagnostic log is a leakage vector —
// even a scheme like "leak-secret" or a path like "secret/production"
// tells an attacker something about the deployment.
//
// The test is table-driven with sentinel markers embedded in each
// component ("LEAKSCHEME", "LEAKPATH", "LEAKKEY") so the assertion
// can be exact: the error MUST NOT contain any of the sentinels.
func TestParseRef_NeverLeaksInputInErrorMessage(t *testing.T) {
	t.Parallel()

	const (
		schemeMarker = "LEAKSCHEME"
		pathMarker   = "LEAKPATH"
		keyMarker    = "LEAKKEY"
	)

	tests := []struct {
		name  string
		input string
	}{
		// Class: missing "://" separator — whole-input case.
		{"missing_scheme_sep", "ref+" + schemeMarker + pathMarker + "#" + keyMarker},

		// Class: empty scheme ("ref+://path#key").
		{"empty_scheme", "ref+://" + pathMarker + "#" + keyMarker},

		// Class: invalid scheme (rejected by isValidScheme).
		{"invalid_scheme_starts_with_digit", "ref+1" + schemeMarker + "://" + pathMarker + "#" + keyMarker},
		{"invalid_scheme_starts_with_hyphen", "ref+-" + schemeMarker + "://" + pathMarker + "#" + keyMarker},
		{"invalid_scheme_uppercase", "ref+" + schemeMarker + "Bao://" + pathMarker + "#" + keyMarker},
		{"invalid_scheme_underscore", "ref+" + schemeMarker + "_bao://" + pathMarker + "#" + keyMarker},
		{"invalid_scheme_special_char", "ref+" + schemeMarker + "!://" + pathMarker + "#" + keyMarker},

		// Class: missing key fragment (no "#").
		{"missing_key_fragment", "ref+env://" + pathMarker},

		// Class: empty path ("ref+env://#key").
		{"empty_path", "ref+env://#" + keyMarker},

		// Class: empty key ("ref+env://path#").
		{"empty_key_fragment", "ref+env://" + pathMarker + "#"},

		// Class: key contains "#".
		{"key_contains_hash", "ref+env://" + pathMarker + "#" + keyMarker + "#extra"},

		// Class: path validation — leading "/", trailing "/",
		// percent, traversal, empty segment, dot, control byte.
		{"path_leading_slash", "ref+env:///" + pathMarker + "#" + keyMarker},
		{"path_trailing_slash", "ref+env://" + pathMarker + "/#" + keyMarker},
		{"path_percent_encoded", "ref+env://" + pathMarker + "%20x#" + keyMarker},
		{"path_traversal_dotdot", "ref+env://" + pathMarker + "/..#" + keyMarker},
		{"path_dot_segment", "ref+env://" + pathMarker + "/.#" + keyMarker},
		{"path_empty_segment", "ref+env://" + pathMarker + "//x#" + keyMarker},
		{"path_control_byte_null", "ref+env://" + pathMarker + "\x00x#" + keyMarker},
		{"path_control_byte_newline", "ref+env://" + pathMarker + "\nx#" + keyMarker},
		{"path_control_byte_del", "ref+env://" + pathMarker + "\x7fx#" + keyMarker},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := secrets.ParseRef(tc.input)
			require.Error(t, err, "input %q must be rejected as malformed", tc.input)

			msg := err.Error()
			assert.NotContains(t, msg, schemeMarker,
				"error message must not contain the scheme substring: %q", msg)
			assert.NotContains(t, msg, pathMarker,
				"error message must not contain the path substring: %q", msg)
			assert.NotContains(t, msg, keyMarker,
				"error message must not contain the key substring: %q", msg)

			// Defend against a future refactor that swaps the `0x%02x`
			// hex-literal byte formatter in validatePath for a raw
			// `%s` (which would embed the control byte verbatim).
			// Asserting no raw 0x00/0x0a/0x7f byte catches that
			// regression even though the current message is safe.
			assert.NotContains(t, msg, "\x00", "error message must not contain raw NUL byte: %q", msg)
			assert.NotContains(t, msg, "\x0a", "error message must not contain raw LF byte: %q", msg)
			assert.NotContains(t, msg, "\x7f", "error message must not contain raw DEL byte: %q", msg)
		})
	}
}

// ---------------------------------------------------------------------------
// Property-based test
// ---------------------------------------------------------------------------

func TestParseRef_PropertyBased_NotARefNeverErrors(t *testing.T) {
	t.Parallel()

	// Property: any string NOT starting with "ref+" returns (zero, nil).
	f := func(s string) bool {
		if len(s) >= 4 && s[:4] == "ref+" {
			return true // skip — this starts with ref+
		}
		ref, err := secrets.ParseRef(s)
		return err == nil && ref.IsZero()
	}
	require.NoError(t, quick.Check(f, nil))
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestParseRef_ConcurrentCalls_NoDataRace(t *testing.T) {
	t.Parallel()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, _ = secrets.ParseRef("ref+openbao://secret/data/hmac#salt")
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Provider interface — compile-time satisfaction check
// ---------------------------------------------------------------------------

// mockProvider is a test helper that satisfies the Provider interface.
type mockProvider struct {
	scheme string
}

func (m *mockProvider) Scheme() string { return m.scheme }

func (m *mockProvider) Resolve(_ context.Context, _ secrets.Ref) (string, error) {
	return "", nil
}

func (m *mockProvider) Close() error { return nil }

// Compile-time check that mockProvider satisfies Provider.
var _ secrets.Provider = (*mockProvider)(nil)

func TestProvider_MockSatisfiesInterface(t *testing.T) {
	t.Parallel()

	p := &mockProvider{scheme: "mock"}
	assert.Equal(t, "mock", p.Scheme())

	ref := secrets.Ref{Scheme: "mock", Path: "path", Key: "key"}
	val, err := p.Resolve(t.Context(), ref)
	require.NoError(t, err)
	assert.Empty(t, val)

	require.NoError(t, p.Close())
}

// ---------------------------------------------------------------------------
// Ref.Valid()
// ---------------------------------------------------------------------------

func TestRef_Valid(t *testing.T) {
	t.Parallel()

	tests := []struct { //nolint:govet // readability over alignment
		name    string
		ref     secrets.Ref
		wantErr bool
		errHint string
	}{
		{
			name: "valid ref",
			ref:  secrets.Ref{Scheme: "openbao", Path: "secret/data/hmac", Key: "salt"},
		},
		{
			name: "minimal valid",
			ref:  secrets.Ref{Scheme: "x", Path: "p", Key: "k"},
		},
		{
			name:    "empty scheme",
			ref:     secrets.Ref{Scheme: "", Path: "path", Key: "key"},
			wantErr: true, errHint: "empty scheme",
		},
		{
			name:    "invalid scheme",
			ref:     secrets.Ref{Scheme: "UPPER", Path: "path", Key: "key"},
			wantErr: true, errHint: "invalid scheme",
		},
		{
			name:    "empty path",
			ref:     secrets.Ref{Scheme: "openbao", Path: "", Key: "key"},
			wantErr: true, errHint: "empty path",
		},
		{
			name:    "empty key",
			ref:     secrets.Ref{Scheme: "openbao", Path: "path", Key: ""},
			wantErr: true, errHint: "empty key",
		},
		{
			name:    "path traversal",
			ref:     secrets.Ref{Scheme: "openbao", Path: "secret/../etc/passwd", Key: "key"},
			wantErr: true, errHint: "..",
		},
		{
			name:    "zero value",
			ref:     secrets.Ref{},
			wantErr: true, errHint: "empty scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.ref.Valid()
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, secrets.ErrMalformedRef)
				assert.Contains(t, err.Error(), tt.errHint)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Ref.Format — ensures %+v does not leak path
// ---------------------------------------------------------------------------

func TestRef_Format_PlusV_RedactsPath(t *testing.T) {
	t.Parallel()

	ref := secrets.Ref{Scheme: "openbao", Path: "secret/data/prod/hmac", Key: "salt"}

	// %+v normally prints struct field names and values — our Format
	// method ensures it goes through String() instead.
	plusV := fmt.Sprintf("%+v", ref)
	assert.NotContains(t, plusV, "secret/data/prod/hmac")
	assert.Contains(t, plusV, "[REDACTED]")

	// Also test %v and %s via Sprint/Sprintf to exercise Format.
	//nolint:gocritic // intentionally testing fmt.Sprintf routing, not String()
	v := fmt.Sprintf("%v", ref)
	assert.NotContains(t, v, "secret/data/prod/hmac")
	assert.Contains(t, v, "[REDACTED]")

	//nolint:gocritic // intentionally testing fmt.Sprintf routing, not String()
	s := fmt.Sprintf("%s", ref)
	assert.NotContains(t, s, "secret/data/prod/hmac")
	assert.Contains(t, s, "[REDACTED]")
}

// ---------------------------------------------------------------------------
// ContainsRef — tightened to require lowercase alpha after ref+
// ---------------------------------------------------------------------------

func TestContainsRef_RejectsInvalidSchemes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"uppercase scheme", "ref+UPPERCASE://foo", false},
		{"no scheme (just ://)", "ref+://foo", false},
		{"digit-starting scheme", "ref+1bad://foo", false},
		{"valid lowercase scheme", "ref+vault://foo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, secrets.ContainsRef(tt.input))
		})
	}
}
