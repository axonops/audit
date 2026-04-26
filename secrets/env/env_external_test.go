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

package env_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/secrets"
	"github.com/axonops/audit/secrets/env"
)

// TestProvider_Resolve_HappyPath sets an env var and resolves it.
func TestProvider_Resolve_HappyPath(t *testing.T) {
	t.Setenv("AUDIT_TEST_TOKEN", "s3cret-value")
	p := env.New()
	got, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: env.Scheme,
		Path:   "AUDIT_TEST_TOKEN",
	})
	require.NoError(t, err)
	assert.Equal(t, "s3cret-value", got)
}

// TestProvider_Resolve_Unset returns ErrSecretResolveFailed when the
// variable is not set.
func TestProvider_Resolve_Unset(t *testing.T) {
	p := env.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: env.Scheme,
		Path:   "AUDIT_DEFINITELY_UNSET_TEST_VAR",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_EmptyValue treats set-to-empty as unset —
// empty audit secret is never legitimate.
func TestProvider_Resolve_EmptyValue(t *testing.T) {
	t.Setenv("AUDIT_TEST_EMPTY", "")
	p := env.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: env.Scheme,
		Path:   "AUDIT_TEST_EMPTY",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrSecretResolveFailed))
}

// TestProvider_Resolve_FragmentRejected — env:// has no key concept;
// a non-empty fragment must be rejected.
func TestProvider_Resolve_FragmentRejected(t *testing.T) {
	t.Setenv("AUDIT_TEST_TOKEN", "value")
	p := env.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: env.Scheme,
		Path:   "AUDIT_TEST_TOKEN",
		Key:    "subkey",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
}

// TestProvider_Resolve_InvalidName rejects names that don't match
// POSIX `[A-Z_][A-Z0-9_]*`.
func TestProvider_Resolve_InvalidName(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"lowercase", "lowercase"},
		{"leading_digit", "1VAR"},
		{"hyphen", "MY-VAR"},
		{"dot", "MY.VAR"},
		{"space", "MY VAR"},
		{"unicode", "ÉCŒ"},
	}
	p := env.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := p.Resolve(context.Background(), secrets.Ref{
				Scheme: env.Scheme,
				Path:   tc.path,
			})
			require.Error(t, err)
			assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
		})
	}
}

// TestProvider_Resolve_RedactsName — the variable name must NEVER
// appear in the error message; the locked S5/Q5 contract.
func TestProvider_Resolve_RedactsName(t *testing.T) {
	const sentinel = "AUDIT_REDACT_SENTINEL_VAR"
	p := env.New()
	_, err := p.Resolve(context.Background(), secrets.Ref{
		Scheme: env.Scheme,
		Path:   sentinel,
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel,
		"error message MUST NOT contain the variable name (redaction contract)")
}

// TestProvider_Scheme returns "env".
func TestProvider_Scheme(t *testing.T) {
	t.Parallel()
	p := env.New()
	assert.Equal(t, "env", p.Scheme())
	assert.Equal(t, "env", env.Scheme)
}

// TestProvider_Close is a no-op idempotent.
func TestProvider_Close(t *testing.T) {
	t.Parallel()
	p := env.New()
	require.NoError(t, p.Close())
	require.NoError(t, p.Close())
}

// TestProvider_Concurrent — Resolve from many goroutines under
// -race. Provider is stateless; this confirms zero-state-mutation.
func TestProvider_Concurrent(t *testing.T) {
	t.Setenv("AUDIT_TEST_CONCURRENT", "value")
	p := env.New()
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			val, err := p.Resolve(context.Background(), secrets.Ref{
				Scheme: env.Scheme,
				Path:   "AUDIT_TEST_CONCURRENT",
			})
			assert.NoError(t, err)
			assert.Equal(t, "value", val)
		}()
	}
	wg.Wait()
}

// TestProvider_ParseRef_Integration verifies the documented URI
// shape end-to-end via [secrets.ParseRef].
func TestProvider_ParseRef_Integration(t *testing.T) {
	t.Setenv("AUDIT_TEST_PARSEREF", "from-parseref")
	ref, err := secrets.ParseRef("ref+env://AUDIT_TEST_PARSEREF")
	require.NoError(t, err)
	assert.Equal(t, "env", ref.Scheme)
	assert.Equal(t, "AUDIT_TEST_PARSEREF", ref.Path)
	assert.Empty(t, ref.Key)

	p := env.New()
	got, err := p.Resolve(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "from-parseref", got)
}

// TestProvider_ParseRef_RejectsFragment confirms that ParseRef
// itself rejects env:// references with a fragment.
func TestProvider_ParseRef_RejectsFragment(t *testing.T) {
	t.Parallel()
	_, err := secrets.ParseRef("ref+env://VAR#fragment")
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrMalformedRef))
}

// Ensure goimports-friendly use of strings (cheap reference for
// future maintainers who add string-manipulating tests).
var _ = strings.HasPrefix
