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

package outputconfig_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/go-audit/outputconfig"
	"github.com/axonops/go-audit/secrets"
)

// ---------------------------------------------------------------------------
// Mock secret provider
// ---------------------------------------------------------------------------

type mockSecretProvider struct { //nolint:govet // readability over alignment
	scheme     string
	data       map[string]map[string]string // path → {key → value}
	err        error                        // error to return from Resolve
	calls      atomic.Int64
	delay      time.Duration // delay before resolving (for timeout tests)
	closeCalls atomic.Int64
}

func (m *mockSecretProvider) Scheme() string { return m.scheme }

func (m *mockSecretProvider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(m.delay):
		}
	}
	if m.err != nil {
		return "", m.err
	}
	keys, ok := m.data[ref.Path]
	if !ok {
		return "", fmt.Errorf("%w: path %q", secrets.ErrSecretNotFound, ref.Path)
	}
	val, ok := keys[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: key %q at path %q", secrets.ErrSecretNotFound, ref.Key, ref.Path)
	}
	return val, nil
}

func (m *mockSecretProvider) Close() error {
	m.closeCalls.Add(1)
	return nil
}

func (m *mockSecretProvider) String() string {
	return fmt.Sprintf("mock{scheme: %s, [REDACTED]}", m.scheme)
}

// newMockProvider creates a mock with pre-loaded secrets.
func newMockProvider(scheme string, data map[string]map[string]string) *mockSecretProvider {
	return &mockSecretProvider{scheme: scheme, data: data}
}

// Compile-time check.
var _ secrets.Provider = (*mockSecretProvider)(nil)

// ---------------------------------------------------------------------------
// Helper: minimal YAML with a ref+ in a type-config field
// ---------------------------------------------------------------------------

func yamlWithHMACRefs(saltRef, versionRef, hashRef, enabledValue string) []byte {
	return []byte(fmt.Sprintf(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: %s
      salt:
        version: %s
        value: %s
      hash: %s
`, enabledValue, versionRef, saltRef, hashRef))
}

// ---------------------------------------------------------------------------
// TestLoad_WithSecretProvider — integration tests
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_AllHMACFieldsResolved(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":      "my-secret-salt-value-32bytes!!!!",
			"version":   "v1",
			"algorithm": "HMAC-SHA-256",
			"enabled":   "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"ref+mock://secret/data/hmac#version",
		"ref+mock://secret/data/hmac#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	hmac := result.Outputs[0].HMACConfig
	require.NotNil(t, hmac)
	assert.True(t, hmac.Enabled)
	assert.Equal(t, "v1", hmac.SaltVersion)
	assert.Equal(t, []byte("my-secret-salt-value-32bytes!!!!"), hmac.SaltValue)
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_EnvVarProducesRef(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt": "env-var-resolved-salt-32bytes!!!",
		},
	})
	t.Setenv("TEST_HMAC_SALT_REF", "ref+mock://secret/data/hmac#salt")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ${TEST_HMAC_SALT_REF}
      hash: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	hmac := result.Outputs[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, []byte("env-var-resolved-salt-32bytes!!!"), hmac.SaltValue)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_HMACDisabledSkipsRefs(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"enabled": "false"},
	})
	// Salt/version/hash use ref+ URIs but enabled resolves to false,
	// so those refs must NOT be resolved.
	data := yamlWithHMACRefs(
		"ref+mock://nonexistent/path#salt",
		"ref+mock://nonexistent/path#version",
		"ref+mock://nonexistent/path#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Nil(t, result.Outputs[0].HMACConfig)
	// Provider should only have been called once (for the enabled field).
	assert.Equal(t, int64(1), mock.calls.Load())
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_HMACDisabledLiteral_SkipsRefs(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// No mock needed — enabled is a literal false, remaining refs are
	// never resolved and should not cause errors.
	data := yamlWithHMACRefs(
		"ref+nonexistent://path#salt",
		"ref+nonexistent://path#version",
		"ref+nonexistent://path#hash",
		"false",
	)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
	)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Nil(t, result.Outputs[0].HMACConfig)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_NoProviderNoRefsUnchanged(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, &tax, nil)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_NoProviderWithRefsErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    stdout:
      format: ref+openbao://secret/data/config#format
`)
	_, err := outputconfig.Load(context.Background(), data, &tax, nil)
	require.Error(t, err)
	// No provider registered → resolver is nil → refs pass through
	// env+secret expansion unchanged → safety net catches them.
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

func TestLoad_WithSecretProvider_DuplicateSchemeErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock1 := newMockProvider("mock", nil)
	mock2 := newMockProvider("mock", nil)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock1),
		outputconfig.WithSecretProvider(mock2),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestLoad_WithSecretProvider_ContextTimeout(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := &mockSecretProvider{
		scheme: "mock",
		data:   map[string]map[string]string{"path": {"key": "value"}},
		delay:  5 * time.Second, // will timeout
	}
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://path#key
      hash: HMAC-SHA-256
`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := outputconfig.Load(
		ctx, data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
		outputconfig.WithSecretTimeout(50*time.Millisecond),
	)
	require.Error(t, err)
}

func TestLoad_WithSecretProvider_ErrorNeverContainsSecretValue(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	secretValue := "SUPER-SECRET-VALUE-MUST-NOT-LEAK"
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": secretValue, "enabled": "true"},
	})
	// Hash ref will fail — check that the error message from that
	// failure does not contain the already-resolved salt value.
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"ref+mock://nonexistent/path#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secretValue)
}

func TestLoad_WithSecretProvider_PathLevelCaching(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":      "cached-salt-value-32-bytes!!!!!!",
			"version":   "v1",
			"algorithm": "HMAC-SHA-256",
			"enabled":   "true",
		},
	})
	// All 4 HMAC fields from the same path — should be 4 provider calls
	// (one per unique ref, since each has a different key).
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"ref+mock://secret/data/hmac#version",
		"ref+mock://secret/data/hmac#algorithm",
		"ref+mock://secret/data/hmac#enabled",
	)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	// Each unique key requires a separate provider call since each
	// ref has a different fragment. But same-key refs are cached.
	assert.Equal(t, int64(4), mock.calls.Load())
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
	_ = result
}

func TestLoad_WithSecretProvider_MixedLiteralEnvRef(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": "ref-resolved-salt-value-32bytes!"},
	})
	t.Setenv("TEST_HMAC_VERSION", "v2")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: ${TEST_HMAC_VERSION}
        value: ref+mock://secret/data/hmac#salt
      hash: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	hmac := result.Outputs[0].HMACConfig
	require.NotNil(t, hmac)
	assert.Equal(t, "v2", hmac.SaltVersion)                                     // from env var
	assert.Equal(t, []byte("ref-resolved-salt-value-32bytes!"), hmac.SaltValue) // from ref
	assert.Equal(t, "HMAC-SHA-256", hmac.Algorithm)                             // literal
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithSecretProvider_UnregisteredSchemeErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+vault://secret/data/hmac#salt
      hash: HMAC-SHA-256
`)
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock), // mock scheme, not vault
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrProviderNotRegistered)
}

func TestLoad_WithSecretProvider_EmptyResolvedValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":    "",
			"enabled": "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoad_WithSecretProvider_OversizedValueRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	bigValue := strings.Repeat("x", outputconfig.MaxSecretValueSize+1)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt":    bigValue,
			"enabled": "true",
		},
	})
	data := yamlWithHMACRefs(
		"ref+mock://secret/data/hmac#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretResolveFailed)
	assert.NotContains(t, err.Error(), bigValue)
}

func TestLoad_WithSecretProvider_HMACEnabledTrue_RequiresAllFields(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"enabled": "true"},
		// salt path doesn't exist — will fail.
	})
	data := yamlWithHMACRefs(
		"ref+mock://nonexistent/path#salt",
		"v1",
		"HMAC-SHA-256",
		"ref+mock://secret/data/hmac#enabled",
	)
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrSecretNotFound)
}

// ---------------------------------------------------------------------------
// Ref in non-HMAC field (ensures tree walk covers all fields)
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_RefInNonHMACFieldResolves(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Stdout type config doesn't have string fields to resolve,
	// but we can verify the pipeline doesn't error with refs in
	// fields that are processed by the tree walker.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {"app": "my-resolved-app"},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#app
host: test
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, "my-resolved-app", result.AppName)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Backward compatibility: unused env vars with no refs
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_EnvVarProducesLiteral_NoProviderCall(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", nil)
	t.Setenv("TEST_HMAC_SALT_LITERAL", "literal-salt-value-32-bytes!!!!!")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ${TEST_HMAC_SALT_LITERAL}
      hash: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, int64(0), mock.calls.Load())
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.Equal(t, []byte("literal-salt-value-32-bytes!!!!!"), result.Outputs[0].HMACConfig.SaltValue)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Single-pass guarantee
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_SinglePassGuarantee(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Provider returns a value that itself contains ref+.
	// It must NOT be re-resolved.
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {
			"salt": "ref+mock://other/path#key",
		},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      hash: HMAC-SHA-256
`)
	// The resolved value contains "ref+mock://..." which the safety
	// net should flag as an unresolved reference.
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
	// Provider should only have been called once — no re-scan.
	assert.Equal(t, int64(1), mock.calls.Load())
}

// ---------------------------------------------------------------------------
// LoadResult.String() does not contain secrets
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_LoadResultStringNeverContainsSecrets(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	secretSalt := "super-secret-salt-32-bytes!!!!!!"
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": secretSalt},
	})
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      hash: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	s := result.String()
	assert.NotContains(t, s, secretSalt)
	s2 := fmt.Sprintf("%+v", result)
	assert.NotContains(t, s2, secretSalt)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// env var pointing to disabled HMAC
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_HMACEnabledEnvRef_RefSalt(t *testing.T) {
	tax := testTaxonomy(t)
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/hmac": {"salt": "env-enabled-ref-salt-32-bytes!!!"},
	})
	t.Setenv("TEST_HMAC_ENABLED", "true")
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: ${TEST_HMAC_ENABLED}
      salt:
        version: v1
        value: ref+mock://secret/data/hmac#salt
      hash: HMAC-SHA-256
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.Equal(t, []byte("env-enabled-ref-salt-32-bytes!!!"), result.Outputs[0].HMACConfig.SaltValue)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Cache hit: same ref in two different fields → one provider call
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_CacheHit_SameRefTwoFields(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	// Both app_name and host resolve from the same ref — provider
	// should be called only once (cache hit on second call).
	mock := newMockProvider("mock", map[string]map[string]string{
		"secret/data/config": {"name": "my-app"},
	})
	data := []byte(`
version: 1
app_name: ref+mock://secret/data/config#name
host: ref+mock://secret/data/config#name
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, "my-app", result.AppName)
	assert.Equal(t, "my-app", result.Host)
	// Same scheme+path+key → one provider call, not two.
	assert.Equal(t, int64(1), mock.calls.Load())
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// Nil provider guard
// ---------------------------------------------------------------------------

func TestLoad_WithSecretProvider_NilProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(
		context.Background(), data, &tax, nil,
		outputconfig.WithSecretProvider(nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// ---------------------------------------------------------------------------
// Unresolved ref in top-level field (no provider registered)
// ---------------------------------------------------------------------------

func TestLoad_UnresolvedRefInAppName_NoProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: ref+openbao://secret/data/config#app
host: test
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

func TestLoad_UnresolvedRefInHost_NoProviderErrors(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: ref+vault://secret/data/config#host
outputs:
  c:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, secrets.ErrUnresolvedRef)
}

// ---------------------------------------------------------------------------
// HMAC enabled ref with no provider
// ---------------------------------------------------------------------------

func TestLoad_HMACEnabledRef_NoProvider_ClearError(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: ref+openbao://secret/data/hmac#enabled
      salt:
        version: v1
        value: my-salt-value-32-bytes!!!!!!!!
      hash: HMAC-SHA-256
`)
	_, err := outputconfig.Load(context.Background(), data, &tax, nil)
	require.Error(t, err)
	// Should get a clear error about no provider, not a toBool error
	// leaking the ref URI.
	assert.Contains(t, err.Error(), "no provider")
}
