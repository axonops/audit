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
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

func TestComputeHMAC_AllAlgorithms(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"test","outcome":"success"}`)
	salt := []byte("this-is-a-test-salt-value-32bytes!")

	for _, algo := range audit.SupportedHMACAlgorithms() {
		t.Run(algo, func(t *testing.T) {
			t.Parallel()
			result, err := audit.ComputeHMAC(payload, salt, algo)
			require.NoError(t, err)
			assert.NotEmpty(t, result)
			// Verify it's hex-encoded (even number of hex chars).
			assert.Regexp(t, `^[0-9a-f]+$`, result)
		})
	}
}

func TestVerifyHMAC_RoundTrip(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"auth_failure","severity":8}`)
	salt := []byte("round-trip-test-salt-16b")

	hmacVal, err := audit.ComputeHMAC(payload, salt, "HMAC-SHA-256")
	require.NoError(t, err)

	ok, err := audit.VerifyHMAC(payload, hmacVal, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyHMAC_TamperedPayload(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"auth_failure","severity":8}`)
	salt := []byte("tamper-test-salt-16bytes")

	hmacVal, err := audit.ComputeHMAC(payload, salt, "HMAC-SHA-256")
	require.NoError(t, err)

	// Tamper with the payload.
	tampered := []byte(`{"event_type":"auth_failure","severity":9}`)
	ok, err := audit.VerifyHMAC(tampered, hmacVal, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, ok, "tampered payload should fail verification")
}

func TestVerifyHMAC_WrongSalt(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"test"}`)
	salt1 := []byte("correct-salt-value-16b")
	salt2 := []byte("wrong-salt-value-16bbb")

	hmacVal, err := audit.ComputeHMAC(payload, salt1, "HMAC-SHA-256")
	require.NoError(t, err)

	ok, err := audit.VerifyHMAC(payload, hmacVal, salt2, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, ok, "wrong salt should fail verification")
}

func TestComputeHMAC_EmptyPayload(t *testing.T) {
	t.Parallel()
	_, err := audit.ComputeHMAC(nil, []byte("salt-value-16bytes"), "HMAC-SHA-256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payload")
}

func TestComputeHMAC_EmptySalt(t *testing.T) {
	t.Parallel()
	_, err := audit.ComputeHMAC([]byte("payload"), nil, "HMAC-SHA-256")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "salt")
}

func TestComputeHMAC_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	_, err := audit.ComputeHMAC([]byte("payload"), []byte("salt-value-16bytes"), "MD5")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestValidateHMACConfig_Valid(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte("sixteen-byte-key"),
		Algorithm:   "HMAC-SHA-256",
	}
	assert.NoError(t, audit.ValidateHMACConfig(cfg))
}

func TestValidateHMACConfig_Disabled(t *testing.T) {
	t.Parallel()
	assert.NoError(t, audit.ValidateHMACConfig(nil))
	assert.NoError(t, audit.ValidateHMACConfig(&audit.HMACConfig{Enabled: false}))
}

func TestValidateHMACConfig_SaltTooShort(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte("short"),
		Algorithm:   "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "at least")
}

func TestValidateHMACConfig_MissingSalt(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		Algorithm:   "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "salt value")
}

func TestValidateHMACConfig_MissingVersion(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:   true,
		SaltValue: []byte("sixteen-byte-key"),
		Algorithm: "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "version")
}

func TestValidateHMACConfig_MissingAlgorithm(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte("sixteen-byte-key"),
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestValidateHMACConfig_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte("sixteen-byte-key"),
		Algorithm:   "SHA-1",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "unknown")
}

func TestHMAC_PropertyBased_RoundTrip(t *testing.T) {
	t.Parallel()
	f := func(payload []byte, salt []byte) bool {
		if len(payload) == 0 || len(salt) == 0 {
			return true // skip empty inputs
		}
		hmacVal, err := audit.ComputeHMAC(payload, salt, "HMAC-SHA-256")
		if err != nil {
			return false
		}
		ok, err := audit.VerifyHMAC(payload, hmacVal, salt, "HMAC-SHA-256")
		return err == nil && ok
	}
	require.NoError(t, quick.Check(f, nil))
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkHMAC_SHA256_SmallEvent(b *testing.B) {
	payload := []byte(`{"timestamp":"2026-01-01T00:00:00Z","event_type":"auth_failure","severity":8,"outcome":"failure","actor_id":"alice"}`)
	salt := []byte("benchmark-salt-value-32-bytes!!!")
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = audit.ComputeHMAC(payload, salt, "HMAC-SHA-256")
	}
}

func BenchmarkHMAC_SHA256_LargeEvent(b *testing.B) {
	// ~2KB payload.
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = 'a' + byte(i%26)
	}
	salt := []byte("benchmark-salt-value-32-bytes!!!")
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = audit.ComputeHMAC(payload, salt, "HMAC-SHA-256")
	}
}

func TestHMACConfig_String_HidesSalt(t *testing.T) {
	t.Parallel()
	cfg := audit.HMACConfig{
		Enabled:     true,
		SaltVersion: "v1",
		SaltValue:   []byte("super-secret-salt-value"),
		Algorithm:   "HMAC-SHA-256",
	}
	s := cfg.String()
	assert.NotContains(t, s, "super-secret-salt-value")
	assert.Contains(t, s, "v1")
	assert.Contains(t, s, "HMAC-SHA-256")

	gs := cfg.GoString()
	assert.NotContains(t, gs, "super-secret-salt-value")

	// Verify fmt verbs route through String/GoString (no salt leakage).
	//nolint:gocritic // intentionally testing fmt.Sprint routing
	fmtResult := fmt.Sprint(cfg)
	assert.NotContains(t, fmtResult, "super-secret-salt-value")
}

func TestHMACConfig_String_Disabled(t *testing.T) {
	t.Parallel()
	cfg := audit.HMACConfig{Enabled: false}
	assert.Equal(t, "HMACConfig{Enabled: false}", cfg.String())
}

func TestVerifyHMAC_ErrorPath(t *testing.T) {
	t.Parallel()
	ok, err := audit.VerifyHMAC(nil, "anyvalue", []byte("valid-salt-16bytes!!"), "HMAC-SHA-256")
	require.Error(t, err)
	assert.False(t, ok)
}

func BenchmarkHMAC_SHA512_SmallEvent(b *testing.B) {
	payload := []byte(`{"timestamp":"2026-01-01T00:00:00Z","event_type":"auth_failure","severity":8,"outcome":"failure","actor_id":"alice"}`)
	salt := []byte("benchmark-salt-value-32-bytes!!!")
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = audit.ComputeHMAC(payload, salt, "HMAC-SHA-512")
	}
}
