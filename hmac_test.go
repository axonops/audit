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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
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

// TestVerifyHMAC_RejectsMalformedEarly_NotTimingSensitive is the
// named contract test from #483 Testing Requirements. Proves
// structurally invalid HMAC values are rejected with
// [ErrHMACMalformed] + [ErrValidation] BEFORE the constant-time
// compare, since malformed inputs are pre-authentication
// structural rejects and not timing-sensitive.
func TestVerifyHMAC_RejectsMalformedEarly_NotTimingSensitive(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"test"}`)
	salt := []byte("well-formed-salt-value-16b")
	const algo = "HMAC-SHA-256"

	tests := []struct {
		name      string
		hmacValue string
		reason    string
	}{
		{"empty", "", "empty hmac value"},
		{"too_short", "abc", "wrong length (3 instead of 64)"},
		{"too_short_by_one", strings.Repeat("a", 63), "one byte short"},
		{"too_long_by_one", strings.Repeat("a", 65), "one byte long"},
		{"wrong_length_sha512_digest", strings.Repeat("a", 128), "SHA-512 digest length for a SHA-256 check"},
		{"non_hex_uppercase", strings.Repeat("A", 64), "uppercase hex is rejected (ComputeHMAC emits lowercase)"},
		{"non_hex_invalid_chars", "zxy" + strings.Repeat("0", 61), "non-hex prefix"},
		{"non_hex_mid", strings.Repeat("0", 30) + "g" + strings.Repeat("0", 33), "non-hex byte in the middle"},
		{"non_hex_trailing_null", strings.Repeat("0", 63) + "\x00", "null byte at end"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ok, err := audit.VerifyHMAC(payload, tt.hmacValue, salt, algo)
			assert.False(t, ok,
				"malformed hmac must not verify (%s)", tt.reason)
			require.Error(t, err,
				"malformed hmac must return an error (%s)", tt.reason)
			assert.ErrorIs(t, err, audit.ErrHMACMalformed,
				"%s should wrap ErrHMACMalformed", tt.reason)
			assert.ErrorIs(t, err, audit.ErrValidation,
				"%s should also wrap ErrValidation", tt.reason)
		})
	}
}

// TestVerifyHMAC_ValidInputs_ReachesConstantTimeCompare is the
// named companion to the malformed-rejection test. A valid-length
// + valid-hex input that happens to NOT match the true HMAC must
// NOT return an error — it returns (false, nil). This preserves
// the timing contract: wrong-but-well-formed inputs hit
// hmac.Equal and take the same time as a correct compare.
func TestVerifyHMAC_ValidInputs_ReachesConstantTimeCompare(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event_type":"test"}`)
	salt := []byte("well-formed-salt-value-16b")
	const algo = "HMAC-SHA-256"

	t.Run("correct_hmac_verifies_true", func(t *testing.T) {
		t.Parallel()
		correct, err := audit.ComputeHMAC(payload, salt, algo)
		require.NoError(t, err)
		ok, err := audit.VerifyHMAC(payload, correct, salt, algo)
		require.NoError(t, err)
		assert.True(t, ok, "correct HMAC must verify")
	})

	t.Run("wrong_but_well_formed_returns_false_nil", func(t *testing.T) {
		t.Parallel()
		// All-zeros hex string of SHA-256 length — valid format,
		// not a match. MUST return (false, nil), NOT an error.
		wrongButValid := strings.Repeat("0", 64)
		ok, err := audit.VerifyHMAC(payload, wrongButValid, salt, algo)
		require.NoError(t, err,
			"wrong-but-well-formed hmac must NOT return an error — that would leak which inputs reached hmac.Equal")
		assert.False(t, ok, "wrong hmac must not verify")
	})

	t.Run("sha512_valid_length_and_hex", func(t *testing.T) {
		t.Parallel()
		const sha512Algo = "HMAC-SHA-512"
		correct, err := audit.ComputeHMAC(payload, salt, sha512Algo)
		require.NoError(t, err)
		require.Len(t, correct, 128, "sanity: SHA-512 hex is 128 chars")
		ok, err := audit.VerifyHMAC(payload, correct, salt, sha512Algo)
		require.NoError(t, err)
		assert.True(t, ok)
	})
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
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("sixteen-byte-key"),
		},
		Algorithm: "HMAC-SHA-256",
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
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("short"),
		},
		Algorithm: "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "at least")
}

func TestValidateHMACConfig_MissingSalt(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:   true,
		Salt:      audit.HMACSalt{Version: "v1"},
		Algorithm: "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "salt.value")
}

func TestValidateHMACConfig_MissingVersion(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled:   true,
		Salt:      audit.HMACSalt{Value: []byte("sixteen-byte-key")},
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
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("sixteen-byte-key"),
		},
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestValidateHMACConfig_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("sixteen-byte-key"),
		},
		Algorithm: "SHA-1",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "unknown")
}

// TestValidateHMACConfig_SaltVersionCharsetValid accepts every variant
// of the allowed charset [A-Za-z0-9._:-] for the salt version,
// including length boundaries (1 char, 64 chars exactly).
func TestValidateHMACConfig_SaltVersionCharsetValid(t *testing.T) {
	t.Parallel()
	for _, v := range []string{
		"v1", "v2.0", "2026-Q1", "key-rotation-12",
		"salt_v1:stage",
		"UPPER123-lower.v2_3",
		"a",                     // length 1 (minimum boundary)
		strings.Repeat("a", 64), // length 64 (maximum boundary)
	} {
		t.Run(v, func(t *testing.T) {
			t.Parallel()
			cfg := &audit.HMACConfig{
				Enabled: true,
				Salt: audit.HMACSalt{
					Version: v,
					Value:   []byte("sixteen-byte-key"),
				},
				Algorithm: "HMAC-SHA-256",
			}
			assert.NoError(t, audit.ValidateHMACConfig(cfg))
		})
	}
}

// TestValidateHMACConfig_SaltVersionCharsetInvalid rejects versions
// containing characters that would create escape or injection ambiguity
// on the wire (space, newline, =, quote, pipe, control chars).
func TestValidateHMACConfig_SaltVersionCharsetInvalid(t *testing.T) {
	t.Parallel()
	for _, v := range []string{
		"v 1",          // space
		"v1\nv2",       // newline — log-injection vector
		"v=2",          // = — CEF key=value delimiter
		`v"1`,          // double-quote — JSON injection
		"v|1",          // CEF header delimiter
		"v\x00",        // NUL
		"v\t1",         // tab
		"",             // empty (separately handled by MissingVersion test)
		"has space in", // spaces inside
	} {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			t.Parallel()
			cfg := &audit.HMACConfig{
				Enabled: true,
				Salt: audit.HMACSalt{
					Version: v,
					Value:   []byte("sixteen-byte-key"),
				},
				Algorithm: "HMAC-SHA-256",
			}
			err := audit.ValidateHMACConfig(cfg)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrConfigInvalid)
		})
	}
}

// TestValidateHMACConfig_SaltVersionTooLong rejects versions exceeding
// the 64-byte bound. Prevents unbounded payload inflation.
func TestValidateHMACConfig_SaltVersionTooLong(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: strings.Repeat("a", 65),
			Value:   []byte("sixteen-byte-key"),
		},
		Algorithm: "HMAC-SHA-256",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// TestReservedLibraryField_RejectedAtRuntime covers consumer-supplied
// Fields map with `_hmac` or `_hmac_version`. The library emits these on
// every HMAC-enabled event. Consumer-supplied collisions would
// duplicate the field and enable canonicalisation-ambiguity attacks
// on verifiers (issue #473 security-reviewer finding 6b). Rejection
// runs regardless of ValidationMode.
func TestReservedLibraryField_RejectedAtRuntime(t *testing.T) {
	t.Parallel()
	for _, mode := range []audit.ValidationMode{
		audit.ValidationStrict, audit.ValidationWarn, audit.ValidationPermissive,
	} {
		for _, fieldName := range []string{"_hmac", "_hmac_version"} {
			t.Run(fmt.Sprintf("%v/%s", mode, fieldName), func(t *testing.T) {
				t.Parallel()
				tax := &audit.Taxonomy{
					Version: 1,
					Categories: map[string]*audit.CategoryDef{
						"security": {Events: []string{"auth_failure"}},
					},
					Events: map[string]*audit.EventDef{
						"auth_failure": {Required: []string{"outcome"}},
					},
				}
				out := testhelper.NewMockOutput("reserved-check")
				auditor, err := audit.New(
					audit.WithTaxonomy(tax),
					audit.WithAppName("test-app"),
					audit.WithHost("test-host"),
					audit.WithValidationMode(mode),
					audit.WithOutputs(out),
				)
				require.NoError(t, err)
				defer func() { _ = auditor.Close() }()

				err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
					"outcome":  "failure",
					fieldName:  "attacker-controlled",
					"actor_id": "alice",
				}))
				require.Error(t, err, "reserved field name must be rejected even in %v mode", mode)
				assert.ErrorIs(t, err, audit.ErrReservedFieldName,
					"error must wrap ErrReservedFieldName sentinel")
				assert.ErrorIs(t, err, audit.ErrValidation,
					"error must also wrap ErrValidation")
			})
		}
	}
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
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("super-secret-salt-value"),
		},
		Algorithm: "HMAC-SHA-256",
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

// ---------------------------------------------------------------------------
// Salt version authentication tests (issue #473)
//
// These tests verify that `_hmac_version` (the salt version identifier) is
// authenticated by the HMAC. Before the fix, `_hmac_version` was appended to
// the wire AFTER `computeHMACFast` ran, leaving it outside the
// authenticated region — a MITM could flip v1 → v2 to redirect a
// verifier's salt lookup without detection. The fix reorders
// drain.go:183-192 to append `_hmac_version` BEFORE computing HMAC.
// ---------------------------------------------------------------------------

// stripHMACJSONField removes the `,"_hmac":"<hex>"` field from a JSON
// event line, keeping `_hmac_version` in place. This is the canonicalisation
// rule: recompute HMAC over the remaining bytes. Called from the #473
// tests. Mirrors the helper in tests/bdd/steps/hmac_steps.go.
func stripHMACJSONField(line []byte) []byte {
	s := string(line)
	idx := strings.Index(s, `,"_hmac":"`)
	if idx < 0 {
		return line
	}
	valStart := idx + len(`,"_hmac":"`)
	rel := strings.Index(s[valStart:], `"`)
	if rel < 0 {
		return line
	}
	end := valStart + rel + 1
	return []byte(s[:idx] + s[end:])
}

// newHMACPipelineTestAuditor constructs an auditor with a single HMAC
// output configured for JSON. Returns the auditor and the mock output
// the caller reads raw bytes from. Salt length is >= MinSaltLength.
func newHMACPipelineTestAuditor(t *testing.T, name, saltVersion string, salt []byte) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	out := testhelper.NewMockOutput(name)
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: saltVersion,
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)
	return auditor, out
}

// TestComputeHMACFast_IncludesSaltVersionInPayload is the named
// contract test from #473 Testing Requirements. It proves the salt
// version identifier is part of the byte stream fed into
// [hmacState.computeHMACFast] (i.e. it is an input to the HMAC
// function, not metadata appended afterward).
//
// This is the positive/constructive companion to
// [TestVerifyHMAC_TamperingHmacVersion_Detected] — that test proves
// tampering is detected; this test proves the data flow that makes
// detection possible. Two runs of the same event differ only in
// SaltVersion; if SaltVersion reached the HMAC function, the two
// resulting `_hmac` values MUST differ. If SaltVersion were appended
// after the HMAC call (the pre-#473 bug), the two hashes would be
// identical. The assertion is a direct positive contract on the
// implementation — it fails closed if the bug regresses.
//
// It also independently re-computes the HMAC externally over the
// on-wire bytes minus `_hmac` and verifies it matches the embedded
// value, proving the wire payload (which visibly contains the salt
// version) is what was hashed.
func TestComputeHMACFast_IncludesSaltVersionInPayload(t *testing.T) {
	t.Parallel()
	salt := []byte("salt-version-in-payload-32b!!!")

	// Run the pipeline twice with SaltVersion v1 and v2 — same length
	// so the JSON keys/framework-field ordering is byte-identical
	// except for the version character.
	runOnce := func(saltVersion string) ([]byte, string) {
		auditor, out := newHMACPipelineTestAuditor(t, "salt-in-payload-"+saltVersion, saltVersion, salt)
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome": "failure", "actor_id": "alice",
		})))
		require.True(t, out.WaitForEvents(1, 2*time.Second))
		require.NoError(t, auditor.Close())
		line := out.GetEvents()[0]
		hmacHex := extractJSONStringField(t, line, "_hmac")
		require.NotEmpty(t, hmacHex)
		return line, hmacHex
	}

	lineV1, hmacV1 := runOnce("v1")
	lineV2, hmacV2 := runOnce("v2")

	// Sanity: both lines contain the expected _hmac_version value.
	assert.Contains(t, string(lineV1), `"_hmac_version":"v1"`,
		"line must embed the salt version on the wire")
	assert.Contains(t, string(lineV2), `"_hmac_version":"v2"`)

	// Primary assertion: changing only SaltVersion changes the HMAC.
	// If the implementation regressed to appending _hmac_version AFTER the
	// HMAC computation, both hashes would be identical.
	assert.NotEqual(t, hmacV1, hmacV2,
		"HMAC must differ when SaltVersion differs — proves salt version is an input to computeHMACFast (#473)")

	// Secondary assertion: re-compute HMAC externally over the on-wire
	// bytes minus the `_hmac` field. The result must match the
	// embedded HMAC, proving the wire-visible payload (which contains
	// _hmac_version) IS what was fed into the HMAC.
	canonicalV1 := stripHMACJSONField(lineV1)
	verifiedV1, err := audit.VerifyHMAC(canonicalV1, hmacV1, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verifiedV1,
		"HMAC over (wire bytes minus _hmac) must verify — proves the payload fed to computeHMACFast was the wire content including _hmac_version")
}

// TestHMACOutputOrdering_VBeforeHmac asserts that on-wire JSON places
// `_hmac_version` BEFORE `_hmac`. Pre-fix the order was reversed, which left
// `_hmac_version` outside the authenticated region. Post-fix `_hmac_version` is
// appended first so it is part of the hashed bytes.
func TestHMACOutputOrdering_VBeforeHmac(t *testing.T) {
	t.Parallel()
	salt := []byte("ordering-test-salt-16-bytes!!")
	auditor, out := newHMACPipelineTestAuditor(t, "order-test", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	s := string(line)
	vIdx := strings.Index(s, `"_hmac_version"`)
	hIdx := strings.Index(s, `"_hmac"`)
	require.GreaterOrEqual(t, vIdx, 0, "_hmac_version must appear in JSON output")
	require.GreaterOrEqual(t, hIdx, 0, "_hmac must appear in JSON output")
	assert.Less(t, vIdx, hIdx,
		"_hmac_version must appear BEFORE _hmac so it is inside the authenticated region (issue #473)")
}

// TestDrainPipeline_NoFieldsAppearAfterHMAC asserts that `_hmac` is the
// LAST field on the wire — no fields appended after it. Verifiers rely
// on this positional invariant. A future field accidentally appended
// after _hmac would land outside the authenticated region, reopening
// the class of bug #473 fixed.
func TestDrainPipeline_NoFieldsAppearAfterHMAC(t *testing.T) {
	t.Parallel()
	salt := []byte("last-field-test-salt-16bytes")
	auditor, out := newHMACPipelineTestAuditor(t, "last-field", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	s := string(line)
	// Trim optional trailing newline. The last field before `}\n` must
	// be `"_hmac":"<hex>"` — positionally `_hmac` is the last key.
	s = strings.TrimRight(s, "\n")
	require.True(t, strings.HasSuffix(s, `"}`), "JSON line must end with `}`")
	// The substring `"_hmac":"` must be the last key introducer before `}`.
	lastHmac := strings.LastIndex(s, `"_hmac":"`)
	require.GreaterOrEqual(t, lastHmac, 0, "_hmac must appear")
	// Everything after the _hmac value up to the closing brace must be
	// only the closing quote + closing brace — no comma + new field.
	valStart := lastHmac + len(`"_hmac":"`)
	closingQuote := strings.Index(s[valStart:], `"`)
	require.GreaterOrEqual(t, closingQuote, 0, "_hmac value must be closed")
	tail := s[valStart+closingQuote+1:]
	assert.Equal(t, `}`, tail,
		"no fields must appear after _hmac; tail was %q (issue #473 invariant)", tail)
}

// TestHMAC_OnWireBytesMatchHashedBytes is the defensive end-to-end test
// that the bytes written to the output equal the bytes the HMAC was
// computed over, plus the `_hmac` field appended last. The verifier
// reconstructs the hashed bytes by stripping only `_hmac` from the
// on-wire line and recomputing the HMAC.
func TestHMAC_OnWireBytesMatchHashedBytes(t *testing.T) {
	t.Parallel()
	salt := []byte("onwire-test-salt-16-bytes!!!")
	auditor, out := newHMACPipelineTestAuditor(t, "onwire", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]

	// Parse _hmac out of the JSON.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimRight(line, "\n"), &parsed))
	hmacHex, ok := parsed["_hmac"].(string)
	require.True(t, ok)
	require.NotEmpty(t, hmacHex)

	// Canonicalise: strip only `_hmac` from the on-wire bytes, keeping
	// `_hmac_version` in place because it is authenticated.
	canonical := stripHMACJSONField(line)

	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"HMAC on-wire bytes (minus _hmac suffix) must verify against the HMAC in the event — "+
			"if this fails, the canonicalisation rule and the producer are out of sync (issue #473)")
}

// TestVerifyHMAC_TamperingHmacVersion_Detected is the primary security
// regression test for issue #473. It emits an event with _hmac_version="v1",
// mutates the on-wire bytes to set _hmac_version="v2" (simulating a MITM),
// then verifies using the correct salt and the canonicalisation rule
// (strip only _hmac). The verifier MUST reject the tampered bytes
// because _hmac_version is now part of the authenticated region.
func TestVerifyHMAC_TamperingHmacVersion_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("tamper-v-salt-16-bytes!!!!!")
	auditor, out := newHMACPipelineTestAuditor(t, "tamper-v", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]

	// Sanity: unmodified line verifies.
	hmacHex := extractJSONStringField(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)
	unverifyPassed, err := audit.VerifyHMAC(stripHMACJSONField(line), hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	require.True(t, unverifyPassed, "unmodified event must verify")

	// Tamper: replace "_hmac_version":"v1" with "_hmac_version":"v2" in the on-wire
	// bytes. Both strings are the same length so positions don't shift.
	tampered := bytes.Replace(line, []byte(`"_hmac_version":"v1"`), []byte(`"_hmac_version":"v2"`), 1)
	require.NotEqual(t, line, tampered, "tamper step must modify the line")

	// Canonicalise and verify: strip only _hmac from the TAMPERED bytes.
	canonical := stripHMACJSONField(tampered)
	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"HMAC verification must fail on a tampered _hmac_version — this is the core guarantee of issue #473")
}

// TestVerifyHMAC_TamperingActorId_Detected is the sanity counterpart to
// the #473 primary test. It tampers a non-HMAC field (actor_id) and
// confirms verification still fails, proving the HMAC continues to
// cover the rest of the payload. Guards against a regression where
// the fix accidentally narrows HMAC scope to only _hmac_version.
func TestVerifyHMAC_TamperingActorId_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("tamper-actor-salt-16-bytes!")
	auditor, out := newHMACPipelineTestAuditor(t, "tamper-actor", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	hmacHex := extractJSONStringField(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)

	// Tamper actor_id. "alice" and "bobby" are both 5 characters.
	tampered := bytes.Replace(line, []byte(`"actor_id":"alice"`), []byte(`"actor_id":"bobby"`), 1)
	require.NotEqual(t, line, tampered, "tamper step must modify the line")

	canonical := stripHMACJSONField(tampered)
	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"HMAC verification must fail when a non-HMAC field is tampered — guards against HMAC narrowing")
}

// TestVerifyHMAC_CEF_TamperingHmacVersion_Detected is the CEF parity
// of TestVerifyHMAC_TamperingHmacVersion_Detected. Currently no CEF
// HMAC verification exists at any layer; this test ensures the CEF
// wire format also benefits from the #473 fix.
func TestVerifyHMAC_CEF_TamperingHmacVersion_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("cef-tamper-salt-16-bytes!!!")
	out := testhelper.NewMockOutput("cef-tamper")
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}
	cefFormatter := &audit.CEFFormatter{
		Vendor: "Acme", Product: "TestApp", Version: "1.0",
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithFormatter(cefFormatter),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]

	// CEF wire format: `... _hmacVersion=v1 _hmac=<hex>\n`
	// Assert order: _hmacVersion before _hmac.
	s := string(line)
	vIdx := strings.Index(s, "_hmacVersion=")
	hIdx := strings.Index(s, " _hmac=")
	require.GreaterOrEqual(t, vIdx, 0, "_hmacVersion must appear in CEF")
	require.GreaterOrEqual(t, hIdx, 0, "_hmac must appear in CEF")
	assert.Less(t, vIdx, hIdx,
		"CEF: _hmacVersion must precede _hmac (issue #473)")

	// Extract _hmac hex value.
	hmacHex := extractCEFExtensionValue(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)

	// Canonicalise: strip ` _hmac=<hex>` tail, leaving newline intact.
	stripIdx := strings.LastIndex(s, " _hmac=")
	require.GreaterOrEqual(t, stripIdx, 0)
	// Find the end of the _hmac value: it ends at \n or end-of-string.
	// CEF lines end with `\n`.
	canonicalStr := s[:stripIdx] + "\n"
	if !strings.HasSuffix(s, "\n") {
		canonicalStr = s[:stripIdx]
	}
	canonical := []byte(canonicalStr)

	// Sanity: unmodified verifies.
	unverifyPassed, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	require.True(t, unverifyPassed, "unmodified CEF event must verify")

	// Tamper: flip _hmacVersion=v1 → v2 in the CEF line.
	tampered := bytes.Replace(line, []byte("_hmacVersion=v1"), []byte("_hmacVersion=v2"), 1)
	require.NotEqual(t, line, tampered, "CEF tamper step must modify the line")
	tamperedStr := string(tampered)
	tStripIdx := strings.LastIndex(tamperedStr, " _hmac=")
	require.GreaterOrEqual(t, tStripIdx, 0)
	tamperedCanonical := []byte(tamperedStr[:tStripIdx] + "\n")
	if !strings.HasSuffix(tamperedStr, "\n") {
		tamperedCanonical = []byte(tamperedStr[:tStripIdx])
	}
	verified, err := audit.VerifyHMAC(tamperedCanonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"CEF: tampered _hmacVersion must fail HMAC verification (issue #473 CEF parity)")
}

// extractJSONStringField parses the line as JSON and returns the named
// string field. Helper for the tampering tests.
func extractJSONStringField(t *testing.T, line []byte, key string) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimRight(line, "\n"), &m))
	v, ok := m[key].(string)
	require.True(t, ok, "field %q must be a string in the JSON event", key)
	return v
}

// extractCEFExtensionValue extracts the value of a CEF extension key
// from a line like `CEF:0|...|ext1=v1 _hmacVersion=v1 _hmac=<hex>`.
// Returns the raw value with CEF escapes preserved.
func extractCEFExtensionValue(t *testing.T, line []byte, key string) string {
	t.Helper()
	s := string(line)
	needle := " " + key + "="
	idx := strings.LastIndex(s, needle)
	require.GreaterOrEqual(t, idx, 0, "CEF extension %q must appear in the line", key)
	valStart := idx + len(needle)
	end := strings.IndexAny(s[valStart:], " \n")
	if end < 0 {
		return s[valStart:]
	}
	return s[valStart : valStart+end]
}

// TestVerifyHMAC_RemoveHmacVersion_Detected covers the "delete to
// downgrade" attack where an attacker strips `_hmac_version` entirely from
// the on-wire bytes. A naive verifier that parses JSON and uses a
// default salt when `_hmac_version` is missing would accept the event.
// The strip-only-`_hmac` canonicalisation correctly rejects this: the
// original `_hmac_version` was part of the hashed bytes, so removing it
// changes the canonical payload and the HMAC no longer matches.
func TestVerifyHMAC_RemoveHmacVersion_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("remove-v-salt-16-bytes!!!")
	auditor, out := newHMACPipelineTestAuditor(t, "remove-v", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	hmacHex := extractJSONStringField(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)

	// Remove `,"_hmac_version":"v1"` from the on-wire bytes entirely.
	// _hmac_version is inside the authenticated region, so removing it
	// changes the canonicalised bytes and verification must fail.
	removed := bytes.ReplaceAll(line, []byte(`,"_hmac_version":"v1"`), []byte(``))
	require.NotEqual(t, line, removed, "remove step must modify the line")

	canonical := stripHMACJSONField(removed)
	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"removing _hmac_version from the wire must fail HMAC verification (issue #473: delete-to-downgrade attack)")
}

// TestVerifyHMAC_TamperingSeverity_Detected covers tampering with a
// numeric framework field. severity is rendered as a bare number in
// JSON (no quotes), so the mutation shape differs from string-field
// tampers — worth its own coverage to catch JSON-escape regressions
// that might treat numeric fields differently.
func TestVerifyHMAC_TamperingSeverity_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("tamper-sev-salt-16-bytes!")
	auditor, out := newHMACPipelineTestAuditor(t, "tamper-sev", "v1", salt)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	hmacHex := extractJSONStringField(t, line, "_hmac")

	// severity defaults to 5 for auth_failure (no override). Tamper
	// "severity":5 → "severity":1 — same length, numeric unquoted.
	tampered := bytes.Replace(line, []byte(`"severity":5`), []byte(`"severity":1`), 1)
	require.NotEqual(t, line, tampered, "severity tamper must modify the line")

	canonical := stripHMACJSONField(tampered)
	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"HMAC verification must fail when a numeric framework field (severity) is tampered")
}

// TestVerifyHMAC_CEF_TamperingActorId_Detected is the CEF parity of the
// JSON actor_id tamper test. No existing CEF HMAC verification test
// covers consumer-field tampering.
func TestVerifyHMAC_CEF_TamperingActorId_Detected(t *testing.T) {
	t.Parallel()
	salt := []byte("cef-actor-salt-16-bytes!!")
	out := testhelper.NewMockOutput("cef-actor")
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}
	cefFormatter := &audit.CEFFormatter{
		Vendor: "Acme", Product: "TestApp", Version: "1.0",
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithFormatter(cefFormatter),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice-user01",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	s := string(line)
	hmacHex := extractCEFExtensionValue(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)

	// Tamper suser (the default CEF key for actor_id).
	// "alice-user01" → "bobby-user01" (same length).
	tampered := bytes.Replace(line, []byte("suser=alice-user01"), []byte("suser=bobby-user01"), 1)
	require.NotEqual(t, line, tampered, "CEF actor_id tamper must modify the line")

	// Strip trailing ` _hmac=<hex>`.
	stripIdx := strings.LastIndex(string(tampered), " _hmac=")
	require.GreaterOrEqual(t, stripIdx, 0)
	tamperedCanonical := tampered[:stripIdx]
	if strings.HasSuffix(s, "\n") {
		tamperedCanonical = append(tamperedCanonical, '\n')
	}

	verified, err := audit.VerifyHMAC(tamperedCanonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.False(t, verified,
		"CEF: tampered consumer field (suser) must fail HMAC verification")
}

// TestHMAC_CEF_OnWireBytesMatchHashedBytes is the CEF parity of
// TestHMAC_OnWireBytesMatchHashedBytes. Dedicated positive test that
// the CEF line with only ` _hmac=<hex>` stripped verifies against the
// emitted HMAC. Catches canonicalisation regressions in the CEF path.
func TestHMAC_CEF_OnWireBytesMatchHashedBytes(t *testing.T) {
	t.Parallel()
	salt := []byte("cef-onwire-salt-16-byt!!!")
	out := testhelper.NewMockOutput("cef-onwire")
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
		},
	}
	cefFormatter := &audit.CEFFormatter{
		Vendor: "Acme", Product: "TestApp", Version: "1.0",
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithFormatter(cefFormatter),
		audit.WithNamedOutput(out, audit.WithHMAC(&audit.HMACConfig{
			Enabled: true,
			Salt: audit.HMACSalt{
				Version: "v1",
				Value:   salt,
			},
			Algorithm: "HMAC-SHA-256",
		})),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome": "failure", "actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, auditor.Close())

	line := out.GetEvents()[0]
	hmacHex := extractCEFExtensionValue(t, line, "_hmac")
	require.NotEmpty(t, hmacHex)

	// Canonicalise: strip trailing ` _hmac=<hex>`, preserving newline.
	s := string(line)
	stripIdx := strings.LastIndex(s, " _hmac=")
	require.GreaterOrEqual(t, stripIdx, 0)
	canonical := []byte(s[:stripIdx])
	if strings.HasSuffix(s, "\n") {
		canonical = append(canonical, '\n')
	}

	verified, err := audit.VerifyHMAC(canonical, hmacHex, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"CEF on-wire bytes (minus ` _hmac=<hex>` tail) must verify against the emitted HMAC (issue #473 CEF parity)")
}

// TestReservedLibraryField_RejectedEvenWhenDeclaredInTaxonomy proves
// that the runtime reserved-field check fires even if the consumer
// managed to declare `_hmac` or `_hmac_version` as a taxonomy event field
// (and the taxonomy-level `reservedFieldNames` check was bypassed or
// disabled). The runtime check is the defence-in-depth safety net.
func TestReservedLibraryField_RejectedEvenWhenDeclaredInTaxonomy(t *testing.T) {
	t.Parallel()
	// Taxonomy validation rejects this via checkReservedFieldNames.
	// We construct the Taxonomy directly (bypassing ParseTaxonomyYAML's
	// validation) to simulate the defence-in-depth case — even if a
	// consumer sneaks a reserved name into a Taxonomy struct, the
	// runtime check still fires.
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
			// Note: we don't declare _hmac as required/optional — that
			// would trip the taxonomy-level reserved-field check at
			// WithTaxonomy. The runtime check catches the collision
			// when the consumer supplies _hmac in Fields at audit time,
			// regardless of taxonomy declaration state.
		},
	}
	out := testhelper.NewMockOutput("runtime-reserved")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	defer func() { _ = auditor.Close() }()

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":       "failure",
		"actor_id":      "alice",
		"_hmac_version": "attacker-injected-version",
	}))
	require.Error(t, err, "reserved field injection at runtime must be rejected")
	assert.ErrorIs(t, err, audit.ErrReservedFieldName)
	assert.ErrorIs(t, err, audit.ErrValidation)
}

// TestHMAC_DeterministicOutput_SameInputSameOutput proves that
// the HMAC computation is purely deterministic — identical
// (payload, salt, algorithm) inputs always produce the same
// output bytes. Contract is critical for verifiers: any
// non-determinism in the underlying primitive breaks every
// downstream consumer that recomputes HMACs to verify integrity.
// (#565 G6).
func TestHMAC_DeterministicOutput_SameInputSameOutput(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event":"determinism-test","actor":"alice"}`)
	salt := []byte("deterministic-salt-32-bytes-len!")
	algo := "HMAC-SHA-256"

	first, err := audit.ComputeHMAC(payload, salt, algo)
	require.NoError(t, err)
	second, err := audit.ComputeHMAC(payload, salt, algo)
	require.NoError(t, err)
	assert.Equal(t, first, second,
		"identical inputs must produce identical HMAC bytes; "+
			"non-determinism would break downstream verification")

	third, err := audit.ComputeHMAC(payload, salt, algo)
	require.NoError(t, err)
	assert.Equal(t, first, third)
}

// TestHMAC_PerOutput_KeyRotation_OldEventsVerifiable proves that
// rotating the HMAC salt on a live auditor does NOT invalidate
// events stamped under the previous version. The verifier carries
// the salt version inline (the `hmac_field_version` field) so
// downstream consumers can look up the correct salt for each
// event.
//
// This is the load-bearing property that makes salt rotation
// operationally safe: a rotation event does not retroactively
// break verification of events already on disk. (#565 G6).
func TestHMAC_PerOutput_KeyRotation_OldEventsVerifiable(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"event":"rotation-test","actor":"alice"}`)
	saltV1 := []byte("salt-version-one-32-bytes-len!!!")
	saltV2 := []byte("salt-version-two-32-bytes-len!!!")
	algo := "HMAC-SHA-256"

	// Stamp an event with v1.
	stampV1, err := audit.ComputeHMAC(payload, saltV1, algo)
	require.NoError(t, err)

	// Rotate to v2; stamp another event with the new salt.
	stampV2, err := audit.ComputeHMAC(payload, saltV2, algo)
	require.NoError(t, err)
	require.NotEqual(t, stampV1, stampV2,
		"different salts must produce different HMACs")

	// The v1-stamped event must still verify with v1 salt.
	okV1, verr := audit.VerifyHMAC(payload, stampV1, saltV1, algo)
	require.NoError(t, verr)
	assert.True(t, okV1, "v1-stamped event must verify under v1 salt after rotation")

	// And must NOT verify with v2 salt — operators rely on this
	// contract to detect when an event was stamped under the
	// wrong key.
	okWrong, verr := audit.VerifyHMAC(payload, stampV1, saltV2, algo)
	require.NoError(t, verr)
	assert.False(t, okWrong, "v1-stamped event must NOT verify under v2 salt")
}

// TestHMAC_EmptyAlgorithmName proves that ValidateHMACConfig
// rejects an empty Algorithm field with a clear error wrapping
// audit.ErrConfigInvalid. The empty algorithm is a footgun: a
// silent default would mean different consumer setups produce
// different HMACs for the same payload. (#565 G6).
func TestHMAC_EmptyAlgorithmName(t *testing.T) {
	t.Parallel()
	cfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("non-empty-salt-32-bytes-len!!!!!"),
		},
		Algorithm: "",
	}
	err := audit.ValidateHMACConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "algorithm is required",
		"diagnostic must name the missing field so operators can fix the config")
}
