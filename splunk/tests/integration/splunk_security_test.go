//go:build integration

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

// Integration tests for the splunk output's security guarantees against
// a real Splunk Enterprise container:
//
//   - AC 5: HMAC integrity end-to-end. Auditor wires HMACConfig via
//     WithHMAC; events are signed in the format pipeline; the indexed
//     `_hmac` field re-verifies via the same library helper that
//     production consumers use.
//
//   - AC 6: sensitivity-label PII stripping end-to-end. Fields tagged
//     `pii` in the taxonomy MUST be absent from the wire payload, the
//     indexed `_raw`, and from Splunk's auto-extracted fields. The
//     PII values MUST NOT appear anywhere in Splunk's index — substring
//     search across `index=main` returns zero hits.
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

//go:embed testdata/security_taxonomy.yaml
var securityTaxonomyYAML []byte

// hmacSalt generates a fresh per-test 32-byte salt via crypto/rand
// (twice MinSaltLength so the test would catch a "salt truncated to
// MinSaltLength" regression).
func hmacSalt(t *testing.T) []byte {
	t.Helper()
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	return salt
}

// reconstructAuthenticatedPayload reproduces the exact byte sequence
// the library HMAC'd over. Splunk's `_raw` is the JSON-parsed event
// with the framing `\n` consumed; the HMAC was computed over the
// framed bytes, so we strip ONLY `,"_hmac":"..."` (`_hmac_version`
// stays in — it is inside the authenticated region per issue #473)
// and re-append `\n` to reconstruct the authenticated payload.
func reconstructAuthenticatedPayload(line []byte) []byte {
	s := string(line)
	hmacStart := strings.Index(s, `,"_hmac":"`)
	if hmacStart < 0 {
		return line
	}
	hmacValStart := hmacStart + len(`,"_hmac":"`)
	hmacEnd := strings.Index(s[hmacValStart:], `"`)
	if hmacEnd < 0 {
		return line
	}
	hmacEnd = hmacValStart + hmacEnd + 1
	stripped := s[:hmacStart] + s[hmacEnd:]
	return append([]byte(stripped), '\n')
}

// newSecurityAuditor constructs an audit.Auditor pointed at the
// splunk output with per-output configuration applied via opts (the
// caller passes WithHMAC, WithExcludeLabels, or both).
func newSecurityAuditor(t *testing.T, out *splunk.Output, opts ...audit.OutputOption) *audit.Auditor {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML(securityTaxonomyYAML)
	require.NoError(t, err)
	a, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("splunk-security-integration"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out, opts...),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestSplunkIntegration_HMACIntegrity_RoundTrip — end-to-end HMAC
// integrity proof. Sign a known event through the splunk output, read
// it back via Splunk's search REST, strip ONLY the `_hmac` field
// (leaving `_hmac_version` inside the authenticated region), and
// re-verify with audit.VerifyHMAC. The library-level VerifyHMAC call
// is what production operators use, so a green test here means an
// operator's verifier will accept production events.
func TestSplunkIntegration_HMACIntegrity_RoundTrip(t *testing.T) {
	skipIfArm64(t)

	salt := hmacSalt(t)
	const saltVersion = "test-2026-q2"
	cfg := &audit.HMACConfig{
		Enabled:   true,
		Algorithm: "HMAC-SHA-256",
		Salt:      audit.HMACSalt{Version: saltVersion, Value: salt},
	}
	require.NoError(t, audit.ValidateHMACConfig(cfg),
		"the test salt must satisfy MinSaltLength + algorithm + version constraints")

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "audit:event"
	})
	auditor := newSecurityAuditor(t, out, audit.WithHMAC(cfg))

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))

	hits := waitForEvent(t, fmt.Sprintf(
		`index=main sourcetype="audit:event" %q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1, "HMAC-signed event must reach Splunk's index")

	rawAny, ok := hits[0]["_raw"]
	require.True(t, ok, "search hit must include _raw")
	rawStr, ok := rawAny.(string)
	require.True(t, ok, "_raw must be a string")
	rawBytes := []byte(rawStr)

	// Splunk default-truncates _raw at 10 000 bytes. If the formatter
	// silently produced an oversize payload, _hmac might fall past
	// the truncation boundary; assert explicitly so the failure mode
	// surfaces as "payload too large" rather than "field not found".
	require.Less(t, len(rawBytes), 10000,
		"indexed _raw must be under Splunk's default 10 000-byte truncation boundary")

	// Decode just enough to extract _hmac and _hmac_version.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(rawBytes, &parsed))
	hmacVal, ok := parsed["_hmac"].(string)
	require.True(t, ok, "_hmac field missing from indexed event")
	hmacVersion, ok := parsed["_hmac_version"].(string)
	require.True(t, ok, "_hmac_version field missing from indexed event")
	assert.Equal(t, saltVersion, hmacVersion,
		"_hmac_version must equal cfg.Salt.Version — a mismatch breaks operator-side salt rotation lookup")

	// Reconstruct the authenticated bytes via byte-surgical strip of
	// the `_hmac` field only. A JSON re-marshal would reorder keys
	// (Go's encoding/json sorts maps alphabetically) producing a
	// different byte sequence and a falsely-failing verification.
	payload := reconstructAuthenticatedPayload(rawBytes)
	verified, err := audit.VerifyHMAC(payload, hmacVal, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"VerifyHMAC must accept the round-tripped payload — this is the operator-side integrity guarantee")
}

// TestSplunkIntegration_SensitivityLabels_PIIExcluded — end-to-end
// proof that fields labelled `pii` in the taxonomy are absent from
// the wire payload, the indexed `_raw`, and from Splunk's auto-
// extracted field set when the output is wired with
// WithExcludeLabels("pii"). Non-PII fields on the same event MUST
// pass through (positive control), and the literal PII values MUST
// NOT appear anywhere in Splunk's index across any sourcetype
// (catches leaks via metadata, error responses, or auto-extraction
// into renamed fields).
func TestSplunkIntegration_SensitivityLabels_PIIExcluded(t *testing.T) {
	skipIfArm64(t)

	const (
		piiEmail = "alice-pii-leak-canary@example.com"
		piiSSN   = "999-PII-LEAK-CANARY-001"
	)

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "audit:event"
	})
	auditor := newSecurityAuditor(t, out, audit.WithExcludeLabels("pii"))

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
		"email":       piiEmail,
		"ssn":         piiSSN,
	})))

	hits := waitForEvent(t, fmt.Sprintf(
		`index=main sourcetype="audit:event" %q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1, "non-PII event must reach Splunk's index")

	rawAny, ok := hits[0]["_raw"]
	require.True(t, ok, "search hit must include _raw")
	rawStr, isStr := rawAny.(string)
	require.True(t, isStr, "_raw must be a string, got %T", rawAny)

	// Substring assertions on _raw — catch literal-value and key-name
	// leaks in the indexed payload.
	assert.NotContains(t, rawStr, piiEmail,
		"PII email value must NOT appear in indexed _raw")
	assert.NotContains(t, rawStr, piiSSN,
		"PII ssn value must NOT appear in indexed _raw")
	assert.NotContains(t, rawStr, `"email"`,
		"PII field key `email` must NOT appear in indexed _raw")
	assert.NotContains(t, rawStr, `"ssn"`,
		"PII field key `ssn` must NOT appear in indexed _raw")

	// Positive control: non-PII fields DID make it through.
	assert.Contains(t, rawStr, m,
		"non-PII actor_id (marker) must survive stripping")
	assert.Contains(t, rawStr, "topic-"+m,
		"non-PII target_id must survive stripping")

	// JSON-tree walk — catch a hypothetical nested-field leak that
	// flat substring checks would miss (e.g., a metadata.email_hash
	// field that wraps the PII).
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(rawStr), &parsed))
	assertNoKeyInTree(t, parsed, "email")
	assertNoKeyInTree(t, parsed, "ssn")

	// Splunk-wide value search — catches leaks via any other sourcetype,
	// any metadata field, or any error path that echoed the PII back.
	// Use the same marker time-window as the main search.
	emailHits := searchSplunk(t, fmt.Sprintf(`index=main %q`, piiEmail))
	assert.Empty(t, emailHits,
		"PII email value must not appear ANYWHERE in index=main (any sourcetype, any field)")
	ssnHits := searchSplunk(t, fmt.Sprintf(`index=main %q`, piiSSN))
	assert.Empty(t, ssnHits,
		"PII ssn value must not appear ANYWHERE in index=main (any sourcetype, any field)")
}

// TestSplunkIntegration_HMACOverStrippedPayload — combined-config
// invariant: when an output has BOTH HMAC enabled AND a sensitivity
// label excluded, the HMAC MUST be computed over the POST-strip
// payload, not the pre-strip one. A regression that HMAC'd the
// pre-strip payload would leak the PII via the digest (the wire
// bytes wouldn't carry the email, but the `_hmac` would commit to
// a digest derived from it — a side-channel for replay/comparison
// attacks against the same operator's salted events).
//
// The test confirms the ordering by verifying that VerifyHMAC
// succeeds against the wire bytes (which lack the PII). If HMAC
// had been computed pre-strip, the computed digest would differ
// from the indexed `_hmac` and VerifyHMAC would return false.
func TestSplunkIntegration_HMACOverStrippedPayload(t *testing.T) {
	skipIfArm64(t)

	const piiEmail = "alice-pre-strip-canary@example.com"
	salt := hmacSalt(t)
	cfg := &audit.HMACConfig{
		Enabled:   true,
		Algorithm: "HMAC-SHA-256",
		Salt:      audit.HMACSalt{Version: "test-2026-q2", Value: salt},
	}

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "audit:event"
	})
	auditor := newSecurityAuditor(t, out,
		audit.WithHMAC(cfg),
		audit.WithExcludeLabels("pii"),
	)

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
		"email":       piiEmail, // stripped before HMAC
	})))

	hits := waitForEvent(t, fmt.Sprintf(
		`index=main sourcetype="audit:event" %q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
	rawStr, isStr := hits[0]["_raw"].(string)
	require.True(t, isStr, "_raw must be a string, got %T", hits[0]["_raw"])
	rawBytes := []byte(rawStr)

	// First: the wire bytes must not contain the PII (sanity-check
	// the strip happened at all).
	assert.NotContains(t, rawStr, piiEmail,
		"PII must be absent from wire bytes when WithExcludeLabels is configured")

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(rawBytes, &parsed))
	hmacVal, ok := parsed["_hmac"].(string)
	require.True(t, ok, "_hmac field must be present")

	// The critical assertion: HMAC verifies against the POST-strip
	// payload. If the library HMAC'd the pre-strip payload, the
	// digest committed to bytes the consumer never received and
	// VerifyHMAC would return false here.
	payload := reconstructAuthenticatedPayload(rawBytes)
	verified, err := audit.VerifyHMAC(payload, hmacVal, salt, "HMAC-SHA-256")
	require.NoError(t, err)
	assert.True(t, verified,
		"HMAC must be computed over the POST-strip payload — a pre-strip HMAC would leak PII via the digest")
}

// assertNoKeyInTree walks a parsed JSON map recursively and fails the
// test if any nested object contains the named key. Catches PII leaks
// via nested fields that flat substring assertions would miss.
func assertNoKeyInTree(t *testing.T, v any, forbiddenKey string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			assert.NotEqual(t, forbiddenKey, k,
				"forbidden key %q present in indexed JSON tree", forbiddenKey)
			assertNoKeyInTree(t, child, forbiddenKey)
		}
	case []any:
		for _, child := range x {
			assertNoKeyInTree(t, child, forbiddenKey)
		}
	}
}
