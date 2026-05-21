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

// Integration tests for the CIM Change formatter against a real
// Splunk Enterprise container. Tests construct a full audit.Auditor
// with audit.CIMChangeFormatter wired via WithOutputFormatter,
// submit events through AuditEvent (with audit-side field names),
// and assert that Splunk indexes the events under the CIM-canonical
// key names (action, user_id, object_id, status, vendor_product).
//
// The formatter unit tests in format_cim_test.go cover the
// in-memory mapping; these tests cover the end-to-end contract:
// taxonomy → AuditEvent → CIMChangeFormatter → Splunk HEC →
// indexer → search REST.
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	_ "embed"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// cimTaxonomyYAML is the minimal taxonomy declaring user_create,
// login_success, and login_failure events. Mirrors the relevant
// subset of internal/schemagen/reference_ta_taxonomy.yaml but is
// owned by the splunk sub-module so go.mod doesn't reach across
// the module boundary into the parent's internal/.
//
//go:embed testdata/cim_taxonomy.yaml
var cimTaxonomyYAML []byte

// cimSearch builds a Splunk SPL query that finds events containing
// the per-test marker (unique 8-byte hex) and extracts the embedded
// JSON fields at SEARCH time via `spath`. This avoids depending on
// the Splunk Technology Add-on being installed (which would index-time
// extract via `INDEXED_EXTRACTIONS = json` in props.conf). The TA
// install end-to-end test in splunk_ta_install_test.go covers the
// index-time path separately.
//
// `head 5` bounds the result set for tests that submit a small number
// of events; every existing assertion looks at hits[0].
func cimSearch(sourcetype, marker string, extra ...string) string {
	q := fmt.Sprintf(`index=main sourcetype=%q %q | spath`, sourcetype, marker)
	for _, e := range extra {
		q += " | " + e
	}
	return q + " | head 5"
}

// cimField returns the canonical scalar value of a CIM-mapped field
// in a Splunk search hit. When Splunk's default KV_MODE auto-extracts
// JSON keys AND the search-time `spath` extracts them again, the
// resulting field becomes a multivalue with duplicate entries — the
// JSON encoder serialises that as []any. cimField unwraps the first
// element of any such multivalue (asserting every element is equal,
// so a real divergence would still surface as a test failure).
//
// Returns nil if the field is absent. Returns the value as-is when
// it is already a scalar.
func cimField(t *testing.T, hit map[string]any, name string) any {
	t.Helper()
	v, ok := hit[name]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return v
	}
	if len(arr) == 0 {
		return nil
	}
	for i := 1; i < len(arr); i++ {
		require.Equal(t, arr[0], arr[i],
			"CIM field %q multivalue must have identical entries (got %v); divergence indicates a real wire-format bug, not the KV+spath duplication artefact",
			name, arr)
	}
	return arr[0]
}

// newCIMAuditor builds an audit.Auditor wired to the splunk output
// via WithNamedOutput + WithOutputFormatter(CIMChangeFormatter).
// Taxonomy comes from the embedded testdata file.
//
// WithAppName + WithHost are required by audit.New — without them
// construction returns ErrAppNameRequired / ErrHostRequired.
func newCIMAuditor(t *testing.T, out *splunk.Output, vendorProduct string) *audit.Auditor {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML(cimTaxonomyYAML)
	require.NoError(t, err)
	a, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("splunk-cim-integration"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out,
			audit.WithOutputFormatter(&audit.CIMChangeFormatter{VendorProduct: vendorProduct}),
		),
	)
	require.NoError(t, err)
	// Auditor.Close drains the queue then closes the splunk output
	// via the closeOutputs cascade — single-owner shutdown.
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// assertCIMChangeEvent is the shared CIM-mapping assertion used by
// both the plain and gzip variants. Keeps the contract surface
// identical across wire-format axes so a gzip-specific regression
// (e.g., body mangled, only `action` survives) is caught.
func assertCIMChangeEvent(t *testing.T, hit map[string]any, expectedUserID, expectedObjectID, expectedAction string) {
	t.Helper()
	assert.Equal(t, expectedAction, cimField(t, hit, "action"),
		"CIM action key mapped from audit event_type")
	assert.Equal(t, expectedUserID, cimField(t, hit, "user_id"),
		"CIM user_id mapped from audit actor_id")
	assert.Equal(t, expectedObjectID, cimField(t, hit, "object_id"),
		"CIM object_id mapped from audit target_id")
	assert.Equal(t, "topic", cimField(t, hit, "object_category"),
		"CIM object_category mapped from audit target_type")
	assert.Equal(t, "success", cimField(t, hit, "status"),
		"CIM status mapped from audit outcome")
	assert.Equal(t, "AxonOps:Audit", cimField(t, hit, "vendor_product"),
		"vendor_product emitted by the formatter on every event (format_cim.go:resolvedVendorProduct)")
	_, hasActorID := hit["actor_id"]
	assert.False(t, hasActorID,
		"actor_id is in auditFieldsRemappedToCIM — must be remapped to user_id, not pass through")
}

// TestSplunkIntegration_CIMChange_MapsAuditFieldsToCIMKeys — submit
// an event through the full audit.Auditor → CIMChangeFormatter →
// splunk output pipeline. Verifies that Splunk indexes the event
// under CIM-canonical key names (user_id, object_id, action,
// object_category, status, vendor_product), proving the formatter
// actually emitted CIM-mapped keys on the wire (not just in unit
// tests).
func TestSplunkIntegration_CIMChange_MapsAuditFieldsToCIMKeys(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	m := marker(t)
	// Submit with AUDIT-side field names. The CIMChangeFormatter
	// maps actor_id → user_id, target_id → object_id, target_type
	// → object_category, outcome → status, etc.
	beforeSubmit := time.Now()
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
		"source_ip":   "10.0.0.42",
	})))

	// Search for the per-test marker, extract JSON via spath, and
	// then verify the formatter remapped actor_id → user_id on the
	// wire by asserting the extracted user_id field carries the
	// marker. The substring filter + spath approach avoids requiring
	// the TA to be installed (which would index-time-extract fields).
	hits := waitForEvent(t, cimSearch("axonops:audit", m, fmt.Sprintf(`search user_id=%q`, m)), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"CIM event must be searchable by user_id after spath extraction")
	assertCIMChangeEvent(t, hits[0], m, "topic-"+m, "user_create")
	assert.Equal(t, "10.0.0.42", cimField(t, hits[0], "src"),
		"CIM src mapped from audit source_ip")

	// Splunk indexes _time as epoch seconds; the search REST API
	// returns it as ISO-8601-with-offset or as an epoch-float
	// string depending on the search-job output mode. Either form
	// must parse to within 30s of the submit wall-clock — proves
	// Splunk parsed the formatter's epoch-ms output (not stored
	// it as a string).
	rawTime, ok := hits[0]["_time"].(string)
	require.True(t, ok, "_time should be returned as a string by the search API; got %T", hits[0]["_time"])
	indexedTime := parseSplunkTime(t, rawTime)
	delta := indexedTime.Sub(beforeSubmit).Abs()
	assert.Less(t, delta, 30*time.Second,
		"indexed _time delta %v exceeds 30s — Splunk did not parse the formatter's epoch-ms output", delta)
}

// parseSplunkTime decodes the _time value returned by the search REST.
// Splunk emits one of: RFC3339 with offset (`2026-05-20T10:23:14.000+00:00`),
// epoch-float (`1684574594.123`), or its internal display format
// (`2026-05-20 10:23:14.000 GMT`) depending on the search-job options.
// Test fails on any other shape — that signals the search response
// envelope changed and the assertion can no longer trust the field.
func parseSplunkTime(t *testing.T, s string) time.Time {
	t.Helper()
	if v, err := time.Parse(time.RFC3339, s); err == nil {
		return v
	}
	// Splunk's `output_time_format` default — space-separated with a
	// timezone abbreviation suffix.
	if v, err := time.Parse("2006-01-02 15:04:05.000 MST", s); err == nil {
		return v
	}
	if epoch, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Unix(0, int64(epoch*float64(time.Second)))
	}
	require.Failf(t, "unparseable _time", "%q matched none of RFC3339, splunkd display format, or epoch float", s)
	return time.Time{}
}

// TestSplunkIntegration_CIMChange_OutcomeCollapsesToStatus verifies
// the binary status collapse end-to-end through the formatter.
// Sends two events with outcome=success and outcome=denied; asserts:
//   - success → status=success
//   - denied  → status=failure (collapsed)
//   - the original outcome value is PRESERVED alongside (so consumers
//     can recover the granular semantic downstream).
func TestSplunkIntegration_CIMChange_OutcomeCollapsesToStatus(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, nil)
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	mSuccess := marker(t)
	mFailure := marker(t)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("login_success", audit.Fields{
		"actor_id":  mSuccess,
		"outcome":   "success",
		"source_ip": "10.0.0.1",
	})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("login_failure", audit.Fields{
		"actor_id":  mFailure,
		"outcome":   "denied", // collapsed to status=failure by the formatter
		"source_ip": "10.0.0.2",
	})))

	// Success: status=success, outcome=success.
	successHits := waitForEvent(t,
		cimSearch("audit:event", mSuccess, `search status=success`), 1)
	require.GreaterOrEqual(t, len(successHits), 1,
		"success-status event must be searchable; the formatter must have mapped outcome=success → status=success")
	assert.Equal(t, "success", cimField(t, successHits[0], "outcome"),
		"original outcome value preserved alongside collapsed status")

	// Failure: status=failure (collapsed), outcome=denied (preserved).
	failureHits := waitForEvent(t,
		cimSearch("audit:event", mFailure, `search status=failure`), 1)
	require.GreaterOrEqual(t, len(failureHits), 1,
		"failure-status event must be searchable; the formatter must have collapsed outcome=denied → status=failure")
	first := failureHits[0]
	assert.Equal(t, "denied", cimField(t, first, "outcome"),
		"original outcome must be preserved alongside collapsed status — the lossy collapse is recoverable")
	assert.Equal(t, "failure", cimField(t, first, "status"))
}

// TestSplunkIntegration_CIMChange_GzipPreservesMapping verifies the
// CIM formatter's output survives the gzip wire path with the FULL
// CIM-mapping assertion set (via assertCIMChangeEvent). A
// gzip-specific regression that mangled the JSON body such that
// Splunk stored garbage for everything except `action` and
// `object_id` would have passed the prior narrow assertion — the
// shared helper closes that gap.
func TestSplunkIntegration_CIMChange_GzipPreservesMapping(t *testing.T) {
	skipIfArm64(t)
	gz := true
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
		c.Gzip = &gz
	})
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "gzip-topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))

	hits := waitForEvent(t, cimSearch("axonops:audit", m, fmt.Sprintf(`search user_id=%q`, m)), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"gzipped CIM event must still index correctly")
	assertCIMChangeEvent(t, hits[0], m, "gzip-topic-"+m, "user_create")
}
