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

// Integration tests that prove the reference Splunk TA at
// deploy/splunk-ta-axonops-audit/ actually works when installed in a
// real Splunk instance. Unit tests in cmd/audit-gen verify file
// generation; appinspect in CI verifies the TA passes Splunkbase
// publishing rules; THIS file verifies the operator end-to-end:
// install the TA, send events, observe Splunk applying the TA's
// eventtypes, tags, INDEXED_EXTRACTIONS, and EVAL clauses.
//
// Container setup: `make test-infra-splunk-up` runs
// `make stage-splunk-ta` first to copy the TA to a gitignored
// staging directory, then bind-mounts that copy into the splunk
// container at /opt/splunk/etc/apps/TA-axonops-audit. Splunk
// auto-loads anything in etc/apps/ at start time.
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// taProbeClient is a single TLS-skipping HTTP client used for every
// `requireTALoaded` probe so we don't leak a fresh Transport per call
// (each leak holds idle persistConns until GC; goleak catches the
// fanout but the churn is wasteful).
var taProbeClient = &http.Client{ //nolint:gochecknoglobals // test infrastructure shared across parallel subtests
	Timeout:   10 * time.Second,
	Transport: &http.Transport{TLSClientConfig: insecureTLS()},
}

// taLoadedProbe queries Splunk's saved/eventtypes REST endpoint for
// the named eventtype. Returns true if the TA's eventtypes.conf has
// been loaded — Splunk returns 404 if the eventtype is unknown.
// Used as the first-step positive control before any field-extraction
// assertion: a green probe means the TA loaded; a red probe means
// the container needs to be recreated with the bind-mount in place.
func taLoadedProbe(t *testing.T, eventtypeName string) bool {
	t.Helper()
	reqURL := fmt.Sprintf("%s/services/saved/eventtypes/%s?output_mode=json",
		splunkSearchURL, url.PathEscape(eventtypeName))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, http.NoBody)
	require.NoError(t, err)
	req.SetBasicAuth(splunkUser, splunkPass)
	resp, err := taProbeClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// requireTALoaded fails (not skips — silent skips hide regressions)
// if the reference TA's eventtypes are not loaded in Splunk. The
// message tells the operator exactly how to recover: re-run
// `make test-infra-splunk-down && make test-infra-splunk-up`.
//
// Named `require*` (not `skip*`) because the body is a hard fail;
// skipping a TA-install assertion silently because the TA wasn't
// mounted would mask the very regression these tests exist to catch.
func requireTALoaded(t *testing.T) {
	t.Helper()
	if !taLoadedProbe(t, "account_user_create") {
		t.Fatalf("reference TA not loaded in test container — recreate with " +
			"`make test-infra-splunk-down && make test-infra-splunk-up`")
	}
}

// TestSplunkTA_Loaded — positive control: an `eventtype=` search
// matches ONLY if the TA's eventtypes.conf was loaded, parsed, and
// applied. Splunk silently logs+skips malformed conf, so this test
// also catches a TA that was mounted but failed to parse.
func TestSplunkTA_Loaded(t *testing.T) {
	skipIfArm64(t)
	requireTALoaded(t)

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))

	// The eventtype filter exercises the TA's eventtypes.conf entry
	// `[account_user_create]` with search `sourcetype="axonops:audit"
	// event_type="user_create"`. A match here proves the TA's
	// eventtype rule was applied at search time.
	hits := waitForEvent(t, fmt.Sprintf(
		`eventtype=account_user_create user_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"eventtype=account_user_create must match TA-tagged event for marker %s", m)
}

// TestSplunkTA_IndexedExtractionsWithoutSpath — the TA's props.conf
// declares `INDEXED_EXTRACTIONS = json` + `KV_MODE = none`. Searches
// against this sourcetype must find fields natively WITHOUT requiring
// a `| spath` pipeline stage. If this test fails but the CIM tests
// still pass (which use spath), the TA's INDEXED_EXTRACTIONS rule
// has regressed — e.g., wrong stanza name, sourcetype typo, or props
// silently shadowed by a higher-priority app.
func TestSplunkTA_IndexedExtractionsWithoutSpath(t *testing.T) {
	skipIfArm64(t)
	requireTALoaded(t)

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))

	// Note: NO `| spath` in the query. The TA's KV_MODE=json is
	// what makes user_id searchable as a predicate AND surfaces it
	// via `| table`. Splunk's default JSON result projection only
	// includes metadata fields, so the `| table` clause is required
	// to assert on the extracted-field values.
	hits := waitForEvent(t, fmt.Sprintf(
		`sourcetype="axonops:audit" user_id=%q | table user_id action object_id vendor_product`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"native field search must match — KV_MODE=json is the load-bearing TA rule")
	// Spot-check the extracted fields. If KV_MODE=json regressed,
	// these would be nil.
	assert.Equal(t, m, cimField(t, hits[0], "user_id"),
		"user_id must be extractable without spath")
	assert.Equal(t, "user_create", cimField(t, hits[0], "action"),
		"action must be extractable without spath")
	assert.Equal(t, "topic-"+m, cimField(t, hits[0], "object_id"),
		"object_id must be extractable without spath")
}

// TestSplunkTA_VendorProductEvalOverridesPerEvent — the TA's
// `EVAL-vendor_product = "AxonOps:Audit"` is a hard override:
// regardless of what the formatter writes (operator could have
// configured a custom VendorProduct), the indexed event must always
// carry the TA's canonical value. This protects against operator
// taxonomy pollution claiming the data is from a different product.
func TestSplunkTA_VendorProductEvalOverridesPerEvent(t *testing.T) {
	skipIfArm64(t)
	requireTALoaded(t)

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})
	// Deliberately wire the formatter with a DIFFERENT vendor_product
	// so the EVAL clobber is observable. The formatter writes
	// "EvilCorp:Override" into the JSON event; the TA must replace
	// it with "AxonOps:Audit" before search results return it.
	auditor := newCIMAuditor(t, out, "EvilCorp:Override")

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))

	hits := waitForEvent(t, fmt.Sprintf(
		`sourcetype="axonops:audit" user_id=%q | table user_id vendor_product`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1)
	assert.Equal(t, "AxonOps:Audit", cimField(t, hits[0], "vendor_product"),
		"TA's EVAL-vendor_product must clobber the formatter's per-event value")
}

// TestSplunkTA_AllEventtypesTaggedChange — every one of the eight
// canonical `<category>_<event>` eventtypes in the reference TA must
// carry `tag=change`. The CIM Change data model is the canonical model
// for audit events. A typo or accidental deletion in tags.conf would
// silently break Enterprise Security correlation; the per-eventtype
// iteration catches that without relying on aggregate counts.
func TestSplunkTA_AllEventtypesTaggedChange(t *testing.T) {
	skipIfArm64(t)
	requireTALoaded(t)

	cases := []struct {
		category, eventType string
	}{
		{"account", "user_create"},
		{"account", "user_update"},
		{"account", "user_delete"},
		{"configuration", "config_update"},
		{"security", "login_success"},
		{"security", "login_failure"},
		{"security", "logout"},
		{"security", "permission_denied"},
	}
	for _, tc := range cases {
		t.Run(tc.category+"_"+tc.eventType, func(t *testing.T) {
			out := newSplunkOutput(t, func(c *splunk.Config) {
				c.Sourcetype = "axonops:audit"
			})
			auditor := newCIMAuditor(t, out, "AxonOps:Audit")

			m := marker(t)
			fields := audit.Fields{"actor_id": m, "outcome": "success"}
			// Some events have extra required fields; fill them all so
			// the taxonomy validator accepts every case in the loop.
			switch tc.eventType {
			case "user_create", "user_update", "user_delete":
				fields["target_id"] = "topic-" + m
				fields["target_type"] = "topic"
			case "login_success", "login_failure":
				fields["source_ip"] = "10.0.0.1"
			}
			require.NoError(t, auditor.AuditEvent(audit.NewEvent(tc.eventType, fields)))

			expected := tc.category + "_" + tc.eventType
			hits := waitForEvent(t, fmt.Sprintf(
				`tag=change eventtype=%s user_id=%q`, expected, m), 1)
			require.GreaterOrEqual(t, len(hits), 1,
				"eventtype %s must carry tag=change", expected)
		})
	}
}

// TestSplunkTA_AuthenticationTagOnlySecurityCategory — security-category
// events MUST carry both tag=change and tag=authentication; non-security
// events MUST carry tag=change but NOT tag=authentication. The negative
// assertion (account event must NOT have tag=authentication) catches a
// tags.conf typo that applied authentication=enabled to every eventtype.
func TestSplunkTA_AuthenticationTagOnlySecurityCategory(t *testing.T) {
	skipIfArm64(t)
	requireTALoaded(t)

	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})
	auditor := newCIMAuditor(t, out, "AxonOps:Audit")

	mSecurity := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("login_success", audit.Fields{
		"actor_id":  mSecurity,
		"outcome":   "success",
		"source_ip": "10.0.0.1",
	})))

	mAccount := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    mAccount,
		"target_id":   "topic-" + mAccount,
		"target_type": "topic",
		"outcome":     "success",
	})))

	// Positive: security event carries tag=authentication.
	authHits := waitForEvent(t, fmt.Sprintf(
		`tag=authentication user_id=%q`, mSecurity), 1)
	require.GreaterOrEqual(t, len(authHits), 1,
		"security-category event must carry tag=authentication (login_success)")

	// Negative: account event does NOT carry tag=authentication. Wait
	// briefly for the event to be searchable under its own marker
	// first, then run the negative check.
	_ = waitForEvent(t, fmt.Sprintf(
		`sourcetype="axonops:audit" user_id=%q`, mAccount), 1)
	noAuthHits := searchSplunk(t, fmt.Sprintf(
		`tag=authentication user_id=%q`, mAccount))
	assert.Empty(t, noAuthHits,
		"account-category event must NOT carry tag=authentication — only security category events should")
}
