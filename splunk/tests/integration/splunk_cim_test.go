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
// Splunk Enterprise container. The library-side CIM mapping is
// exhaustively unit-tested in format_cim_test.go; these tests
// verify that the wire-format envelope (`/event` body with the
// cim_change formatter producing CIM-canonical keys) round-trips
// through Splunk and is searchable as the CIM Change data model.
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// TestSplunkIntegration_CIMJSON_SearchableAsCIMChange — send an
// event shaped per the CIM Change mapping and verify Splunk indexes
// it under the CIM-canonical field names (action, user_id,
// object_id, status, vendor_product, dvc) so dashboards keyed off
// the CIM Change data model find it without further transformation.
func TestSplunkIntegration_CIMJSON_SearchableAsCIMChange(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit" // CIM-aligned sourcetype
	})
	defer func() { require.NoError(t, out.Close()) }()

	m := marker(t)
	// Pre-formatted CIM Change envelope. In production, the
	// audit.CIMChangeFormatter (registered as YAML type: cim_change)
	// emits this shape; the integration test bypasses the auditor
	// and writes raw CIM JSON to assert the wire-level contract.
	cimEvent := map[string]any{
		"_time":           float64(time.Now().UnixMilli()) / 1000.0,
		"action":          "user_create",
		"change_type":     "account",
		"user_id":         m,
		"user_name":       "Alice CIM Test",
		"object_id":       "topic-" + m,
		"object_category": "topic",
		"status":          "success",
		"outcome":         "success", // preserved alongside status
		"vendor_product":  "AxonOps:Audit",
		"src":             "10.0.0.42",
		"dvc":             "host-cim-1",
	}
	payload, err := json.Marshal(cimEvent)
	require.NoError(t, err)
	require.NoError(t, out.Write(payload))

	// Search by CIM-canonical key (user_id) — proves Splunk indexed
	// the JSON keys as expected.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" user_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1, "CIM event must be searchable by user_id")

	// The indexed event should carry every CIM-canonical field we
	// emitted. Splunk's REST API returns indexed fields at the top
	// level of each hit map.
	first := hits[0]
	assert.Equal(t, "user_create", first["action"])
	assert.Equal(t, "account", first["change_type"])
	assert.Equal(t, m, first["user_id"])
	assert.Equal(t, "topic-"+m, first["object_id"])
	assert.Equal(t, "success", first["status"])
	assert.Equal(t, "AxonOps:Audit", first["vendor_product"])
}

// TestSplunkIntegration_CIMJSON_StatusSuccessFailure verifies that
// CIM Change's binary `status` field round-trips correctly for both
// outcome=success → status=success AND outcome=failure → status=failure.
// The library-side outcome-collapse logic is unit-tested; this
// integration anchors that Splunk indexes both values as the same
// field type (string), enabling `stats count by status` queries.
func TestSplunkIntegration_CIMJSON_StatusSuccessFailure(t *testing.T) {
	skipIfArm64(t)
	out := newSplunkOutput(t, nil)
	defer func() { require.NoError(t, out.Close()) }()

	mSuccess := marker(t)
	mFailure := marker(t)

	// Success event.
	successEvent, _ := json.Marshal(map[string]any{
		"_time":          float64(time.Now().UnixMilli()) / 1000.0,
		"action":         "login_success",
		"user_id":        mSuccess,
		"status":         "success",
		"outcome":        "success",
		"vendor_product": "AxonOps:Audit",
	})
	require.NoError(t, out.Write(successEvent))

	// Failure event (denied outcome collapsed to failure per the
	// formatter contract; outcome preserved alongside).
	failureEvent, _ := json.Marshal(map[string]any{
		"_time":          float64(time.Now().UnixMilli()) / 1000.0,
		"action":         "login_failure",
		"user_id":        mFailure,
		"status":         "failure",
		"outcome":        "denied", // preserved granular value
		"vendor_product": "AxonOps:Audit",
	})
	require.NoError(t, out.Write(failureEvent))

	// Verify each is searchable by its status.
	successHits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" user_id=%q status=success`, mSuccess), 1)
	require.GreaterOrEqual(t, len(successHits), 1, "success-status event must be searchable")

	failureHits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="axonops:audit" user_id=%q status=failure`, mFailure), 1)
	require.GreaterOrEqual(t, len(failureHits), 1, "failure-status event must be searchable")

	// The failure event's original outcome value MUST be preserved
	// alongside the collapsed status — operators can recover the
	// granular semantic downstream.
	first := failureHits[0]
	assert.Equal(t, "denied", first["outcome"],
		"original outcome must be preserved alongside collapsed status")
}
