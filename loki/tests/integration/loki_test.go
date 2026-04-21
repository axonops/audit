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

// Package integration_test contains integration tests for the Loki
// output against a real Grafana Loki instance running in Docker.
// Requires: make test-infra-up
//
//nolint:gocritic // sprintfQuotedString: raw JSON and LogQL construction requires literal %s in quoted contexts throughout this file.
package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

const (
	lokiURL    = "http://localhost:3100/loki/api/v1/push"
	lokiQuery  = "http://localhost:3100/loki/api/v1/query_range"
	testTenant = "test-tenant"
)

// queryClient is a dedicated HTTP client for Loki queries (not
// http.DefaultClient, per project rules).
var queryClient = &http.Client{Timeout: 10 * time.Second}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// marker generates a unique string for test isolation.
func marker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "MARKER_" + hex.EncodeToString(b)
}

// newLokiOutput creates a Loki output pointing at the test container.
func newLokiOutput(t *testing.T, opts ...func(*loki.Config)) *loki.Output {
	t.Helper()
	cfg := &loki.Config{
		URL:                lokiURL,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      200 * time.Millisecond,
		Timeout:            10 * time.Second,
		MaxRetries:         3,
		BufferSize:         1000,
		Gzip:               true,
		TenantID:           testTenant,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	out, err := loki.New(cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// lokiQueryResult is the JSON structure returned by Loki's query API.
type lokiQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// queryLoki runs a LogQL query against the test Loki instance and
// returns the parsed result. Uses the test tenant.
func queryLoki(t *testing.T, logql string) lokiQueryResult {
	t.Helper()

	now := time.Now()
	params := url.Values{
		"query": {logql},
		"start": {fmt.Sprintf("%d", now.Add(-5*time.Minute).UnixNano())},
		"end":   {fmt.Sprintf("%d", now.Add(1*time.Minute).UnixNano())},
		"limit": {"1000"},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, lokiQuery+"?"+params.Encode(), http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Scope-OrgID", testTenant)

	resp, err := queryClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Loki query failed: %s", string(body))

	var result lokiQueryResult
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}

// countLogLines returns the total number of log lines across all streams.
func countLogLines(result lokiQueryResult) int {
	n := 0
	for _, stream := range result.Data.Result {
		n += len(stream.Values)
	}
	return n
}

// waitForLoki polls Loki until at least n log lines match the query,
// or the timeout expires. Returns the final query result.
func waitForLoki(t *testing.T, logql string, n int, timeout time.Duration) lokiQueryResult {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		result := queryLoki(t, logql)
		if countLogLines(result) >= n {
			return result
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d log lines from Loki (query: %s, got: %d)",
				n, logql, countLogLines(result))
		case <-tick.C:
		}
	}
}

// findLogLine searches the query result for a log line containing the marker.
func findLogLine(result lokiQueryResult, marker string) (string, bool) {
	for _, stream := range result.Data.Result {
		for _, val := range stream.Values {
			if len(val) >= 2 {
				line := val[1]
				if containsMarker(line, marker) {
					return line, true
				}
			}
		}
	}
	return "", false
}

func containsMarker(line, m string) bool {
	return line != "" && strings.Contains(line, m)
}

// ---------------------------------------------------------------------------
// Basic delivery
// ---------------------------------------------------------------------------

func TestLoki_BasicDelivery(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "go_audit_test"}
	})
	out.SetFrameworkFields("testapp", "test-host", "UTC", 9999)

	m := marker(t)
	meta := audit.EventMetadata{
		EventType: "user_login",
		Severity:  6,
		Category:  "authentication",
		Timestamp: time.Now(),
	}
	data := []byte(fmt.Sprintf(`{"actor_id":"alice","marker":"%s"}`, m))
	require.NoError(t, out.WriteWithMetadata(data, meta))
	require.NoError(t, out.Close())

	// Query by the static label and event_type.
	result := waitForLoki(t, `{job="go_audit_test",event_type="user_login"}`, 1, 15*time.Second)

	line, found := findLogLine(result, m)
	require.True(t, found, "marker %s not found in Loki results", m)
	assert.Contains(t, line, `"actor_id":"alice"`, "event data should be preserved")
}

// ---------------------------------------------------------------------------
// Stream labels
// ---------------------------------------------------------------------------

func TestLoki_StreamLabels(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"environment": "integration_test"}
	})
	out.SetFrameworkFields("labelapp", "label-host", "UTC", 42)

	m := marker(t)
	meta := audit.EventMetadata{
		EventType: "resource_create",
		Severity:  4,
		Category:  "data_access",
		Timestamp: time.Now(),
	}
	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"marker":"%s"}`, m)), meta,
	))
	require.NoError(t, out.Close())

	// Query and verify all labels.
	result := waitForLoki(t, `{environment="integration_test",event_type="resource_create"}`, 1, 15*time.Second)
	require.NotEmpty(t, result.Data.Result)

	stream := result.Data.Result[0].Stream
	assert.Equal(t, "resource_create", stream["event_type"])
	assert.Equal(t, "4", stream["severity"])
	assert.Equal(t, "data_access", stream["event_category"])
	assert.Equal(t, "labelapp", stream["app_name"])
	assert.Equal(t, "label-host", stream["host"])
	assert.Equal(t, "42", stream["pid"])
	assert.Equal(t, "integration_test", stream["environment"])
}

// ---------------------------------------------------------------------------
// Multi-stream (different event types)
// ---------------------------------------------------------------------------

func TestLoki_MultiStream(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "multi_stream_test"}
	})
	out.SetFrameworkFields("msapp", "ms-host", "UTC", 1)

	m := marker(t)
	ts := time.Now()

	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"action":"login","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "user_login", Severity: 6, Category: "auth", Timestamp: ts},
	))
	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"action":"create","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "resource_create", Severity: 4, Category: "data", Timestamp: ts.Add(time.Millisecond)},
	))
	require.NoError(t, out.Close())

	// Each event type should be in a separate stream.
	loginResult := waitForLoki(t, fmt.Sprintf(`{job="multi_stream_test",event_type="user_login"} |= "%s"`, m), 1, 15*time.Second)
	assert.Equal(t, 1, countLogLines(loginResult), "should have exactly 1 login event")

	createResult := waitForLoki(t, fmt.Sprintf(`{job="multi_stream_test",event_type="resource_create"} |= "%s"`, m), 1, 15*time.Second)
	assert.Equal(t, 1, countLogLines(createResult), "should have exactly 1 create event")
}

// ---------------------------------------------------------------------------
// Batch delivery
// ---------------------------------------------------------------------------

func TestLoki_BatchDelivery(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "batch_test"}
		c.BatchSize = 5
		c.FlushInterval = 100 * time.Millisecond
	})
	out.SetFrameworkFields("batchapp", "batch-host", "UTC", 1)

	m := marker(t)
	ts := time.Now()

	for i := 0; i < 10; i++ {
		data := []byte(fmt.Sprintf(`{"index":%d,"marker":"%s"}`, i, m))
		meta := audit.EventMetadata{
			EventType: "batch_event",
			Severity:  6,
			Timestamp: ts.Add(time.Duration(i) * time.Millisecond),
		}
		require.NoError(t, out.WriteWithMetadata(data, meta))
	}

	// Wait for events to be flushed by the batch loop before closing.
	// BatchSize=5 with 10 events → 2 flushes.
	waitForLoki(t, fmt.Sprintf(`{job="batch_test",event_type="batch_event"} |= "%s"`, m), 10, 15*time.Second)

	require.NoError(t, out.Close())

	result := queryLoki(t, fmt.Sprintf(`{job="batch_test",event_type="batch_event"} |= "%s"`, m))
	assert.GreaterOrEqual(t, countLogLines(result), 10, "all 10 events should be delivered")
}

// ---------------------------------------------------------------------------
// Shutdown flush
// ---------------------------------------------------------------------------

func TestLoki_ShutdownFlush(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "shutdown_test"}
		c.BatchSize = 100             // large — won't trigger size flush
		c.FlushInterval = time.Minute // long — won't trigger timer
	})
	out.SetFrameworkFields("shutapp", "shut-host", "UTC", 1)

	m := marker(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, out.WriteWithMetadata(
			[]byte(fmt.Sprintf(`{"n":%d,"marker":"%s"}`, i, m)),
			audit.EventMetadata{EventType: "shutdown_event", Severity: 6, Timestamp: time.Now()},
		))
	}

	// Close should flush pending events.
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="shutdown_test"} |= "%s"`, m), 3, 15*time.Second)
	assert.Equal(t, 3, countLogLines(result), "all pending events should be flushed on shutdown")
}

// ---------------------------------------------------------------------------
// Multi-tenancy (X-Scope-OrgID)
// ---------------------------------------------------------------------------

func TestLoki_MultiTenancy(t *testing.T) {
	tenantA := "tenant-a"
	tenantB := "tenant-b"

	m := marker(t)

	// Push to tenant A.
	outA := newLokiOutput(t, func(c *loki.Config) {
		c.TenantID = tenantA
		c.Labels.Static = map[string]string{"job": "tenant_test"}
	})
	outA.SetFrameworkFields("app", "host", "UTC", 1)
	require.NoError(t, outA.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"tenant":"A","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "tenant_event", Severity: 6, Timestamp: time.Now()},
	))
	require.NoError(t, outA.Close())

	// Push to tenant B.
	outB := newLokiOutput(t, func(c *loki.Config) {
		c.TenantID = tenantB
		c.Labels.Static = map[string]string{"job": "tenant_test"}
	})
	outB.SetFrameworkFields("app", "host", "UTC", 1)
	require.NoError(t, outB.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"tenant":"B","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "tenant_event", Severity: 6, Timestamp: time.Now()},
	))
	require.NoError(t, outB.Close())

	// Query tenant A — should only see tenant A's event.
	queryWithTenant := func(tenant, logql string) lokiQueryResult {
		t.Helper()
		now := time.Now()
		params := url.Values{
			"query": {logql},
			"start": {fmt.Sprintf("%d", now.Add(-5*time.Minute).UnixNano())},
			"end":   {fmt.Sprintf("%d", now.Add(1*time.Minute).UnixNano())},
			"limit": {"1000"},
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, lokiQuery+"?"+params.Encode(), http.NoBody)
		require.NoError(t, err)
		req.Header.Set("X-Scope-OrgID", tenant)
		resp, err := queryClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "query failed: %s", string(body))
		var result lokiQueryResult
		require.NoError(t, json.Unmarshal(body, &result))
		return result
	}

	// Wait for tenant A's event.
	var resultA lokiQueryResult
	deadlineA := time.After(15 * time.Second)
	tickA := time.NewTicker(500 * time.Millisecond)
	defer tickA.Stop()
	for {
		resultA = queryWithTenant(tenantA, fmt.Sprintf(`{job="tenant_test"} |= "%s"`, m))
		if countLogLines(resultA) >= 1 {
			break
		}
		select {
		case <-deadlineA:
			t.Fatal("timed out waiting for tenant A event")
		case <-tickA.C:
		}
	}

	lineA, found := findLogLine(resultA, m)
	require.True(t, found)
	assert.Contains(t, lineA, `"tenant":"A"`)

	// Tenant A should NOT see tenant B's event.
	assert.Equal(t, 1, countLogLines(resultA),
		"tenant A should only see its own event")

	// Tenant B should see its own event.
	var resultB lokiQueryResult
	deadlineB := time.After(15 * time.Second)
	tickB := time.NewTicker(500 * time.Millisecond)
	defer tickB.Stop()
	for {
		resultB = queryWithTenant(tenantB, fmt.Sprintf(`{job="tenant_test"} |= "%s"`, m))
		if countLogLines(resultB) >= 1 {
			break
		}
		select {
		case <-deadlineB:
			t.Fatal("timed out waiting for tenant B event")
		case <-tickB.C:
		}
	}

	lineB, found := findLogLine(resultB, m)
	require.True(t, found)
	assert.Contains(t, lineB, `"tenant":"B"`)
}

// ---------------------------------------------------------------------------
// Event data integrity
// ---------------------------------------------------------------------------

func TestLoki_EventDataIntegrity(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "integrity_test"}
	})
	out.SetFrameworkFields("intapp", "int-host", "UTC", 1)

	m := marker(t)
	eventJSON := fmt.Sprintf(`{"actor_id":"bob","action":"delete","resource_id":"res-123","marker":"%s","nested":{"key":"value"}}`, m)
	require.NoError(t, out.WriteWithMetadata(
		[]byte(eventJSON),
		audit.EventMetadata{EventType: "resource_delete", Severity: 8, Timestamp: time.Now()},
	))
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="integrity_test"} |= "%s"`, m), 1, 15*time.Second)

	line, found := findLogLine(result, m)
	require.True(t, found)

	// Parse the log line as JSON and verify fields.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &parsed))
	assert.Equal(t, "bob", parsed["actor_id"])
	assert.Equal(t, "delete", parsed["action"])
	assert.Equal(t, "res-123", parsed["resource_id"])

	// Verify nested object preserved.
	nested, ok := parsed["nested"].(map[string]any)
	require.True(t, ok, "nested field should be a JSON object")
	assert.Equal(t, "value", nested["key"])
}

// ---------------------------------------------------------------------------
// Gzip compression (verify real Loki accepts gzip body)
// ---------------------------------------------------------------------------

func TestLoki_GzipCompression(t *testing.T) {
	// Gzip enabled (default in newLokiOutput).
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "gzip_test"}
		c.Gzip = true
	})
	out.SetFrameworkFields("gzapp", "gz-host", "UTC", 1)

	m := marker(t)
	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"gzip":"enabled","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "gzip_event", Severity: 6, Timestamp: time.Now()},
	))
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="gzip_test"} |= "%s"`, m), 1, 15*time.Second)
	_, found := findLogLine(result, m)
	assert.True(t, found, "gzip-compressed event should be accepted by real Loki")
}

// ---------------------------------------------------------------------------
// Uncompressed delivery
// ---------------------------------------------------------------------------

func TestLoki_UncompressedDelivery(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "nogzip_test"}
		c.Gzip = false
	})
	out.SetFrameworkFields("noapp", "no-host", "UTC", 1)

	m := marker(t)
	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"gzip":"disabled","marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "nogzip_event", Severity: 6, Timestamp: time.Now()},
	))
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="nogzip_test"} |= "%s"`, m), 1, 15*time.Second)
	_, found := findLogLine(result, m)
	assert.True(t, found, "uncompressed event should be accepted by real Loki")
}

// ---------------------------------------------------------------------------
// Duplicate timestamps (monotonic enforcement)
// ---------------------------------------------------------------------------

func TestLoki_DuplicateTimestamps(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "timestamp_test"}
	})
	out.SetFrameworkFields("tsapp", "ts-host", "UTC", 1)

	m := marker(t)
	// Send 5 events with the exact same timestamp — the library should
	// bump each by 1ns to ensure monotonic ordering within the stream.
	ts := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, out.WriteWithMetadata(
			[]byte(fmt.Sprintf(`{"n":%d,"marker":"%s"}`, i, m)),
			audit.EventMetadata{EventType: "ts_event", Severity: 6, Timestamp: ts},
		))
	}
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="timestamp_test"} |= "%s"`, m), 5, 15*time.Second)
	assert.Equal(t, 5, countLogLines(result),
		"all 5 events with duplicate timestamps should be accepted by Loki")
}

// ---------------------------------------------------------------------------
// Dynamic label exclusion
// ---------------------------------------------------------------------------

func TestLoki_DynamicLabelExclusion(t *testing.T) {
	out := newLokiOutput(t, func(c *loki.Config) {
		c.Labels.Static = map[string]string{"job": "exclusion_test"}
		c.Labels.Dynamic.ExcludeSeverity = true
		c.Labels.Dynamic.ExcludePID = true
	})
	out.SetFrameworkFields("exapp", "ex-host", "UTC", 42)

	m := marker(t)
	require.NoError(t, out.WriteWithMetadata(
		[]byte(fmt.Sprintf(`{"marker":"%s"}`, m)),
		audit.EventMetadata{EventType: "ex_event", Severity: 8, Category: "security", Timestamp: time.Now()},
	))
	require.NoError(t, out.Close())

	result := waitForLoki(t, fmt.Sprintf(`{job="exclusion_test",event_type="ex_event"} |= "%s"`, m), 1, 15*time.Second)
	require.NotEmpty(t, result.Data.Result)

	stream := result.Data.Result[0].Stream
	assert.Equal(t, "ex_event", stream["event_type"], "event_type should be present")
	assert.Equal(t, "security", stream["event_category"], "event_category should be present")
	assert.Equal(t, "exapp", stream["app_name"], "app_name should be present")

	// Excluded labels should NOT be present.
	_, hasSeverity := stream["severity"]
	assert.False(t, hasSeverity, "severity should be excluded from labels")
	_, hasPID := stream["pid"]
	assert.False(t, hasPID, "pid should be excluded from labels")
}
