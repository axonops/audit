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

// Integration tests covering the auditor's fan-out behaviour when one
// of the outputs is the splunk HEC. The auditor MUST deliver every
// event to every output (no loss), the per-output formatters MUST be
// applied independently, and a failure in one output MUST NOT
// compromise delivery to the other (cross-output isolation).
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/splunk"
)

// newFanoutAuditor builds an audit.Auditor with two named outputs
// (file + splunk). Both outputs are wired with the default JSON
// formatter; per-output formatters are exercised in
// TestSplunkIntegration_Fanout_DifferentFormatters.
func newFanoutAuditor(t *testing.T, fileOut audit.Output, splunkOut audit.Output) *audit.Auditor {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML(cimTaxonomyYAML)
	require.NoError(t, err)
	a, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("splunk-fanout-integration"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(splunkOut),
	)
	require.NoError(t, err)
	return a
}

// countFileEventsMatching reads the JSON-lines file at path and
// returns the count of lines containing the marker substring. Used
// by the fan-out tests to verify file-side delivery.
func countFileEventsMatching(t *testing.T, path, marker string) int {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-only path under t.TempDir
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// Confirm the line is valid JSON before counting — guards
		// against partial writes or non-event diagnostic output.
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			actor, _ := m["actor_id"].(string)
			if actor == marker {
				n++
			}
		}
	}
	require.NoError(t, scanner.Err())
	return n
}

// TestSplunkIntegration_Fanout_FileAndSplunk — submit N events to an
// auditor with two named outputs (file + splunk). Both outputs MUST
// receive every event after Close: the file gets exactly N (file is
// synchronous), Splunk gets at least N (at-least-once delivery
// guarantee; the test bounds duplicates to catch a silent
// duplication regression). goroutine-leak detection comes from
// goleak.VerifyTestMain in splunk_test.go.
func TestSplunkIntegration_Fanout_FileAndSplunk(t *testing.T) {
	skipIfArm64(t)

	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	// MaxRetries=0 keeps the test deterministic: any transient
	// network blip won't multiply the indexed-event count via retry,
	// so the upper-bound duplication canary stays meaningful.
	splunkOut := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "audit:event"
		c.MaxRetries = 0
	})

	auditor := newFanoutAuditor(t, fileOut, splunkOut)

	m := marker(t)
	const n = 50
	for i := 0; i < n; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"actor_id":    m,
			"target_id":   fmt.Sprintf("topic-%d", i),
			"target_type": "topic",
			"outcome":     "success",
		})))
	}
	require.NoError(t, auditor.Close())

	// File side: exactly N (file output is synchronous; Close flushes
	// before returning).
	fileCount := countFileEventsMatching(t, filePath, m)
	assert.Equal(t, n, fileCount,
		"file output must receive exactly %d events matching marker %s", n, m)

	// Splunk side: at-least-once delivery means count >= N. With
	// MaxRetries=0 and no injected failures, we expect exactly N —
	// the upper bound catches any silent duplication regression
	// without flaking on a transient HEC blip.
	hits := waitForEvent(t, fmt.Sprintf(
		`index=main sourcetype="audit:event" %q | head %d`, m, n*2), n)
	require.GreaterOrEqual(t, len(hits), n,
		"splunk must receive at least %d events (at-least-once)", n)
	assert.LessOrEqual(t, len(hits), n+5,
		"splunk should not produce duplicates without retries; got %d (want %d)", len(hits), n)
}

// TestSplunkIntegration_Fanout_SplunkDown_FileStillSucceeds — when
// the splunk output's HEC URL points at a dead listener, the file
// output MUST still receive all N events and Close MUST return
// within a bounded time. This pins the fan-out independence guarantee
// — operators must be able to rely on a healthy output continuing
// to deliver even when another output is broken.
func TestSplunkIntegration_Fanout_SplunkDown_FileStillSucceeds(t *testing.T) {
	skipIfArm64(t)

	// Dead-listener: an httptest server that always returns 502
	// Bad Gateway. The splunk output will retry (MaxRetries=0 here
	// so it drops fast) and never index events, but the failure
	// MUST NOT block the fan-out.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "simulated outage", http.StatusBadGateway)
	}))
	t.Cleanup(dead.Close)

	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	gz := false
	splunkOut, err := splunk.New(&splunk.Config{
		URL:                        dead.URL,
		Token:                      "fake-token",
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              1 << 20,
		MaxEventBytes:              1 << 20,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    2 * time.Second,
		BufferSize:                 1000,
		MaxRetries:                 0,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: true,
	}, nil)
	require.NoError(t, err)

	auditor := newFanoutAuditor(t, fileOut, splunkOut)

	m := marker(t)
	const n = 50
	for i := 0; i < n; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"actor_id":    m,
			"target_id":   fmt.Sprintf("topic-%d", i),
			"target_type": "topic",
			"outcome":     "success",
		})))
	}

	// Close MUST return within the auditor's shutdown timeout.
	// Bound aggressively — the dead listener responds fast enough
	// that no part of Close should take more than a few seconds.
	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- auditor.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-closeCtx.Done():
		t.Fatalf("auditor.Close did not return within 30s despite the splunk output being unreachable — fan-out blocked on the failing output")
	}

	fileCount := countFileEventsMatching(t, filePath, m)
	assert.Equal(t, n, fileCount,
		"file output must receive all %d events even when splunk is down", n)
}

// TestSplunkIntegration_Fanout_DifferentFormatters — file output uses
// JSONFormatter, splunk uses CIMChangeFormatter. The per-output
// WithOutputFormatter option MUST apply independently: the file gets
// audit-canonical field names (actor_id, event_type) and Splunk gets
// CIM-canonical names (user_id, action).
func TestSplunkIntegration_Fanout_DifferentFormatters(t *testing.T) {
	skipIfArm64(t)

	dir := t.TempDir()
	filePath := filepath.Join(dir, "audit.log")
	fileOut, err := file.New(&file.Config{Path: filePath})
	require.NoError(t, err)

	splunkOut := newSplunkOutput(t, func(c *splunk.Config) {
		c.Sourcetype = "axonops:audit"
	})

	tax, err := audit.ParseTaxonomyYAML(cimTaxonomyYAML)
	require.NoError(t, err)
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("splunk-fanout-integration"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(splunkOut,
			audit.WithOutputFormatter(&audit.CIMChangeFormatter{VendorProduct: "AxonOps:Audit"}),
		),
	)
	require.NoError(t, err)

	m := marker(t)
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"actor_id":    m,
		"target_id":   "topic-" + m,
		"target_type": "topic",
		"outcome":     "success",
	})))
	require.NoError(t, auditor.Close())

	// File side: JSONFormatter preserves audit-canonical names.
	fileBytes, err := os.ReadFile(filePath) //nolint:gosec // test-only path under t.TempDir
	require.NoError(t, err)
	fileLine := string(fileBytes)
	assert.Contains(t, fileLine, `"actor_id":"`+m+`"`,
		"file output (JSONFormatter) must keep audit-canonical actor_id")
	assert.Contains(t, fileLine, `"event_type":"user_create"`,
		"file output (JSONFormatter) must keep audit-canonical event_type")

	// Splunk side: CIMChangeFormatter renames actor_id → user_id
	// and event_type → action. Use cimSearch+spath because the
	// `axonops:audit` sourcetype has the TA's KV_MODE=json which
	// matches duplicates against the cimField helper.
	hits := waitForEvent(t, cimSearch("axonops:audit", m, fmt.Sprintf(`search user_id=%q`, m)), 1)
	require.GreaterOrEqual(t, len(hits), 1)
	assert.Equal(t, m, cimField(t, hits[0], "user_id"),
		"splunk output (CIMChangeFormatter) must emit CIM-canonical user_id")
	assert.Equal(t, "user_create", cimField(t, hits[0], "action"),
		"splunk output (CIMChangeFormatter) must emit CIM-canonical action")
}
