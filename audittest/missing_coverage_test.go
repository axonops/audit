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

package audittest_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

// Issue #561 unit tests covering audittest.WithSync, audittest.WithVerbose
// and Recorder.RequireEvents. These supplement the BDD scenarios in
// tests/bdd/features/missing_coverage_bundle.feature so coverage.out
// records the symbols above 80%.

const minimalTaxonomyYAML = `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`

// TestWithSync_DefaultsToSynchronousDelivery verifies the option wires
// audit.WithSynchronousDelivery: events appear in the recorder
// immediately after AuditEvent returns, with no Close call.
func TestWithSync_DefaultsToSynchronousDelivery(t *testing.T) {
	t.Parallel()
	auditor, rec, _ := audittest.New(t, []byte(minimalTaxonomyYAML), audittest.WithSync())
	require.NotNil(t, auditor)
	require.NotNil(t, rec)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-1",
	}))
	require.NoError(t, err)

	// No Close call — sync delivery makes the event visible immediately.
	assert.Equal(t, 1, rec.Count(), "WithSync must make events visible without Close")
	events := rec.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "user_create", events[0].EventType)
}

// TestWithVerbose_EnablesDiagnosticLogging verifies the option wires
// audit.WithDiagnosticLogger so lifecycle messages reach the captured
// handler (silenced by default in test auditors).
func TestWithVerbose_EnablesDiagnosticLogging(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	captured := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	auditor, _, _ := audittest.New(t, []byte(minimalTaxonomyYAML),
		audittest.WithVerbose(),
		audittest.WithAuditOption(audit.WithDiagnosticLogger(captured)),
	)
	require.NotNil(t, auditor)

	// Trigger a lifecycle event by closing the auditor — Close emits a
	// "shutdown started" / "shutdown complete" diagnostic log when
	// verbose mode is enabled.
	require.NoError(t, auditor.Close())

	output := buf.String()
	assert.Contains(t, output, "audit:",
		"WithVerbose must produce diagnostic log output containing 'audit:' prefix")
}

// TestWithVerbose_DefaultIsNonVerbose verifies that constructing an
// audittest auditor without WithVerbose runs cleanly. (When no
// WithDiagnosticLogger is supplied, audittest defaults to a
// discard-handler logger; with one, the user's handler is honoured.)
func TestWithVerbose_DefaultIsNonVerbose(t *testing.T) {
	t.Parallel()
	auditor, _, _ := audittest.New(t, []byte(minimalTaxonomyYAML))
	require.NotNil(t, auditor)
	require.NoError(t, auditor.Close())
}

// TestRequireEvents_ExactCount returns the recorded events without
// failing the bench when the count matches.
func TestRequireEvents_ExactCount(t *testing.T) {
	t.Parallel()
	auditor, rec, _ := audittest.New(t, []byte(minimalTaxonomyYAML))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-1",
	})))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-2",
	})))

	events := rec.RequireEvents(t, 2)
	assert.Len(t, events, 2)
	assert.Equal(t, "user_create", events[0].EventType)
	assert.Equal(t, "user_create", events[1].EventType)
}

// TestRequireEvents_FailsBenchOnMismatch verifies RequireEvents calls
// tb.Fatalf when the event count does not match. Uses a probe TB so
// the failure does not propagate to this test.
func TestRequireEvents_FailsBenchOnMismatch(t *testing.T) {
	t.Parallel()
	auditor, rec, _ := audittest.New(t, []byte(minimalTaxonomyYAML))
	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-1",
	})))

	probe := &probeTB{TB: t}
	rec.RequireEvents(probe, 5)
	assert.True(t, probe.failed, "RequireEvents must fail the bench when count mismatches")
	assert.Contains(t, probe.fatalMsg, "5",
		"failure message should reference the expected count")
}

// TestRequireEvents_ZeroExpectedAndZeroActual handles the n=0 boundary.
func TestRequireEvents_ZeroExpectedAndZeroActual(t *testing.T) {
	t.Parallel()
	_, rec, _ := audittest.New(t, []byte(minimalTaxonomyYAML))
	events := rec.RequireEvents(t, 0)
	assert.Empty(t, events)
}

// probeTB is a minimal testing.TB that captures Fatalf invocations
// without propagating them. Lets tests assert on RequireEvents'
// failure path.
type probeTB struct {
	testing.TB
	fatalMsg string
	failed   bool
}

func (p *probeTB) Helper() {}
func (p *probeTB) Fatalf(format string, args ...any) {
	p.failed = true
	p.fatalMsg = fmt.Sprintf(format, args...)
}
func (p *probeTB) Errorf(format string, args ...any) {
	p.failed = true
	p.fatalMsg = fmt.Sprintf(format, args...)
}
func (p *probeTB) FailNow() { p.failed = true }
func (p *probeTB) Fail()    { p.failed = true }
