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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// Issue #561 / F-21: unit tests for EventHandle.AuditEvent (event.go).
// Pairs with the BDD scenarios in tests/bdd/features/missing_coverage_bundle.feature
// so coverage.out shows the function above 80%.

// TestEventHandle_AuditEvent_DeliversViaBoundAuditor verifies the
// happy path: the event is delivered through the auditor that owns
// the handle.
func TestEventHandle_AuditEvent_DeliversViaBoundAuditor(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithSynchronousDelivery())

	handle, err := auditor.Handle("auth_failure")
	require.NoError(t, err)

	err = handle.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-1",
	}))
	require.NoError(t, err)

	events := out.GetEvents()
	require.Len(t, events, 1, "EventHandle.AuditEvent must deliver exactly 1 event")
	assert.Contains(t, string(events[0]), "auth_failure")
}

// TestEventHandle_AuditEvent_AfterClose_ReturnsErrClosed verifies the
// closed-auditor path: the handle's AuditEvent returns ErrClosed
// without writing to the output.
func TestEventHandle_AuditEvent_AfterClose_ReturnsErrClosed(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)

	handle, err := auditor.Handle("auth_failure")
	require.NoError(t, err)

	require.NoError(t, auditor.Close())

	err = handle.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "success",
		"actor_id": "actor-1",
	}))
	require.Error(t, err)
	assert.True(t, errors.Is(err, audit.ErrClosed),
		"closed-auditor handle.AuditEvent must return ErrClosed, got: %v", err)
	assert.Empty(t, out.GetEvents(), "no event should be delivered after Close")
}

// TestEventHandle_AuditEvent_ValidationError_Propagated verifies that
// validation errors flow through the handle path identically to the
// auditor path.
func TestEventHandle_AuditEvent_ValidationError_Propagated(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor := newTestAuditor(t, out, audit.WithSynchronousDelivery())

	handle, err := auditor.Handle("auth_failure")
	require.NoError(t, err)

	// Empty fields — required fields missing.
	err = handle.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{}))
	require.Error(t, err)
	assert.True(t, errors.Is(err, audit.ErrValidation),
		"missing-required validation error must wrap ErrValidation, got: %v", err)
	assert.Empty(t, out.GetEvents(), "validation-failed event must not be delivered")
}
