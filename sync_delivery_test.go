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
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncLogger_EventAvailableImmediately(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithSynchronousDelivery(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)

	// No Close() called — events should be available immediately.
	assert.Equal(t, 1, out.EventCount(), "sync auditor should deliver events immediately")

	// Close is still safe.
	require.NoError(t, auditor.Close())
}

func TestSyncLogger_CloseIsSafe(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithSynchronousDelivery(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Close without any events — should not panic.
	require.NoError(t, auditor.Close())

	// Double close — should not panic.
	require.NoError(t, auditor.Close())
}

func TestSyncLogger_ValidationStillRuns(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithSynchronousDelivery(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Missing required field should still be rejected.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
}

func TestNewQuick_DefaultsToSync(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.NewQuick(t, "user_create")

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "ok"}))
	require.NoError(t, err)

	// No Close — events available immediately because Quick defaults to sync.
	assert.Equal(t, 1, events.Count(), "NewQuick should use synchronous delivery")
}
