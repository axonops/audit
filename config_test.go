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
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_InvalidValidationMode(t *testing.T) {
	_, err := audit.New(
		audit.WithValidationMode("bogus"),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "invalid validation mode")
}

func TestNew_QueueSizeDefault(t *testing.T) {
	// QueueSize 0 should not cause an error; it defaults to 10,000.
	auditor, err := audit.New(
		audit.WithQueueSize(0),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_ShutdownTimeoutDefault(t *testing.T) {
	// ShutdownTimeout 0 should not cause an error; it defaults to 5s.
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_CustomShutdownTimeout(t *testing.T) {
	auditor, err := audit.New(
		audit.WithShutdownTimeout(10*time.Second),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_DisabledNoOp(t *testing.T) {
	out := testhelper.NewMockOutput("disabled-check")
	auditor, err := audit.New(
		audit.WithDisabled(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NotNil(t, auditor)

	// Audit on disabled auditor returns nil.
	err = auditor.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	assert.NoError(t, err)

	require.NoError(t, auditor.Close())
	assert.Equal(t, 0, out.EventCount(), "disabled auditor must not deliver events")
}

func TestNew_NegativeQueueSize_DefaultsCorrectly(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithQueueSize(-1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Verify the defaulted buffer actually works by sending an event.
	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount(), "event should be delivered through defaulted buffer")
}

func TestNew_NegativeShutdownTimeout_DefaultsCorrectly(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithShutdownTimeout(-1),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
	assert.Equal(t, 1, out.EventCount(), "event should be delivered with defaulted drain timeout")
}
