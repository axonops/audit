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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

var testTaxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
    - user_delete
  security:
    severity: 8
    events:
      - auth_failure
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
  user_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`)

func TestNewLogger(t *testing.T) {
	t.Parallel()
	auditor, events, metrics := audittest.New(t, testTaxonomyYAML)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}

func TestNewQuick(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.NewQuick(t, "user_create", "user_delete")

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"any_field": "any_value",
		"extra":     42,
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

func TestNew_ValidationError(t *testing.T) {
	t.Parallel()
	auditor, events, metrics := audittest.New(t, testTaxonomyYAML)

	// Missing required field "actor_id".
	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required")
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, events.Count())
	assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}

func TestNew_WithDisabled(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, testTaxonomyYAML,
		audittest.WithDisabled(),
	)

	// Disabled auditor accepts events without error but does not deliver.
	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, events.Count())
}

func TestNew_TableDriven_WithReset(t *testing.T) {
	// Not parallel — subtests share an auditor and use Reset.
	auditor, events, _ := audittest.New(t, testTaxonomyYAML)

	tests := []struct {
		fields    audit.Fields
		name      string
		eventType string
	}{
		{name: "create", eventType: "user_create", fields: audit.Fields{"outcome": "success", "actor_id": "alice"}},
		{name: "failure", eventType: "auth_failure", fields: audit.Fields{"outcome": "failure", "actor_id": "unknown", "reason": "bad password"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events.Reset()
			err := auditor.AuditEvent(audit.NewEvent(tc.eventType, tc.fields))
			require.NoError(t, err)
			// Wait for drain to process — auditor stays open across sub-tests.
			require.Eventually(t, func() bool { return events.Count() == 1 }, 2*time.Second, 10*time.Millisecond)
			assert.Equal(t, tc.eventType, events.Events()[0].EventType)
		})
	}
}

func TestQuickTaxonomy(t *testing.T) {
	t.Parallel()
	tax := audittest.QuickTaxonomy("user_create", "user_delete")
	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "user_create")
	assert.Contains(t, tax.Events, "user_delete")
	assert.Contains(t, tax.Categories, "test")
}
