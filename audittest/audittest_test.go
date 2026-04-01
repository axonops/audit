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

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/audittest"
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
default_enabled:
  - write
  - security
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
      reason: {}
`)

func TestNewLogger(t *testing.T) {
	t.Parallel()
	logger, events, metrics := audittest.NewLogger(t, testTaxonomyYAML)

	err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}

func TestNewLoggerQuick(t *testing.T) {
	t.Parallel()
	logger, events, _ := audittest.NewLoggerQuick(t, "user_create", "user_delete")

	err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"any_field": "any_value",
		"extra":     42,
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

func TestNewLogger_ValidationError(t *testing.T) {
	t.Parallel()
	logger, events, metrics := audittest.NewLogger(t, testTaxonomyYAML)

	// Missing required field "actor_id".
	err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required")
	require.NoError(t, logger.Close())

	assert.Equal(t, 0, events.Count())
	assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}

func TestNewLogger_WithConfig(t *testing.T) {
	t.Parallel()
	logger, events, _ := audittest.NewLogger(t, testTaxonomyYAML,
		audittest.WithConfig(audit.Config{
			Version: 1,
			Enabled: false, // disabled logger
		}),
	)

	// Disabled logger accepts events without error but does not deliver.
	err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	assert.Equal(t, 0, events.Count())
}

func TestNewLogger_TableDriven_WithReset(t *testing.T) {
	// Not parallel — subtests share a logger and use Reset.
	logger, events, _ := audittest.NewLogger(t, testTaxonomyYAML)

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
			err := logger.AuditEvent(audit.NewEvent(tc.eventType, tc.fields))
			require.NoError(t, err)
			// Wait for drain to process — logger stays open across sub-tests.
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
	assert.Equal(t, []string{"test"}, tax.DefaultEnabled)
}
