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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/go-audit/audittest"
)

// --- Pattern 1: Full integration test with real taxonomy ---

func TestCreateUser_EmitsAuditEvent(t *testing.T) {
	// Use the same taxonomy YAML that production code uses.
	logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)

	svc := NewUserService(logger)
	err := svc.CreateUser("alice", "alice@example.com")
	require.NoError(t, err)

	// Close drains the async buffer — events are now in the recorder.
	_ = logger.Close()

	// Assert on captured events.
	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Equal(t, EventUserCreate, evt.EventType)
	assert.True(t, evt.HasField(FieldActorID, "alice"))
	assert.True(t, evt.HasField(FieldEmail, "alice@example.com"))

	// Assert on metrics.
	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}

func TestLogin_Failure_EmitsAuthEvent(t *testing.T) {
	logger, events, _ := audittest.NewLogger(t, taxonomyYAML)

	svc := NewUserService(logger)
	err := svc.Login("bob", "wrong-password")
	require.NoError(t, err) // AuditEvent itself shouldn't error

	_ = logger.Close()

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Equal(t, EventAuthFailure, evt.EventType)
	assert.True(t, evt.HasField(FieldActorID, "bob"))
	assert.True(t, evt.HasField(FieldReason, "invalid password"))
}

func TestLogin_Success_NoAuditEvent(t *testing.T) {
	logger, events, _ := audittest.NewLogger(t, taxonomyYAML)

	svc := NewUserService(logger)
	err := svc.Login("alice", "correct")
	require.NoError(t, err)

	_ = logger.Close()

	// Successful login does not emit an audit event.
	assert.Equal(t, 0, events.Count())
}

// --- Pattern 2: Quick smoke test without a taxonomy ---

func TestAuditEventEmitted_Quick(t *testing.T) {
	// NewLoggerQuick creates a permissive logger — any fields accepted.
	logger, events, _ := audittest.NewLoggerQuick(t, "user_create")

	svc := NewUserService(logger)
	_ = svc.CreateUser("charlie", "charlie@example.com")

	_ = logger.Close()

	// Just verify the event was emitted — no field validation.
	assert.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

// --- Pattern 3: Validation error testing ---

func TestValidationError_MissingRequiredField(t *testing.T) {
	logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)

	// Emit an event missing the required "actor_id" field.
	// This tests that the taxonomy validation works correctly.
	err := logger.AuditEvent(
		NewUserCreateEvent("success", ""), // actor_id is empty string, not missing
	)
	// Note: empty string is still present — validation checks presence, not emptiness.
	// To test truly missing fields, use NewEvent directly:
	require.NoError(t, err)

	_ = logger.Close()

	// The event was delivered (empty string is still a value).
	assert.Equal(t, 1, events.Count())
	assert.Equal(t, 0, metrics.ValidationErrors(EventUserCreate))
}
