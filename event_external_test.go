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

	"github.com/stretchr/testify/assert"

	"github.com/axonops/audit"
)

// TestBasicEvent_MetadataMethods_ReturnZeroValues locks the
// documented #597 contract for taxonomy-agnostic events: NewEvent
// returns an Event whose new metadata methods all return zero
// values. Consumers needing metadata access must use generated
// builders or [Auditor.Handle].
func TestBasicEvent_MetadataMethods_ReturnZeroValues(t *testing.T) {
	t.Parallel()
	ev := audit.NewEvent("user_create", audit.Fields{"outcome": "success"})
	assert.Equal(t, "user_create", ev.EventType())
	assert.Equal(t, audit.Fields{"outcome": "success"}, ev.Fields())
	assert.Empty(t, ev.Description(), "basicEvent has no taxonomy binding")
	assert.Nil(t, ev.Categories(), "basicEvent has no taxonomy binding")
	assert.Nil(t, ev.FieldInfoMap(), "basicEvent has no taxonomy binding")
}

// TestNewEventKV_MetadataMethods_ReturnZeroValues mirrors the
// basicEvent contract on the kv constructor.
func TestNewEventKV_MetadataMethods_ReturnZeroValues(t *testing.T) {
	t.Parallel()
	ev, err := audit.NewEventKV("auth_failure", "outcome", "failure", "actor_id", "alice")
	assert.NoError(t, err)
	assert.Equal(t, "auth_failure", ev.EventType())
	assert.Empty(t, ev.Description())
	assert.Nil(t, ev.Categories())
	assert.Nil(t, ev.FieldInfoMap())
}
