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
	"fmt"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

var exampleTaxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`)

func ExampleNew() {
	// Use a real *testing.T in actual tests — this is for runnable doc only.
	t := &testing.T{}

	auditor, events, metrics := audittest.New(t, exampleTaxonomyYAML)

	_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))

	fmt.Println("count:", events.Count())
	fmt.Println("type:", events.Events()[0].EventType)
	fmt.Println("deliveries:", metrics.EventDeliveries("recorder", "success"))
	// Output:
	// count: 1
	// type: user_create
	// deliveries: 1
}

func ExampleNewQuick() {
	t := &testing.T{}

	auditor, events, _ := audittest.NewQuick(t, "user_create", "user_delete")

	_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"any_field": "any_value",
	}))

	fmt.Println("count:", events.Count())
	fmt.Println("type:", events.Events()[0].EventType)
	// Output:
	// count: 1
	// type: user_create
}

func ExampleRecorder_FindByType() {
	t := &testing.T{}

	auditor, events, _ := audittest.NewQuick(t, "user_create", "auth_failure")

	_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"actor_id": "alice"}))
	_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"actor_id": "bob"}))
	_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"actor_id": "charlie"}))

	creates := events.FindByType("user_create")
	fmt.Println("user_create count:", len(creates))
	fmt.Println("auth_failure count:", len(events.FindByType("auth_failure")))
	// Output:
	// user_create count: 2
	// auth_failure count: 1
}

// ExampleRecorder_WaitForN shows how to wait for asynchronously-
// delivered events to land in the Recorder before asserting. Use
// WaitForN with [WithAsync] or any auditor configured for async
// delivery — synchronous auditors do not need it.
func ExampleRecorder_WaitForN() {
	t := &testing.T{}

	auditor, events, _ := audittest.New(t, exampleTaxonomyYAML, audittest.WithAsync())
	defer func() { _ = auditor.Close() }() // stub *testing.T has no Cleanup — close explicitly

	// Emit events from a goroutine — simulates a service emitting
	// audit events on a hot path.
	go func() {
		for i := 0; i < 3; i++ {
			_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": "alice",
			}))
		}
	}()

	if ok := events.WaitForN(t, 3, 2*time.Second); !ok {
		fmt.Println("timeout waiting for 3 events")
		return
	}
	fmt.Println("count:", events.Count())
	// Output:
	// count: 3
}

// exampleSensitivityTaxonomyYAML registers a "pii" sensitivity label
// so ExampleWithExcludeLabels can exercise the strip path.
var exampleSensitivityTaxonomyYAML = []byte(`
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
`)

// ExampleWithExcludeLabels shows how to assert that a compliance
// output does NOT receive pii-labelled fields. The recorder acts as
// the compliance destination; labels defined in the taxonomy drive
// the strip.
func ExampleWithExcludeLabels() {
	t := &testing.T{}

	auditor, events, _ := audittest.New(t, exampleSensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder", "pii"),
	)

	_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"email":    "alice@example.com",
	}))

	evt := events.Events()[0]
	fmt.Println("actor_id:", evt.StringField("actor_id"))
	fmt.Println("email present:", evt.Field("email") != nil)
	// Output:
	// actor_id: alice
	// email present: false
}
