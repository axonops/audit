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
	_ = auditor.Close()

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
	_ = auditor.Close()

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
	_ = auditor.Close()

	creates := events.FindByType("user_create")
	fmt.Println("user_create count:", len(creates))
	fmt.Println("auth_failure count:", len(events.FindByType("auth_failure")))
	// Output:
	// user_create count: 2
	// auth_failure count: 1
}
