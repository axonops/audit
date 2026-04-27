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

// Code Generation demonstrates audit-gen typed builders: compile-time
// safety for event types, required fields, and sensitivity labels.
//
// Run:
//
//	go generate ./...
//	go run .
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() { _ = auditor.Close() }()

	fmt.Println("--- Using typed event builders ---")

	// All event types, field names, and categories are generated constants.
	// A typo like "NewUserCrateEvent" would fail at compile time.
	if auditErr := auditor.AuditEvent(
		NewUserCreateEvent("alice", "success").
			SetTargetID("user-42"),
	); auditErr != nil {
		log.Printf("audit: %v", auditErr)
	}

	// Reserved standard fields (reason, source_ip, …) get typed
	// setters on every generated builder.
	if auditErr := auditor.AuditEvent(
		NewAuthFailureEvent("unknown", "failure").
			SetReason("invalid credentials").
			SetSourceIP("192.168.1.100"),
	); auditErr != nil {
		log.Printf("audit: %v", auditErr)
	}

	// Reserved standard fields (here, actor_id) are typed even when not
	// declared in the event's taxonomy fields.
	if auditErr := auditor.AuditEvent(
		NewUserReadEvent("success").
			SetActorID("bob"),
	); auditErr != nil {
		log.Printf("audit: %v", auditErr)
	}
}
