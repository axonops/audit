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

// Multi-output demonstrates fan-out: a single Audit call delivers events
// to both stdout and a file simultaneously. Both outputs are configured
// in outputs.yaml.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/axonops/audit"
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

	// Emit events — each goes to both stdout and the file.
	events := []audit.Event{
		NewUserCreateEvent("alice", "success"),
		NewAuthFailureEvent("unknown", "failure"),
		NewUserCreateEvent("bob", "success"),
	}

	for _, evt := range events {
		if auditErr := auditor.AuditEvent(evt); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	if closeErr := auditor.Close(); closeErr != nil {
		log.Printf("close auditor: %v", closeErr)
	}

	// Show that the file also received all events.
	fmt.Println("\n--- Contents of audit.log ---")
	data, err := os.ReadFile("./audit.log")
	if err != nil {
		log.Fatalf("read audit.log: %v", err)
	}
	fmt.Print(string(data))

	_ = os.Remove("./audit.log")
}
