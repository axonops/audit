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

// Sensitivity-labels demonstrates per-output field stripping: the same
// audit event is delivered to three outputs with different field subsets
// based on sensitivity labels.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

var logFiles = []string{"full-audit.log", "public-audit.log", "pci-audit.log"}

func main() {
	auditor := createAuditor()
	emitEvents(auditor)

	if err := auditor.Close(); err != nil {
		log.Printf("close auditor: %v", err)
	}

	printLogFiles()
	cleanupLogFiles()
}

func createAuditor() *audit.Auditor {
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	return auditor
}

func emitEvents(auditor *audit.Auditor) {
	if err := auditor.AuditEvent(NewUserCreateEvent("admin", "success").
		SetEmail("alice@example.com").
		SetPhone("555-0100").
		SetUserName("alice_smith").
		SetDepartment("engineering")); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := auditor.AuditEvent(NewPaymentProcessEvent("alice", "success").
		SetCardNumber("4111111111111111").
		SetCardExpiry("12/28").
		SetAmount("99.99")); err != nil {
		log.Printf("audit error: %v", err)
	}
}

func printLogFiles() {
	for _, name := range logFiles {
		fmt.Printf("\n--- %s ---\n", name)
		data, err := os.ReadFile(name) //nolint:gosec // example reads its own output files
		if err != nil {
			fmt.Printf("  (not created)\n")
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				fmt.Println(line)
			}
		}
	}
}

func cleanupLogFiles() {
	for _, name := range logFiles {
		_ = os.Remove(name)
	}
}
