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
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"

	audit "github.com/axonops/go-audit"
	_ "github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/outputconfig"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

//go:embed outputs.yaml
var outputsYAML []byte

var logFiles = []string{"full-audit.log", "public-audit.log", "pci-audit.log"}

func main() {
	logger := createLogger()
	emitEvents(logger)

	if err := logger.Close(); err != nil {
		log.Printf("close logger: %v", err)
	}

	printLogFiles()
	cleanupLogFiles()
}

func createLogger() *audit.Logger {
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}
	result, err := outputconfig.Load(outputsYAML, &tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	return logger
}

func emitEvents(logger *audit.Logger) {
	if err := logger.AuditEvent(audit.NewEvent(EventUserCreate, audit.Fields{
		FieldOutcome:    "success",
		FieldActorID:    "admin",
		FieldEmail:      "alice@example.com",
		FieldPhone:      "555-0100",
		FieldUserName:   "alice_smith",
		FieldDepartment: "engineering",
	})); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.AuditEvent(audit.NewEvent(EventPaymentProcess, audit.Fields{
		FieldOutcome:    "success",
		FieldActorID:    "alice",
		FieldCardNumber: "4111111111111111",
		FieldCardExpiry: "12/28",
		FieldAmount:     "99.99",
	})); err != nil {
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
