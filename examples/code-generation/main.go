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

// Code-generation demonstrates the audit-gen workflow: define events in
// a YAML taxonomy, generate type-safe Go constants, and use them to
// eliminate string-literal errors at compile time.
package main

import (
	_ "embed"
	"fmt"
	"log"

	audit "github.com/axonops/go-audit"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse the embedded taxonomy YAML at startup.
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		log.Fatalf("create stdout: %v", err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("close logger: %v", closeErr)
		}
	}()

	// All event types, field names, and categories are generated constants.
	// A typo like "EventUserCrate" would fail at compile time.
	fmt.Println("--- Using generated constants ---")

	if err := logger.Audit(EventUserCreate, audit.Fields{
		FieldOutcome:  "success",
		FieldActorID:  "alice",
		FieldTargetID: "user-42",
	}); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.Audit(EventAuthFailure, audit.Fields{
		FieldOutcome:  "failure",
		FieldActorID:  "unknown",
		FieldReason:   "invalid credentials",
		FieldSourceIP: "192.168.1.100",
	}); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.Audit(EventUserRead, audit.Fields{
		FieldOutcome: "success",
		FieldActorID: "bob",
	}); err != nil {
		log.Printf("audit error: %v", err)
	}
}
