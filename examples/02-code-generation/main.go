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

// Code-generation demonstrates the recommended go-audit workflow:
// define events in a YAML taxonomy, generate type-safe Go constants
// with audit-gen, and configure outputs in a separate YAML file.
package main

import (
	_ "embed"
	"fmt"
	"log"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/outputconfig"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

//go:embed outputs.yaml
var outputsYAML []byte

func main() {
	// 1. Parse the embedded taxonomy.
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	// 2. Load output configuration from YAML.
	result, err := outputconfig.Load(outputsYAML, &tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}

	// 3. Create the logger with taxonomy + outputs.
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)

	logger, err := audit.NewLogger(result.Config, opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("close logger: %v", closeErr)
		}
	}()

	// All event types, field names, and categories are generated constants.
	// A typo like "NewUserCrateEvent" would fail at compile time.
	fmt.Println("--- Using typed event builders ---")

	createEvt := NewUserCreateEvent("alice", "success")
	createEvt.Fields()["target_id"] = "user-42"
	if err := logger.AuditEvent(createEvt); err != nil {
		log.Printf("audit error: %v", err)
	}

	authEvt := NewAuthFailureEvent("unknown", "failure")
	authEvt.Fields()["reason"] = "invalid credentials"
	authEvt.Fields()["source_ip"] = "192.168.1.100"
	if err := logger.AuditEvent(authEvt); err != nil {
		log.Printf("audit error: %v", err)
	}

	readEvt := NewUserReadEvent("success")
	readEvt.Fields()["actor_id"] = "bob"
	if err := logger.AuditEvent(readEvt); err != nil {
		log.Printf("audit error: %v", err)
	}
}
