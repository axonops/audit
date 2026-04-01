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

// Formatters demonstrates JSON vs CEF output side by side: the same
// events are written to two files with different formatters configured
// in outputs.yaml.
package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"

	audit "github.com/axonops/go-audit"
	_ "github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/outputconfig"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

//go:embed outputs.yaml
var outputsYAML []byte

func main() {
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

	// Emit events.
	if err := logger.AuditEvent(audit.NewEvent(EventUserCreate, audit.Fields{
		FieldOutcome: "success",
		FieldActorID: "alice",
	})); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.AuditEvent(audit.NewEvent(EventAuthFailure, audit.Fields{
		FieldOutcome: "failure",
		FieldActorID: "unknown",
	})); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.AuditEvent(audit.NewEvent(EventAuthSuccess, audit.Fields{
		FieldOutcome: "success",
		FieldActorID: "bob",
	})); err != nil {
		log.Printf("audit error: %v", err)
	}

	if err := logger.Close(); err != nil {
		log.Printf("close logger: %v", err)
	}

	// Print both files side by side.
	printFile("json-audit.log")
	printFile("cef-audit.log")

	// Clean up.
	_ = os.Remove("./json-audit.log")
	_ = os.Remove("./cef-audit.log")
}

func printFile(name string) {
	data, err := os.ReadFile(name) //nolint:gosec // name is always a hardcoded literal
	if err != nil {
		log.Printf("read %s: %v", name, err)
		return
	}
	fmt.Printf("\n--- %s ---\n", name)
	fmt.Print(string(data))
}
