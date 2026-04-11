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

// File-output demonstrates writing audit events to a log file with
// automatic rotation, size limits, and restricted file permissions.
// Output configuration is loaded from outputs.yaml.
package main

import (
	"context"
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

	result, err := outputconfig.Load(context.Background(), outputsYAML, tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}

	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)

	logger, err := audit.NewLogger(opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Emit five events.
	users := []string{"alice", "bob", "carol", "dave", "eve"}
	for _, user := range users {
		if auditErr := logger.AuditEvent(NewUserCreateEvent(user, "success")); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	// Close flushes buffered events to disk.
	if closeErr := logger.Close(); closeErr != nil {
		log.Printf("close logger: %v", closeErr)
	}

	// Read and print the file contents.
	data, err := os.ReadFile("./audit.log")
	if err != nil {
		log.Fatalf("read audit.log: %v", err)
	}
	fmt.Println("--- Contents of audit.log ---")
	fmt.Print(string(data))

	// Clean up.
	_ = os.Remove("./audit.log")
}
