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

// Stdout-output demonstrates the simplest possible output: writing
// audit events to standard output. No external dependencies, no
// additional blank imports, no type-specific configuration.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/outputconfig"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

//go:embed outputs.yaml
var outputsYAML []byte

func main() {
	// 1. Parse the taxonomy.
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	// 2. Load output configuration — stdout needs no blank import.
	result, err := outputconfig.Load(context.Background(), outputsYAML, tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}

	// 3. Create the logger.
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)

	logger, err := audit.NewLogger(opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// 4. Emit audit events — they appear on stdout as JSON.
	events := []audit.Event{
		NewAuthLoginEvent("alice", "password", "success"),
		NewUserCreateEvent("alice", "success", "user-42"),
		NewAuthLogoutEvent("alice", "success"),
	}

	for _, e := range events {
		if auditErr := logger.AuditEvent(e); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	// 5. Close flushes any buffered events.
	if closeErr := logger.Close(); closeErr != nil {
		log.Printf("close logger: %v", closeErr)
	}

	// Print tips to stderr so stdout remains clean JSON for piping.
	fmt.Fprintln(os.Stderr, "\n--- Tip: pipe to jq for pretty-printing ---")
	fmt.Fprintln(os.Stderr, "  go run . 2>/dev/null | jq .")
	fmt.Fprintln(os.Stderr, "  go run . 2>/dev/null | jq 'select(.event_type == \"auth_login\")'")
	fmt.Fprintln(os.Stderr, "  go run . 2>/dev/null | jq .  # 2>/dev/null suppresses this tip")
}
