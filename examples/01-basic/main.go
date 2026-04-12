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

// Basic demonstrates the absolute minimum: a file-free logger that
// requires no YAML, no go:embed, and no output configuration. This is
// the fastest way to evaluate go-audit in a playground or single-file
// program. For production use, see examples 02+ which use YAML
// taxonomy and output configuration.
package main

import (
	"fmt"
	"log"

	"github.com/axonops/audit"
)

func main() {
	// Create a logger with a development taxonomy and stdout output.
	// DevTaxonomy accepts any event type with any fields — not for production.
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(audit.DevTaxonomy("user_create", "auth_failure")),
		audit.WithOutputs(audit.Stdout()),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Emit a valid event using slog-style key-value pairs.
	fmt.Println("--- Valid event ---")
	if auditErr := logger.AuditEvent(audit.NewEventKV("user_create",
		"outcome", "success",
		"actor_id", "alice",
	)); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	// Emit another event using the Fields map style.
	fmt.Println("\n--- Auth failure event ---")
	if auditErr := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "unknown",
	})); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}
}
