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

// Basic demonstrates the minimum viable audit event: create a logger
// with an inline taxonomy, emit one valid event, and show what happens
// when a required field is missing.
package main

import (
	"fmt"
	"log"

	audit "github.com/axonops/go-audit"
)

func main() {
	// 1. Define a taxonomy inline. In production you would load this
	//    from a YAML file — see the code-generation example.
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create", "user_delete"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Required: []string{"outcome", "actor_id"},
			},
			"user_delete": {
				Required: []string{"outcome", "actor_id"},
			},
			"auth_failure": {
				Required: []string{"outcome", "actor_id"},
			},
		},
		DefaultEnabled: []string{"write", "security"},
	}

	// 2. Create a stdout output — events are printed as JSON lines.
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		log.Fatalf("create stdout output: %v", err)
	}

	// 3. Create the logger with the taxonomy and output.
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

	// 4. Emit a valid event — this prints a JSON line to stdout.
	fmt.Println("--- Valid event ---")
	if auditErr := logger.Audit("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	// 5. Emit an invalid event — actor_id is missing (required by taxonomy).
	fmt.Println("\n--- Invalid event (missing required field) ---")
	err = logger.Audit("user_create", audit.Fields{
		"outcome": "success",
		// actor_id intentionally omitted
	})
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}
}
