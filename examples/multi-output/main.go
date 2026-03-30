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
// to both stdout and a file simultaneously.
package main

import (
	"fmt"
	"log"
	"os"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

func main() {
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"write":    {"user_create"},
			"security": {"auth_failure"},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Category: "write",
				Required: []string{"outcome", "actor_id"},
			},
			"auth_failure": {
				Category: "security",
				Required: []string{"outcome", "actor_id"},
			},
		},
		DefaultEnabled: []string{"write", "security"},
	}

	// Create two outputs: stdout and a file.
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		log.Fatalf("create stdout output: %v", err)
	}

	fileOut, err := file.New(file.Config{
		Path:        "./audit.log",
		Permissions: "0600",
	}, nil)
	if err != nil {
		log.Fatalf("create file output: %v", err)
	}

	// WithOutputs accepts multiple outputs — every Audit call fans out
	// to all of them.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(stdout, fileOut),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Emit events — each goes to both stdout and the file.
	events := []struct {
		eventType string
		actorID   string
		outcome   string
	}{
		{"user_create", "alice", "success"},
		{"auth_failure", "unknown", "failure"},
		{"user_create", "bob", "success"},
	}

	for _, e := range events {
		if auditErr := logger.Audit(e.eventType, audit.Fields{
			"outcome":  e.outcome,
			"actor_id": e.actorID,
		}); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	if closeErr := logger.Close(); closeErr != nil {
		log.Printf("close logger: %v", closeErr)
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
