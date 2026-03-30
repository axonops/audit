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
			"write": {"user_create"},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Category: "write",
				Required: []string{"outcome", "actor_id"},
			},
		},
		DefaultEnabled: []string{"write"},
	}

	// Create a file output with rotation settings.
	// - MaxSizeMB: rotate when file exceeds 10 MB
	// - MaxBackups: keep 3 rotated files
	// - Permissions: only owner can read/write (0600)
	fileOut, err := file.New(file.Config{
		Path:        "./audit.log",
		MaxSizeMB:   10,
		MaxBackups:  3,
		Permissions: "0600",
	}, nil) // nil = no file-specific metrics
	if err != nil {
		log.Fatalf("create file output: %v", err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(fileOut),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Emit five events.
	users := []string{"alice", "bob", "carol", "dave", "eve"}
	for _, user := range users {
		if auditErr := logger.Audit("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": user,
		}); auditErr != nil {
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
