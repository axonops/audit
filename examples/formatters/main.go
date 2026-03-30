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
// events are written to two files with different formatters, and a
// custom SeverityFunc maps security events to higher CEF severity.
package main

import (
	"fmt"
	"log"
	"os"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
)

// severityMap returns CEF severity based on the event's category.
// Security events get severity 8 (high); everything else gets 3 (low).
func severityMap(eventType string) int {
	switch eventType {
	case "auth_failure", "auth_success":
		return 8
	default:
		return 3
	}
}

func main() {
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"write":    {"user_create"},
			"security": {"auth_failure", "auth_success"},
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
			"auth_success": {
				Category: "security",
				Required: []string{"outcome", "actor_id"},
			},
		},
		DefaultEnabled: []string{"write", "security"},
	}

	// Two file outputs — same events, different formats.
	jsonFile, err := file.New(file.Config{Path: "./json-audit.log"}, nil)
	if err != nil {
		log.Fatalf("create json file: %v", err)
	}

	cefFile, err := file.New(file.Config{Path: "./cef-audit.log"}, nil)
	if err != nil {
		log.Fatalf("create cef file: %v", err)
	}

	// CEF formatter with custom severity mapping.
	cefFmt := &audit.CEFFormatter{
		Vendor:       "Example",
		Product:      "AuditDemo",
		Version:      "1.0",
		SeverityFunc: severityMap,
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		// JSON output: nil formatter uses the logger's default (JSON).
		audit.WithNamedOutput(audit.WrapOutput(jsonFile, "json_file"), nil, nil),
		// CEF output: per-output formatter override.
		audit.WithNamedOutput(audit.WrapOutput(cefFile, "cef_file"), nil, cefFmt),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Emit events.
	_ = logger.Audit("user_create", audit.Fields{"outcome": "success", "actor_id": "alice"})
	_ = logger.Audit("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "unknown"})
	_ = logger.Audit("auth_success", audit.Fields{"outcome": "success", "actor_id": "bob"})

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
