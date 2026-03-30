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

// Event-routing demonstrates per-output filtering: security events go
// to one file, write events go to another, and stdout gets everything.
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
			"read":     {"user_read"},
			"security": {"auth_failure"},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Category: "write",
				Required: []string{"outcome", "actor_id"},
			},
			"user_read": {
				Category: "read",
				Required: []string{"outcome"},
			},
			"auth_failure": {
				Category: "security",
				Required: []string{"outcome", "actor_id"},
			},
		},
		DefaultEnabled: []string{"write", "read", "security"},
	}

	// Create three outputs with different routing rules.
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		log.Fatalf("create stdout: %v", err)
	}

	securityFile, err := file.New(file.Config{Path: "./security.log"}, nil)
	if err != nil {
		log.Fatalf("create security file: %v", err)
	}

	writesFile, err := file.New(file.Config{Path: "./writes.log"}, nil)
	if err != nil {
		log.Fatalf("create writes file: %v", err)
	}

	// WithNamedOutput wires each output with an optional route and formatter.
	// WrapOutput gives each output a human-readable name for metrics and logs.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		// Console: nil route = receives ALL events.
		audit.WithNamedOutput(audit.WrapOutput(stdout, "console"), nil, nil),
		// security.log: only security events.
		audit.WithNamedOutput(
			audit.WrapOutput(securityFile, "security_log"),
			&audit.EventRoute{IncludeCategories: []string{"security"}},
			nil,
		),
		// writes.log: only write events.
		audit.WithNamedOutput(
			audit.WrapOutput(writesFile, "writes_log"),
			&audit.EventRoute{IncludeCategories: []string{"write"}},
			nil,
		),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Emit one event per category.
	_ = logger.Audit("user_create", audit.Fields{"outcome": "success", "actor_id": "alice"})
	_ = logger.Audit("user_read", audit.Fields{"outcome": "success"})
	_ = logger.Audit("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "unknown"})

	if err := logger.Close(); err != nil {
		log.Printf("close logger: %v", err)
	}

	// Show filtered output.
	printFile("security.log")
	printFile("writes.log")

	// Clean up.
	_ = os.Remove("./security.log")
	_ = os.Remove("./writes.log")
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
