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

// HMAC Integrity demonstrates per-output HMAC tamper detection.
// Security events go to a file with HMAC enabled; all events go to
// stdout without HMAC. Only security events pay the crypto cost.
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
	// 1. Parse taxonomy.
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	// 2. Load output configuration (includes HMAC settings).
	result, err := outputconfig.Load(outputsYAML, &tax, nil)
	if err != nil {
		log.Fatalf("load outputs: %v", err)
	}

	// 3. Create logger.
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)

	logger, err := audit.NewLogger(result.Config, opts...)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// 4. Emit events using generated typed builders.

	// Security event — goes to all three outputs:
	//   secure_log:      HMAC (routed by category)
	//   tamperproof_log: HMAC (receives all events)
	//   console:         no HMAC
	fmt.Println("--- Security event ---")
	authEvt := NewAuthFailureEvent("unknown", "failure")
	authEvt.Fields()["reason"] = "invalid credentials"
	authEvt.Fields()["source_ip"] = "192.168.1.100"
	if auditErr := logger.AuditEvent(authEvt); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	// Write event — goes to two outputs:
	//   secure_log:      SKIPPED (route excludes write category)
	//   tamperproof_log: HMAC (receives all events)
	//   console:         no HMAC
	fmt.Println("\n--- Write event ---")
	userEvt := NewUserCreateEvent("admin", "success")
	userEvt.Fields()["target_id"] = "user-42"
	if auditErr := logger.AuditEvent(userEvt); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	fmt.Println("\n--- Compare the three outputs below ---")

	// Close the logger to flush all events before reading files.
	if closeErr := logger.Close(); closeErr != nil {
		log.Printf("close logger: %v", closeErr)
	}

	// Show what landed in each file.
	printFile("secure-audit.log")
	printFile("all-audit.log")

	// Clean up.
	_ = os.Remove("secure-audit.log")
	_ = os.Remove("all-audit.log")
}

func printFile(name string) {
	data, err := os.ReadFile(name) //nolint:gosec // example reads its own output files
	if err != nil {
		log.Printf("read %s: %v", name, err)
		return
	}
	fmt.Printf("\n--- %s ---\n%s", name, data)
}
