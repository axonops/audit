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
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("close logger: %v", closeErr)
		}
	}()

	// 4. Emit events.
	fmt.Println("--- Security event (HMAC in secure_log, plain on stdout) ---")
	if auditErr := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":   "failure",
		"actor_id":  "unknown",
		"reason":    "invalid credentials",
		"source_ip": "192.168.1.100",
	})); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	fmt.Println("\n--- Write event (stdout only, no HMAC cost) ---")
	if auditErr := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"actor_id":  "admin",
		"target_id": "user-42",
	})); auditErr != nil {
		log.Printf("audit error: %v", auditErr)
	}

	fmt.Println("\n--- Check secure-audit.log for HMAC fields (_hmac, _hmac_v) ---")
}
