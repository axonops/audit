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

// Example 08: Loki Output
//
// Demonstrates sending audit events to Grafana Loki with stream labels,
// gzip compression, and multi-tenant support.
//
// Prerequisites:
//
//	docker run -d --name loki -p 3100:3100 grafana/loki:3.0.0
//
// Run:
//
//	go run .
//
// Query events in Loki:
//
//	curl -s 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=10' | jq .
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	audit "github.com/axonops/go-audit"
	_ "github.com/axonops/go-audit/loki" // register "loki" output type
	"github.com/axonops/go-audit/outputconfig"
)

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse taxonomy.
	// Single-call facade: parse taxonomy, load outputs, create logger.
	logger, err := outputconfig.NewLogger(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			log.Printf("close logger: %v", err)
		}
	}()

	// Audit some events — these will appear in Loki with stream labels.
	// In production, use generated typed builders from audit-gen instead
	// of raw event types and Fields maps (see example 02-code-generation).
	type auditEvent struct {
		fields    audit.Fields
		eventType string
	}
	events := []auditEvent{
		// Categorised events (in "write" or "security" categories):
		{audit.Fields{"outcome": "success", "actor_id": "alice", "resource_id": "user-42"}, "user_create"},
		{audit.Fields{"outcome": "success", "actor_id": "bob", "resource_id": "user-43"}, "user_create"},
		{audit.Fields{"outcome": "failure", "actor_id": "mallory", "reason": "invalid_password"}, "auth_failure"},
		{audit.Fields{"outcome": "failure", "actor_id": "mallory", "resource": "admin_panel"}, "permission_denied"},
		{audit.Fields{"outcome": "success", "actor_id": "alice", "resource_id": "user-42"}, "user_update"},
		// Uncategorised event (not in any category — no event_category label in Loki):
		{audit.Fields{"outcome": "success", "actor_id": "alice", "component": "database"}, "health_check"},
		{audit.Fields{"outcome": "success", "actor_id": "bob", "component": "cache"}, "health_check"},
	}

	for _, e := range events {
		if err := logger.AuditEvent(audit.NewEvent(e.eventType, e.fields)); err != nil {
			log.Printf("audit %s: %v", e.eventType, err)
			continue
		}
		fmt.Printf("Audited: %s by %s\n", e.eventType, e.fields["actor_id"])
	}

	// Wait for the flush interval to deliver the batch.
	fmt.Println("\nWaiting for Loki delivery...")
	time.Sleep(2 * time.Second)

	fmt.Println("Done. Query your events:")
	fmt.Println(`  # All events (categorised + uncategorised):`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=20' | jq .`)
	fmt.Println(`  # Only categorised "write" events:`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={event_category="write"}&limit=10' | jq .`)
	fmt.Println(`  # Only uncategorised events (no event_category label):`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+event_category=""&limit=10' | jq .`)
	fmt.Println(`  # All events by alice (across all categories):`)
	fmt.Println(`  curl -s -H 'X-Scope-OrgID: example' 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}+|+json+|+actor_id="alice"&limit=10' | jq .`)
}
