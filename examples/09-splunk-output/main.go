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

// Example 21: Splunk HEC Output
//
// Demonstrates sending audit events to a Splunk Enterprise instance
// via the HTTP Event Collector, with the CIM Change formatter for
// CIM-compliant indexed-time field extraction and the reference TA
// (deploy/splunk-ta-axonops-audit/) for tag application.
//
// Prerequisites — local Splunk container (x86 only; Splunk does not
// publish an arm64 image):
//
//	docker run -d --name splunk \
//	  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
//	  -e SPLUNK_PASSWORD=ChangeMeForRealUse123! \
//	  -e SPLUNK_START_ARGS=--accept-license \
//	  -e SPLUNK_HEC_TOKEN=example-hec-token \
//	  -e SPLUNK_HEC_SSL=False \
//	  splunk/splunk:10.4-rhel9
//
//	# Wait for HEC to come up (Splunk's startup takes 2–3 minutes):
//	until curl -s http://localhost:8088/services/collector/health \
//	  | grep -q 'HEC is healthy'; do sleep 5; done
//
// Run:
//
//	go generate ./...
//	go run .
//
// Search events in Splunk Web at http://localhost:8000 (admin /
// ChangeMeForRealUse123!), or via the management API:
//
//	curl -s -k -u admin:'ChangeMeForRealUse123!' \
//	  'https://localhost:8089/services/search/jobs/export' \
//	  --data-urlencode 'search=search index=main sourcetype="axonops:audit" | head 20' \
//	  --data-urlencode 'exec_mode=oneshot' \
//	  --data-urlencode 'output_mode=json' | jq '.result'
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"time"

	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
	_ "github.com/axonops/audit/splunk"  // register splunk separately (future releases of audit/outputs will include it)
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("close auditor: %v", err)
		}
	}()

	// Account events — categorised "account", tagged `change` by the TA.
	if err := auditor.AuditEvent(
		NewUserCreateEvent("alice", "success", "topic-orders", "topic"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: user_create by alice")

	if err := auditor.AuditEvent(
		NewUserUpdateEvent("alice", "success", "topic-orders"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: user_update by alice")

	// Security events — categorised "security", tagged BOTH `change`
	// and `authentication` by the TA's per-category tag mapping.
	if err := auditor.AuditEvent(
		NewLoginSuccessEvent("alice", "success", "10.0.0.42"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: login_success by alice")

	// NewLoginFailureEvent(actorID, outcome, reason, sourceIP) — generated args are alphabetised.
	if err := auditor.AuditEvent(
		NewLoginFailureEvent("mallory", "failure", "invalid_password", "203.0.113.7"),
	); err != nil {
		log.Printf("audit: %v", err)
	}
	fmt.Println("Audited: login_failure by mallory")

	// Give the batch loop time to deliver before we close.
	//
	// 2s is twice the outputs.yaml flush_interval (1s) and well
	// above the typical HEC POST round-trip. Production code does
	// NOT need this sleep — `auditor.Close()` blocks until the
	// drain goroutine flushes the queue (capped by ShutdownTimeout,
	// default 5s). The sleep is here only so the example can print
	// the "Done. Search your events:" guidance AFTER delivery has
	// almost certainly completed, giving the reader an unambiguous
	// signal that the events should be searchable.
	//
	// If you change `flush_interval` or `ack_mode` to `required`,
	// raise this value accordingly — the demo coupling is intentional.
	fmt.Println("\nWaiting for Splunk delivery...")
	time.Sleep(2 * time.Second)

	fmt.Println("Done. Search your events:")
	fmt.Println(`  # All events from this app:`)
	fmt.Println(`  curl -s -k -u admin:'ChangeMeForRealUse123!' \`)
	fmt.Println(`    'https://localhost:8089/services/search/jobs/export' \`)
	fmt.Println(`    --data-urlencode 'search=search index=main sourcetype="axonops:audit" app_name="audit-example-splunk"' \`)
	fmt.Println(`    --data-urlencode 'exec_mode=oneshot' --data-urlencode 'output_mode=json' | jq '.result'`)
	fmt.Println()
	fmt.Println(`  # Only security category events (tag=authentication via the reference TA):`)
	fmt.Println(`  # ... search=search index=main tag=authentication ...`)
	fmt.Println()
	fmt.Println(`  # Or open Splunk Web: http://localhost:8000 (admin / ChangeMeForRealUse123!)`)
}
