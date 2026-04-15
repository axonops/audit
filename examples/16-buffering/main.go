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

// Example 18: Buffering and Backpressure
//
// Demonstrates the two-level buffering architecture:
//
//   - Level 1 (core buffer): a tiny buffer_size triggers ErrBufferFull
//     when events are produced faster than the drain goroutine can process.
//   - Level 2 (webhook buffer): an unreachable webhook endpoint fills
//     the per-output buffer, triggering silent drops with metrics.
//
// The file output writes synchronously — it has no internal buffer.
// The webhook output has its own buffer and batch goroutine.
//
// Run:
//
//	go run .
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register "file" output type
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/webhook" // register "webhook" output type
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse taxonomy.
	// Single-call facade: parse taxonomy, load outputs, create logger.
	logger, err := outputconfig.NewLogger(context.Background(), taxonomyYAML, "outputs.yaml", nil)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// --- Level 1: Core Buffer Backpressure ---
	//
	// The core buffer is set to 5 (outputs.yaml: logger.buffer_size: 5).
	// We emit 20 events in a tight loop. The drain goroutine processes
	// events sequentially, so some AuditEvent() calls will find the
	// channel full and return ErrBufferFull.
	fmt.Println("--- Level 1: Core Buffer (buffer_size: 5) ---")
	fmt.Println("Emitting 20 events in a tight loop...")

	var delivered, dropped int
	for i := range 20 {
		actor := fmt.Sprintf("user-%d", i)
		evt := NewUserCreateEvent(actor, "success")
		if auditErr := logger.AuditEvent(evt); auditErr != nil {
			if errors.Is(auditErr, audit.ErrBufferFull) {
				dropped++
			} else {
				log.Printf("unexpected error: %v", auditErr)
			}
		} else {
			delivered++
		}
	}

	fmt.Printf("  Delivered: %d, Dropped (ErrBufferFull): %d\n", delivered, dropped)
	if dropped > 0 {
		fmt.Println("  → Core buffer was full. In production, increase logger.buffer_size")
		fmt.Println("    or investigate slow synchronous outputs blocking the drain goroutine.")
	}

	// --- Level 2: Per-Output Buffer Drops ---
	//
	// The webhook output points at http://localhost:19999 — nothing is
	// listening. The webhook's batch goroutine will attempt to POST,
	// fail, retry once, then drop the batch. When the webhook's internal
	// buffer (buffer_size: 10) fills, subsequent events are dropped
	// silently with a rate-limited slog.Warn.
	//
	// The file output is unaffected — it writes synchronously and
	// succeeds. Events dropped by the webhook are still delivered to
	// the file.
	fmt.Println("\n--- Level 2: Webhook Buffer (buffer_size: 10) ---")
	fmt.Println("The webhook points at an unreachable endpoint.")
	fmt.Println("Watch stderr for drop warnings from the webhook output.")
	fmt.Println("The file output (synchronous) is unaffected.")

	// Give the drain goroutine time to process the first burst and
	// let the webhook's batch loop attempt delivery.
	time.Sleep(3 * time.Second)

	// --- Summary ---
	fmt.Println("\n--- Buffering Architecture Summary ---")
	fmt.Print(`
Two levels of buffering exist in the pipeline:

  Level 1: Core Logger Buffer
    AuditEvent() → channel (logger.buffer_size) → drain goroutine
    Drop signal: ErrBufferFull returned to caller
    Tuning: increase logger.buffer_size (default 10,000)

  Level 2: Per-Output Buffer (webhook, Loki only)
    Drain goroutine → output channel (output buffer_size) → batch loop → HTTP
    Drop signal: RecordWebhookDrop / RecordLokiDrop metric + slog.Warn
    Tuning: increase output buffer_size, decrease flush_interval

  Synchronous outputs (file, syslog, stdout) have NO Level 2 buffer.
  They write directly from the drain goroutine.

See docs/async-delivery.md for the full architecture reference.
`)

	// Close flushes remaining events. The file output will have all
	// delivered events. The webhook will have dropped most of them.
	if closeErr := logger.Close(); closeErr != nil {
		log.Printf("close: %v", closeErr)
	}

	fmt.Println("Check the audit file for delivered events:")
	fmt.Println("  cat audit-buffering-demo.log | head -5")
	fmt.Println("  cat audit-buffering-demo.log | wc -l")
	fmt.Println("  rm audit-buffering-demo.log  # clean up when done")
}
