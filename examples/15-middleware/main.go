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

// Middleware demonstrates automatic HTTP audit logging: the audit
// middleware captures transport metadata (method, path, status, duration),
// handlers populate domain hints (actor, outcome), and health checks are
// skipped.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	audit "github.com/axonops/go-audit"
)

// buildEvent is the EventBuilder callback. The middleware calls it after
// every request with the handler's hints and the captured transport
// metadata. Returning skip=true suppresses the audit event.
func buildEvent(hints *audit.Hints, transport *audit.TransportMetadata) (eventType string, fields audit.Fields, skip bool) {
	// Skip health checks — no audit noise.
	if transport.Path == "/healthz" {
		return "", nil, true
	}

	fields = audit.Fields{
		"outcome":     hints.Outcome,
		"method":      transport.Method,
		"path":        transport.Path,
		"status_code": transport.StatusCode,
		"source_ip":   transport.ClientIP,
		"duration_ms": transport.Duration.Milliseconds(),
	}
	if hints.ActorID != "" {
		fields["actor_id"] = hints.ActorID
	}
	if hints.TargetID != "" {
		fields["target_id"] = hints.TargetID
	}
	// In production, use a generated constant from audit-gen instead of
	// the raw string (see example 02-code-generation for the full pattern).
	return "http_request", fields, false
}

func main() {
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"access": {Events: []string{"http_request"}},
		},
		Events: map[string]*audit.EventDef{
			"http_request": {
				Required: []string{"outcome", "method", "path"},
				Optional: []string{"status_code", "duration_ms"},
			},
		},
	}

	// Capture audit output in a buffer so we can print it at the end.
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatalf("create stdout: %v", err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatalf("create logger: %v", err)
	}

	// Set up HTTP routes.
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /items", func(w http.ResponseWriter, r *http.Request) {
		// Populate domain hints — the middleware reads these back.
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.ActorID = "alice"
			hints.Outcome = "success"
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"1","name":"widget"}]`))
	})

	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.ActorID = "alice"
			hints.Outcome = "success"
			hints.TargetID = "item-42"
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"42","name":"new-widget"}`))
	})

	// Wrap with audit middleware.
	handler := audit.Middleware(logger, buildEvent)(mux)

	// Start a test server and make programmatic requests.
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()
	makeRequest(client, "GET", server.URL+"/healthz")
	makeRequest(client, "GET", server.URL+"/items")
	makeRequest(client, "POST", server.URL+"/items")

	// Close the logger to flush buffered events.
	if err := logger.Close(); err != nil {
		log.Printf("close logger: %v", err)
	}

	// Print the captured audit events.
	fmt.Println("--- Audit events ---")
	fmt.Print(buf.String())
	fmt.Println("\nNote: /healthz produced no audit event (skipped by EventBuilder).")
}

func makeRequest(client *http.Client, method, reqURL string) {
	req, err := http.NewRequestWithContext(context.Background(), method, reqURL, http.NoBody)
	if err != nil {
		log.Printf("create request: %v", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("%s %s: %v", method, reqURL, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	fmt.Printf("%s %s -> %d\n", method, reqURL, resp.StatusCode)
}
