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

// CRUD API is a complete REST API example demonstrating go-audit in a
// realistic application: Postgres-backed CRUD, five audit outputs with
// routing and formatting, HTTP middleware, Prometheus metrics, lifecycle
// events, and graceful shutdown.
package main

import (
	"context"
	_ "embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	audit "github.com/axonops/go-audit"
)

//go:generate go run github.com/axonops/go-audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// Parse taxonomy.
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		log.Fatalf("parse taxonomy: %v", err)
	}

	// Set up Prometheus metrics.
	metrics := newMetrics()

	// Set up audit logger with five outputs.
	logger, err := setupAuditLogger(tax, metrics)
	if err != nil {
		log.Fatalf("setup audit logger: %v", err)
	}

	// Emit startup event.
	if startupErr := logger.EmitStartup(audit.Fields{
		FieldAppName: "crud-api",
		FieldVersion: "0.1.0",
	}); startupErr != nil {
		log.Printf("emit startup: %v", startupErr)
	}

	// Connect to Postgres.
	db, err := connectDB()
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	defer func() { _ = db.Close() }()

	if schemaErr := createSchema(db); schemaErr != nil {
		log.Fatalf("create schema: %v", schemaErr) //nolint:gocritic // db.Close deferred above; Fatalf is acceptable for startup failures
	}

	// Build HTTP server.
	addr := envOr("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           newServer(logger, db, metrics),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("listening on %s", addr)
		if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			log.Fatalf("listen: %v", listenErr)
		}
	}()

	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("http shutdown: %v", err)
	}

	// Close logger — this emits the shutdown event and flushes all outputs.
	if err := logger.Close(); err != nil {
		log.Printf("close logger: %v", err)
	}

	log.Println("shutdown complete")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
