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

package main

import (
	"database/sql"
	"net/http"

	audit "github.com/axonops/go-audit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// newServer builds the HTTP mux with auth middleware, audit middleware,
// CRUD routes, health check, and Prometheus metrics endpoint.
func newServer(logger *audit.Logger, db *sql.DB, m *auditMetrics) http.Handler {
	mux := http.NewServeMux()

	h := &handlers{db: db}

	// Health check — no auth, no audit.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Prometheus metrics — no auth, no audit.
	mux.Handle("GET /metrics", promhttp.Handler())

	// CRUD routes — require auth.
	mux.HandleFunc("GET /items", h.listItems)
	mux.HandleFunc("GET /items/{id}", h.getItem)
	mux.HandleFunc("POST /items", h.createItem)
	mux.HandleFunc("PUT /items/{id}", h.updateItem)
	mux.HandleFunc("DELETE /items/{id}", h.deleteItem)

	// Apply middleware: auth first, then audit.
	// Audit middleware wraps the auth+route handler so it captures
	// the authenticated actor from hints.
	authed := authMiddleware()(mux)
	audited := audit.Middleware(logger, buildAuditEvent)(authed)

	return audited
}

// buildAuditEvent maps HTTP request metadata to audit events.
func buildAuditEvent(hints *audit.Hints, transport *audit.TransportMetadata) (eventType string, fields audit.Fields, skip bool) {
	// Skip health checks and metrics scrapes.
	if transport.Path == "/healthz" || transport.Path == "/metrics" {
		return "", nil, true
	}

	// If the auth middleware set an event type (e.g., auth_failure),
	// use that instead of the default.
	eventType = hints.EventType
	if eventType == "" {
		eventType = mapHTTPToEvent(transport.Method, transport.Path)
	}

	// Skip unknown routes (e.g., favicon.ico, undefined paths).
	if eventType == "" {
		return "", nil, true
	}

	fields = audit.Fields{
		FieldOutcome: hints.Outcome,
	}

	if hints.ActorID != "" {
		fields[FieldActorID] = hints.ActorID
	}
	if hints.TargetID != "" {
		fields[FieldTargetID] = hints.TargetID
	}
	// Error takes precedence over reason when both are set.
	if hints.Reason != "" {
		fields[FieldReason] = hints.Reason
	}
	if hints.Error != "" {
		fields[FieldReason] = hints.Error
	}
	if transport.ClientIP != "" {
		fields[FieldSourceIP] = transport.ClientIP
	}

	return eventType, fields, false
}

// mapHTTPToEvent maps HTTP method + path patterns to audit event types.
// Returns empty string for unrecognised routes (skipped by buildAuditEvent).
func mapHTTPToEvent(method, path string) string {
	switch {
	case method == "GET" && path == "/items":
		return EventItemList
	case method == "GET":
		return EventItemRead
	case method == "POST":
		return EventItemCreate
	case method == "PUT":
		return EventItemUpdate
	case method == "DELETE":
		return EventItemDelete
	default:
		return "" // unknown route — buildAuditEvent will still emit with empty type
	}
}
