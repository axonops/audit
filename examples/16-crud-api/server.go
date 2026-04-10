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
	"strings"

	audit "github.com/axonops/go-audit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// routeTable maps "METHOD resource" or "METHOD resource/{id}" to audit
// event types. IMPORTANT: when adding routes below, also add the event
// mapping here.
var routeTable = map[string]string{
	// Items
	"GET items":         EventItemList,
	"GET items/{id}":    EventItemRead,
	"POST items":        EventItemCreate,
	"PUT items/{id}":    EventItemUpdate,
	"DELETE items/{id}": EventItemDelete,
	// Users
	"GET users":         EventUserList,
	"GET users/{id}":    EventUserRead,
	"POST users":        EventUserCreate,
	"PUT users/{id}":    EventUserUpdate,
	"DELETE users/{id}": EventUserDelete,
	// Orders
	"GET orders":      EventOrderList,
	"GET orders/{id}": EventOrderRead,
	"POST orders":     EventOrderCreate,
	"PUT orders/{id}": EventOrderUpdate,
}

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

	// Item routes.
	mux.HandleFunc("GET /items", h.listItems)
	mux.HandleFunc("GET /items/{id}", h.getItem)
	mux.HandleFunc("POST /items", h.createItem)
	mux.HandleFunc("PUT /items/{id}", h.updateItem)
	mux.HandleFunc("DELETE /items/{id}", h.deleteItem)

	// User routes.
	mux.HandleFunc("GET /users", h.listUsers)
	mux.HandleFunc("GET /users/{id}", h.getUser)
	mux.HandleFunc("POST /users", h.createUser)
	mux.HandleFunc("PUT /users/{id}", h.updateUser)
	mux.HandleFunc("DELETE /users/{id}", h.deleteUser)

	// Order routes.
	mux.HandleFunc("GET /orders", h.listOrders)
	mux.HandleFunc("GET /orders/{id}", h.getOrder)
	mux.HandleFunc("POST /orders", h.createOrder)
	mux.HandleFunc("PUT /orders/{id}", h.updateOrder)

	// Apply middleware: auth first, then audit.
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

	return eventType, collectFields(hints, transport), false
}

// collectFields builds the audit Fields map from hints and transport metadata.
func collectFields(hints *audit.Hints, transport *audit.TransportMetadata) audit.Fields {
	fields := audit.Fields{
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

	// Copy Extra fields (e.g., PII fields like email, phone) so they
	// flow through sensitivity filtering in the output pipeline.
	for k, v := range hints.Extra {
		fields[k] = v
	}

	return fields
}

// mapHTTPToEvent maps HTTP method + resolved path to an audit event type
// using the routeTable. Returns empty string for unrecognised routes.
func mapHTTPToEvent(method, path string) string {
	resource, hasID := parseResource(path)
	if resource == "" {
		return ""
	}

	key := method + " " + resource
	if hasID {
		key += "/{id}"
	}
	return routeTable[key]
}

// parseResource extracts the resource name and whether an ID segment is
// present from a URL path. "/users" → ("users", false),
// "/users/abc-123" → ("users", true).
func parseResource(path string) (resource string, hasID bool) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	return parts[0], len(parts) >= 2 && parts[1] != ""
}
