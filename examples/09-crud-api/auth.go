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
	"net/http"

	audit "github.com/axonops/go-audit"
)

// authMiddleware validates the X-API-Key header and populates audit
// hints with the authenticated identity. Unauthenticated requests to
// protected endpoints receive 401 and emit an auth_failure event via
// the audit middleware's Hints mechanism — no direct logger.Audit call.
func authMiddleware() func(http.Handler) http.Handler {
	// In production this would be backed by a database or identity provider.
	users := map[string]string{
		"key-alice": "alice",
		"key-bob":   "bob",
		"key-admin": "admin",
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health and metrics endpoints.
			if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			hints := audit.HintsFromContext(r.Context())
			apiKey := r.Header.Get("X-API-Key")

			userID, ok := users[apiKey]
			if !ok {
				// Record auth failure in hints for the audit middleware.
				if hints != nil {
					hints.EventType = EventAuthFailure
					hints.Outcome = "failure"
					actorID := apiKey
					if actorID == "" {
						actorID = "anonymous"
					}
					hints.ActorID = actorID
					hints.Reason = "invalid API key"
				}
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Populate hints with authenticated identity.
			if hints != nil {
				hints.ActorID = userID
				hints.AuthMethod = "api_key"
				hints.Outcome = "success"
			}

			next.ServeHTTP(w, r)
		})
	}
}
