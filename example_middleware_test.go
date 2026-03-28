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

package audit_test

import (
	"fmt"
	"log"
	"net/http"

	"github.com/axonops/go-audit"
)

func ExampleMiddleware() {
	taxonomy := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"access": {"http_request"},
		},
		Events: map[string]audit.EventDef{
			"http_request": {
				Category: "access",
				Required: []string{"outcome"},
				Optional: []string{"actor_id", "method", "path", "status_code"},
			},
		},
		DefaultEnabled: []string{"access"},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(taxonomy),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	// The EventBuilder transforms per-request hints into an audit event.
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "http_request", audit.Fields{
			"outcome":     hints.Outcome,
			"method":      transport.Method,
			"path":        transport.Path,
			"status_code": transport.StatusCode,
		}, false
	}

	mw := audit.Middleware(logger, builder)
	_ = mw // wrap your http.Handler with mw(handler)

	fmt.Println("middleware created")
	// Output: middleware created
}

func ExampleHintsFromContext() {
	// Inside an HTTP handler wrapped by Middleware:
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.HintsFromContext(r.Context())
		if hints != nil {
			hints.ActorID = "user-42"
			hints.Outcome = "success"
			hints.TargetType = "document"
			hints.TargetID = "doc-99"
		}
		w.WriteHeader(http.StatusOK)
	})

	_ = handler // register with your router

	fmt.Println("handler with hints")
	// Output: handler with hints
}

func ExampleMiddleware_skip() {
	taxonomy := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"access": {"http_request"},
		},
		Events: map[string]audit.EventDef{
			"http_request": {
				Category: "access",
				Required: []string{"outcome"},
				Optional: []string{"path"},
			},
		},
		DefaultEnabled: []string{"access"},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(taxonomy),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	// Skip health-check endpoints to reduce noise.
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		if transport.Path == "/healthz" || transport.Path == "/readyz" {
			return "", nil, true // skip
		}
		return "http_request", audit.Fields{
			"outcome": hints.Outcome,
			"path":    transport.Path,
		}, false
	}

	mw := audit.Middleware(logger, builder)
	_ = mw

	fmt.Println("skip middleware created")
	// Output: skip middleware created
}

func ExampleMiddleware_router() {
	// Middleware works with any router that supports
	// the func(http.Handler) http.Handler middleware pattern.
	//
	//   // net/http
	//   mux := http.NewServeMux()
	//   mux.Handle("/", handler)
	//   http.ListenAndServe(":8080", mw(mux))
	//
	//   // chi
	//   r := chi.NewRouter()
	//   r.Use(mw)
	//
	//   // gorilla/mux
	//   r := mux.NewRouter()
	//   r.Use(mw)

	fmt.Println("works with any router")
	// Output: works with any router
}
