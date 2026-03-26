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
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/axonops/go-audit"
)

func ExampleNewLogger() {
	taxonomy := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"write":    {"user_create"},
			"security": {"auth_failure"},
		},
		Events: map[string]audit.EventDef{
			"user_create":  {Category: "write", Required: []string{"outcome", "actor_id"}},
			"auth_failure": {Category: "security", Required: []string{"outcome", "actor_id"}},
		},
		DefaultEnabled: []string{"write", "security"},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(taxonomy),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("logger created")
	// Output: logger created
}

func ExampleLogger_Audit() {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    1,
			Categories: map[string][]string{"write": {"doc_create"}},
			Events: map[string]audit.EventDef{
				"doc_create": {Category: "write", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write"},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	if err = logger.Audit("doc_create", audit.Fields{"outcome": "success"}); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	fmt.Println("event emitted")
	// Output: event emitted
}

func ExampleLogger_MustHandle() {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    1,
			Categories: map[string][]string{"write": {"doc_create"}},
			Events: map[string]audit.EventDef{
				"doc_create": {Category: "write", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write"},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Get a handle for zero-allocation audit calls.
	docCreate := logger.MustHandle("doc_create")

	if err = docCreate.Audit(audit.Fields{"outcome": "success"}); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	fmt.Println("handle name:", docCreate.Name())
	// Output: handle name: doc_create
}

func ExampleLogger_EnableCategory() {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version: 1,
			Categories: map[string][]string{
				"read":  {"doc_read"},
				"write": {"doc_create"},
			},
			Events: map[string]audit.EventDef{
				"doc_read":   {Category: "read", Required: []string{"outcome"}},
				"doc_create": {Category: "write", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write"},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	// "read" category is disabled by default. Enable it at runtime.
	if err := logger.EnableCategory("read"); err != nil {
		fmt.Println("enable error:", err)
		return
	}

	fmt.Println("read category enabled")
	// Output: read category enabled
}

func ExampleLogger_Close() {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    1,
			Categories: map[string][]string{"write": {"doc_create"}},
			Events: map[string]audit.EventDef{
				"doc_create": {Category: "write", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write"},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Best practice: defer Close immediately after creation.
	defer func() {
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("logger will be closed on function exit")
	// Output: logger will be closed on function exit
}

func ExampleWithFormatter() {
	cef := &audit.CEFFormatter{
		Vendor:  "MyCompany",
		Product: "MyApp",
		Version: "1.0",
		SeverityFunc: func(eventType string) int {
			if eventType == "auth_failure" {
				return 8
			}
			return 5
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version:    1,
			Categories: map[string][]string{"security": {"auth_failure"}},
			Events: map[string]audit.EventDef{
				"auth_failure": {Category: "security", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"security"},
		}),
		audit.WithFormatter(cef),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("CEF formatter configured")
	// Output: CEF formatter configured
}

func ExampleNewStdoutOutput() {
	// Create a stdout output for development/debugging. When Writer is
	// nil, os.Stdout is used. Here we use a bytes.Buffer for testing.
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{
		Writer: &buf,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	fmt.Println("stdout output:", out.Name())
	// Output: stdout output: stdout
}

func ExampleNewFileOutput() {
	// Create a file output with rotation for production use.
	dir, err := os.MkdirTemp("", "audit-example-*")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out, err := audit.NewFileOutput(audit.FileConfig{
		Path:        filepath.Join(dir, "audit.log"),
		MaxSizeMB:   100,
		MaxBackups:  5,
		MaxAgeDays:  30,
		Permissions: "0600",
	})
	if err != nil {
		fmt.Println("create error:", err)
		return
	}
	defer func() { _ = out.Close() }()

	fmt.Println("file output created")
	// Output: file output created
}

func ExampleEventRoute_include() {
	// Include mode: only security events are delivered to this output.
	route := audit.EventRoute{
		IncludeCategories: []string{"security"},
	}
	fmt.Println("empty:", route.IsEmpty())
	// Output: empty: false
}

func ExampleEventRoute_exclude() {
	// Exclude mode: all events except reads are delivered.
	route := audit.EventRoute{
		ExcludeCategories: []string{"read"},
	}
	fmt.Println("empty:", route.IsEmpty())
	// Output: empty: false
}

func ExampleLogger_SetOutputRoute() {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(audit.Taxonomy{
			Version: 1,
			Categories: map[string][]string{
				"write":    {"user_create"},
				"security": {"auth_failure"},
			},
			Events: map[string]audit.EventDef{
				"user_create":  {Category: "write", Required: []string{"outcome"}},
				"auth_failure": {Category: "security", Required: []string{"outcome"}},
			},
			DefaultEnabled: []string{"write", "security"},
		}),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := logger.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Restrict output to security events only at runtime.
	if err := logger.SetOutputRoute("stdout", &audit.EventRoute{
		IncludeCategories: []string{"security"},
	}); err != nil {
		fmt.Println("route error:", err)
		return
	}

	fmt.Println("route set to security only")
	// Output: route set to security only
}

func ExampleSyslogConfig_tcp() {
	// Plain TCP syslog — the simplest configuration.
	cfg := &audit.SyslogConfig{
		Network:  "tcp",
		Address:  "syslog.example.com:514",
		Facility: "local0",
		AppName:  "myapp",
	}
	fmt.Printf("network=%s address=%s facility=%s app=%s\n",
		cfg.Network, cfg.Address, cfg.Facility, cfg.AppName)
	// Output: network=tcp address=syslog.example.com:514 facility=local0 app=myapp
}

func ExampleSyslogConfig_tls() {
	// TLS syslog with CA verification.
	cfg := &audit.SyslogConfig{
		Network: "tcp+tls",
		Address: "syslog.example.com:6514",
		TLSCA:   "/etc/audit/ca.pem",
	}
	fmt.Printf("network=%s address=%s ca=%s\n", cfg.Network, cfg.Address, cfg.TLSCA)
	// Output: network=tcp+tls address=syslog.example.com:6514 ca=/etc/audit/ca.pem
}

func ExampleSyslogConfig_mtls() {
	// mTLS syslog with client certificate authentication.
	cfg := &audit.SyslogConfig{
		Network: "tcp+tls",
		Address: "syslog.example.com:6514",
		TLSCert: "/etc/audit/client-cert.pem",
		TLSKey:  "/etc/audit/client-key.pem",
		TLSCA:   "/etc/audit/ca.pem",
	}
	fmt.Printf("network=%s address=%s cert=%s key=%s ca=%s\n",
		cfg.Network, cfg.Address, cfg.TLSCert, cfg.TLSKey, cfg.TLSCA)
	// Output: network=tcp+tls address=syslog.example.com:6514 cert=/etc/audit/client-cert.pem key=/etc/audit/client-key.pem ca=/etc/audit/ca.pem
}

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

func ExampleGetHints() {
	// Inside an HTTP handler wrapped by AuditMiddleware:
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hints := audit.GetHints(r.Context())
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
	// AuditMiddleware works with any router that supports
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
