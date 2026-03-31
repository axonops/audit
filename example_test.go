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

	"github.com/axonops/go-audit"
)

func ExampleNewLogger() {
	taxonomy := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":  {Required: []string{"outcome", "actor_id"}},
			"auth_failure": {Required: []string{"outcome", "actor_id"}},
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
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
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
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
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
			Categories: map[string]*audit.CategoryDef{
				"read":  {Events: []string{"doc_read"}},
				"write": {Events: []string{"doc_create"}},
			},
			Events: map[string]*audit.EventDef{
				"doc_read":   {Required: []string{"outcome"}},
				"doc_create": {Required: []string{"outcome"}},
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
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
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
			Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
			Events: map[string]*audit.EventDef{
				"auth_failure": {Required: []string{"outcome"}},
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
			Categories: map[string]*audit.CategoryDef{
				"write":    {Events: []string{"user_create"}},
				"security": {Events: []string{"auth_failure"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create":  {Required: []string{"outcome"}},
				"auth_failure": {Required: []string{"outcome"}},
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
