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
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	err = logger.Audit("doc_create", audit.Fields{"outcome": "success"})
	if err != nil {
		log.Fatal(err)
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
		if err := logger.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	// Get a handle for zero-allocation audit calls.
	docCreate := logger.MustHandle("doc_create")

	err = docCreate.Audit(audit.Fields{"outcome": "success"})
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
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
