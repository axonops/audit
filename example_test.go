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

	"github.com/axonops/audit"
)

func ExampleNew() {
	// Create a stdout output that writes to a buffer for this example.
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write": {Events: []string{"user_create"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create": {Required: []string{"outcome", "actor_id"}},
			},
		}),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Emit an event — it will be written to the buffer as a JSON line.
	if err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})); err != nil {
		log.Fatal(err)
	}

	// Close drains the async buffer so all events are flushed.
	if err := auditor.Close(); err != nil {
		log.Fatal(err)
	}

	// The buffer now contains the JSON-serialised event.
	fmt.Println("has event_type:", bytes.Contains(buf.Bytes(), []byte(`"event_type":"user_create"`)))
	fmt.Println("has actor_id:", bytes.Contains(buf.Bytes(), []byte(`"actor_id":"alice"`)))
	// Output:
	// has event_type: true
	// has actor_id: true
}

func ExampleAuditor_AuditEvent() {
	var buf bytes.Buffer
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
		audit.WithOutputs(stdout),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err = auditor.AuditEvent(audit.NewEvent("doc_create", audit.Fields{"outcome": "success"})); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	if err = auditor.Close(); err != nil {
		log.Fatal(err)
	}

	// The event is now in the buffer as a JSON line.
	fmt.Println("has event_type:", bytes.Contains(buf.Bytes(), []byte(`"event_type":"doc_create"`)))
	fmt.Println("has outcome:", bytes.Contains(buf.Bytes(), []byte(`"outcome":"success"`)))
	// Output:
	// has event_type: true
	// has outcome: true
}

func ExampleAuditor_MustHandle() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Get a handle for zero-allocation audit calls.
	docCreate := auditor.MustHandle("doc_create")

	if err = docCreate.Audit(audit.Fields{"outcome": "success"}); err != nil {
		fmt.Println("audit error:", err)
		return
	}

	fmt.Println("handle event type:", docCreate.EventType())
	// Output: handle event type: doc_create
}

func ExampleAuditor_EnableCategory() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"read":  {Events: []string{"doc_read"}},
				"write": {Events: []string{"doc_create"}},
			},
			Events: map[string]*audit.EventDef{
				"doc_read":   {Required: []string{"outcome"}},
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	// "read" category is disabled by default. Enable it at runtime.
	if err := auditor.EnableCategory("read"); err != nil {
		fmt.Println("enable error:", err)
		return
	}

	fmt.Println("read category enabled")
	// Output: read category enabled
}

func ExampleAuditor_Close() {
	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"doc_create"}}},
			Events: map[string]*audit.EventDef{
				"doc_create": {Required: []string{"outcome"}},
			},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Best practice: defer Close immediately after creation.
	defer func() {
		if err := auditor.Close(); err != nil {
			log.Printf("audit close: %v", err)
		}
	}()

	fmt.Println("auditor will be closed on function exit")
	// Output: auditor will be closed on function exit
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

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version:    1,
			Categories: map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
			Events: map[string]*audit.EventDef{
				"auth_failure": {Required: []string{"outcome"}},
			},
		}),
		audit.WithFormatter(cef),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := auditor.Close(); err != nil {
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

func ExampleAuditor_SetOutputRoute() {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	if err != nil {
		log.Fatal(err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(&audit.Taxonomy{
			Version: 1,
			Categories: map[string]*audit.CategoryDef{
				"write":    {Events: []string{"user_create"}},
				"security": {Events: []string{"auth_failure"}},
			},
			Events: map[string]*audit.EventDef{
				"user_create":  {Required: []string{"outcome"}},
				"auth_failure": {Required: []string{"outcome"}},
			},
		}),
		audit.WithNamedOutput(out, audit.OutputRoute(&audit.EventRoute{})),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if closeErr := auditor.Close(); closeErr != nil {
			log.Printf("audit close: %v", closeErr)
		}
	}()

	// Restrict output to security events only at runtime.
	if err := auditor.SetOutputRoute("stdout", &audit.EventRoute{
		IncludeCategories: []string{"security"},
	}); err != nil {
		fmt.Println("route error:", err)
		return
	}

	fmt.Println("route set to security only")
	// Output: route set to security only
}
