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
	"errors"
	"fmt"

	"github.com/axonops/go-audit"
)

func ExampleParseTaxonomyYAML() {
	// In production code, use //go:embed to load the YAML file.
	data := []byte(`
version: 1
categories:
  write:
    - user_create
  security:
    - auth_failure
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
      reason: {}
`)

	tax, err := audit.ParseTaxonomyYAML(data)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("version:", tax.Version)
	fmt.Println("events:", len(tax.Events))
	// Output:
	// version: 1
	// events: 4
}

func ExampleParseTaxonomyYAML_validation() {
	// ParseTaxonomyYAML returns an error wrapping audit.ErrTaxonomyInvalid
	// when the taxonomy is structurally inconsistent — here, a category
	// references an event type that is not defined in the events map.
	data := []byte(`
version: 1
categories:
  ops:
    - deploy
    - nonexistent_event
events:
  deploy:
    fields:
      outcome: {required: true}
`)

	_, err := audit.ParseTaxonomyYAML(data)
	if errors.Is(err, audit.ErrTaxonomyInvalid) {
		fmt.Println("taxonomy validation failed")
	}
	// Output:
	// taxonomy validation failed
}

// ExampleParseTaxonomyYAML_sensitivityLabels demonstrates defining
// sensitivity labels in a taxonomy and inspecting the resolved field
// labels after parsing.
func ExampleParseTaxonomyYAML_sensitivityLabels() {
	data := []byte(`
version: 1
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email]
      patterns: ["_email$"]
    financial:
      fields: [card_number]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
      card_number: {}
      contact_email: {}
`)

	tax, err := audit.ParseTaxonomyYAML(data)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	def := tax.Events["user_create"]
	for _, field := range []string{"email", "card_number", "contact_email", "outcome"} {
		if labels, ok := def.FieldLabels[field]; ok {
			names := make([]string, 0, len(labels))
			for l := range labels {
				names = append(names, l)
			}
			fmt.Printf("%s: %v\n", field, names)
		} else {
			fmt.Printf("%s: no labels\n", field)
		}
	}
	// Output:
	// email: [pii]
	// card_number: [financial]
	// contact_email: [pii]
	// outcome: no labels
}
