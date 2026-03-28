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
default_enabled:
  - write
  - security
events:
  user_create:
    category: write
    required:
      - outcome
      - actor_id
  auth_failure:
    category: security
    required:
      - outcome
    optional:
      - reason
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
	// when the taxonomy is structurally inconsistent — here, the event's
	// category does not match any key in categories.
	data := []byte(`
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: nonexistent
`)

	_, err := audit.ParseTaxonomyYAML(data)
	if errors.Is(err, audit.ErrTaxonomyInvalid) {
		fmt.Println("taxonomy validation failed")
	}
	// Output:
	// taxonomy validation failed
}
