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

package testhelper

import (
	"fmt"
	"strings"

	"github.com/axonops/audit"
)

// BuildLargeTaxonomyYAML returns a syntactically valid taxonomy YAML
// document containing eventCount synthetic events. Each event has a
// single required actor_id field; all events belong to one "bulk"
// category. Used by cap-removal regression tests (#646) that need to
// verify large taxonomies parse successfully.
//
// When withSensitivity is true, the generated YAML includes a top-level
// sensitivity block with one label and one regex pattern. This forces
// ParseTaxonomyYAML's precomputeSensitivity stage to walk every event
// × every field × every pattern, exercising the O(N×M×P) cost path
// described in the ParseTaxonomyYAML godoc. A regression that turned
// that walk quadratic in event count would manifest as a timeout in
// any test driving this fixture at large eventCount.
//
// The function returns []byte rather than a *Taxonomy because callers
// typically want to drive ParseTaxonomyYAML end-to-end.
func BuildLargeTaxonomyYAML(eventCount int, withSensitivity bool) []byte {
	var b strings.Builder
	// Estimate ~80 bytes per event header (listing + def) plus 4 KiB
	// of fixed prelude/sensitivity. Pre-allocate to avoid copies.
	b.Grow(eventCount*80 + 4096)
	b.WriteString("version: 1\ncategories:\n  bulk:\n")
	for i := range eventCount {
		fmt.Fprintf(&b, "    - event%06d\n", i)
	}
	b.WriteString("events:\n")
	for i := range eventCount {
		fmt.Fprintf(&b, "  event%06d:\n    fields:\n      actor_id: {required: true}\n", i)
	}
	if withSensitivity {
		// One label, one pattern targeting actor_id. Forces
		// precomputeSensitivity to evaluate the pattern against
		// every event's fields.
		b.WriteString(`sensitivity:
  labels:
    pii:
      patterns:
        - "^actor_id$"
`)
	}
	return []byte(b.String())
}

// ValidTaxonomy returns a taxonomy suitable for general testing with
// read, write, and security categories.
func ValidTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"read":     {Events: []string{"schema_read", "config_read"}},
			"write":    {Events: []string{"schema_register", "schema_delete"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"schema_read":     {Required: []string{"outcome"}, Optional: []string{"subject"}},
			"config_read":     {Required: []string{"outcome"}},
			"schema_register": {Required: []string{"outcome", "actor_id", "subject"}, Optional: []string{"schema_type"}},
			"schema_delete":   {Required: []string{"outcome", "actor_id", "subject"}},
			"auth_failure":    {Required: []string{"outcome", "actor_id"}},
		},
	}
}

// TestTaxonomy returns a taxonomy with user_create, user_delete, and
// other common event types for routing and filter tests.
func TestTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create", "user_delete"}},
			"read":     {Events: []string{"user_get", "config_get"}},
			"security": {Events: []string{"auth_failure", "permission_denied"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":       {Required: []string{"outcome"}},
			"user_delete":       {Required: []string{"outcome"}},
			"user_get":          {Required: []string{"outcome"}},
			"config_get":        {Required: []string{"outcome"}},
			"auth_failure":      {Required: []string{"outcome"}},
			"permission_denied": {Required: []string{"outcome"}},
		},
	}
}
