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
	"strings"
	"testing"

	"github.com/axonops/audit"
)

// FuzzParseTaxonomyYAML drives [audit.ParseTaxonomyYAML] with
// arbitrary bytes and asserts the parser never panics and always
// returns either a valid taxonomy OR an error (never both nil).
// The library no longer enforces an input-size cap (#646) — taxonomy
// is developer-trusted input — so the fuzzer no longer asserts a
// size-cap invariant.
//
//nolint:cyclop // invariants are intentionally linear; splitting would hurt readability
func FuzzParseTaxonomyYAML(f *testing.F) {
	// Good seeds — valid minimal + realistic taxonomies.
	f.Add([]byte(`version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      actor_id: {required: true}
`))
	f.Add([]byte(`version: 1
categories:
  security:
    - auth_failure
  write:
    - user_create
events:
  user_create:
    fields:
      actor_id: {required: true}
      outcome: {required: true}
      source_ip: {}
  auth_failure:
    fields:
      actor_id: {required: true}
      outcome: {required: true}
`))

	// Empty / boundary.
	f.Add([]byte(``))
	f.Add([]byte(`---`))
	f.Add([]byte(`version: 1`))

	// Known-bad structures.
	f.Add([]byte(`version: 0`))
	f.Add([]byte(`version: 999999`))
	f.Add([]byte(`version: -1`))
	f.Add([]byte(`version: "one"`))
	f.Add([]byte(`---` + "\n---\n")) // multi-doc
	f.Add([]byte(`version: 1
bogus_unknown_field: yes
`)) // unknown field (DisallowUnknownField)

	// Adversarial YAML.
	f.Add([]byte("version: 1\ncategories: null\n"))
	f.Add([]byte("a: &a [1,2,3]\nb: *a\n")) // anchor/alias
	f.Add([]byte{0xff, 0xfe, 0x00, 0x00})   // invalid UTF-8 / BOM
	// Bidi override in category name (should be rejected by name charset check).
	f.Add([]byte("version: 1\ncategories:\n  \"evil\u202eadmin\":\n    - user_create\nevents:\n  user_create:\n    fields:\n      actor_id: {required: true}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tax, err := audit.ParseTaxonomyYAML(data)

		// Invariant 1 — impossible state.
		// Parser MUST NEVER return a valid taxonomy together with
		// an error.
		if err != nil && tax != nil {
			t.Fatalf("impossible state: err=%v but taxonomy is non-nil: %+v", err, tax)
		}
		if err == nil && tax == nil {
			t.Fatalf("impossible state: nil taxonomy and nil error")
		}

		// Invariant 2 — on accept, the taxonomy must be internally
		// consistent: every event listed in a category must exist
		// in Events. ValidateTaxonomy runs inside ParseTaxonomyYAML,
		// so this SHOULD hold — this invariant catches a future
		// regression where ValidateTaxonomy is bypassed or weakened.
		if err == nil && tax != nil {
			if tax.Version < 1 {
				t.Fatalf("accepted taxonomy has invalid version %d",
					tax.Version)
			}
			for catName, cat := range tax.Categories {
				if cat == nil {
					t.Fatalf("accepted taxonomy has nil category %q", catName)
				}
				for _, evName := range cat.Events {
					if _, ok := tax.Events[evName]; !ok {
						t.Fatalf("accepted taxonomy has category %q referencing undefined event %q",
							catName, evName)
					}
				}
			}
			// Field overlap invariant — a field must not appear in
			// both Required and Optional for the same event.
			for evName, def := range tax.Events {
				if def == nil {
					continue
				}
				seen := make(map[string]bool, len(def.Required))
				for _, f := range def.Required {
					seen[f] = true
				}
				for _, f := range def.Optional {
					if seen[f] {
						t.Fatalf("event %q has field %q in both Required and Optional",
							evName, f)
					}
				}
			}
		}

		// Invariant 3 — an error containing "\x00" (raw null) in
		// its string representation would corrupt log output. The
		// parser's error messages must never embed raw nulls.
		if err != nil && strings.ContainsRune(err.Error(), 0) {
			t.Fatalf("error message contains raw NUL byte: %q", err.Error())
		}
	})
}
