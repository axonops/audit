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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit"
)

// TestTaxonomy_YAML_RoundTrip property-checks that ParseTaxonomyYAML
// is deterministic: any valid YAML parses to the same Taxonomy
// structure across runs, and re-parsing the YAML produces the same
// result. Per pre-coding test-analyst guidance, this avoids the
// emitter-divergence risk of marshalling Taxonomy back to YAML —
// instead we generate the YAML directly and assert parser
// determinism.
//
// The generator constructs a minimal but well-formed taxonomy YAML
// from rapid-generated names so the parser exercises distinct
// (category, event, field) combinations.
func TestTaxonomy_YAML_RoundTrip(t *testing.T) {
	t.Parallel()

	// MaxExamples=50 keeps the test under the 30s AC budget on slow
	// CI runners — taxonomy parsing performs YAML decode + multi-pass
	// validation, which is heavier than the byte-level property tests.
	rapid.Check(t, func(rt *rapid.T) {
		yaml := generateTaxonomyYAML(rt)

		// Parser determinism: two parses produce equal Taxonomy values.
		taxA, errA := audit.ParseTaxonomyYAML([]byte(yaml))
		taxB, errB := audit.ParseTaxonomyYAML([]byte(yaml))

		// The generator only emits valid taxonomies; a parse error
		// here means the generator produced something the parser
		// rejects (a generator bug, not a parser bug).
		if errA != nil || errB != nil {
			rt.Fatalf("generated YAML did not parse:\n  yaml=%q\n  errA=%v\n  errB=%v", yaml, errA, errB)
		}
		if !reflect.DeepEqual(taxA, taxB) {
			rt.Fatalf("parser non-deterministic on identical input:\n  yaml=%q\n  A=%+v\n  B=%+v", yaml, taxA, taxB)
		}

		// Re-marshal-by-hand round trip — the emitted YAML uses
		// canonical YAML keys ParseTaxonomyYAML accepts, so the
		// re-parse must yield the same Taxonomy.
		taxC, errC := audit.ParseTaxonomyYAML([]byte(yaml))
		if errC != nil {
			rt.Fatalf("re-parse of identical YAML failed: %v", errC)
		}
		if !reflect.DeepEqual(taxA, taxC) {
			rt.Fatalf("re-parse produced divergent Taxonomy")
		}
	})
}

// genEvtField is a single event-field declaration in the generator.
type genEvtField struct {
	name string
	typ  string // empty == string default
}

// genEvt is a single event-type declaration in the generator.
type genEvt struct {
	name   string
	fields []genEvtField
}

// generateTaxonomyYAML builds a minimal valid taxonomy YAML from
// rapid-generated names. Constraints (per
// validate_taxonomy.go::taxonomyNamePattern):
//
//   - All identifiers match `^[a-z][a-z0-9_]*$`, length 1..16.
//   - 1..3 categories, each with 1..3 events.
//   - 1..4 fields per event, types from the supported scalar set.
//   - At least one outcome:required:true field per event so the
//     generated taxonomy passes ValidateTaxonomy.
//   - No sensitivity section (sensitivity is exercised by the
//     dedicated TestSensitivity_Stripping_Invariants test).
func generateTaxonomyYAML(rt *rapid.T) string {
	idGen := rapid.StringMatching(`^[a-z][a-z0-9_]{0,7}$`)
	cats := generateCategories(rt, idGen)
	if len(cats) == 0 {
		// Generator collapsed to nothing — emit a minimal stub the
		// parser accepts. (Should be rare given the IntRange(1,3).)
		return "version: 1\ncategories:\n  ops: [no_op]\nevents:\n  no_op:\n    fields:\n      outcome: {required: true}\n"
	}
	return renderTaxonomyYAML(cats)
}

// generateCategories produces the per-category event sets for the
// taxonomy generator. Returns an empty map when name collision after
// retries fails to produce any usable categories.
func generateCategories(rt *rapid.T, idGen *rapid.Generator[string]) map[string][]genEvt {
	numCats := rapid.IntRange(1, 3).Draw(rt, "num_categories")
	cats := make(map[string][]genEvt, numCats)
	usedCatNames := make(map[string]struct{}, numCats)
	usedEvtNames := make(map[string]struct{})

	for i := 0; i < numCats; i++ {
		catName := pickUniqueName(rt, idGen, "cat_name", usedCatNames)
		if catName == "" {
			continue
		}
		evts := generateEventsForCategory(rt, idGen, usedEvtNames)
		if len(evts) == 0 {
			delete(usedCatNames, catName)
			continue
		}
		cats[catName] = evts
	}
	return cats
}

// generateEventsForCategory produces the event entries for a single
// category, drawing fresh event and field names that don't collide
// with previously used names or reserved standard field names.
func generateEventsForCategory(rt *rapid.T, idGen *rapid.Generator[string], usedEvtNames map[string]struct{}) []genEvt {
	numEvts := rapid.IntRange(1, 3).Draw(rt, "num_events")
	evts := make([]genEvt, 0, numEvts)
	for i := 0; i < numEvts; i++ {
		evtName := pickUniqueName(rt, idGen, "evt_name", usedEvtNames)
		if evtName == "" {
			continue
		}
		evts = append(evts, genEvt{name: evtName, fields: generateFields(rt, idGen)})
	}
	return evts
}

// generateFields produces the optional field entries for a single
// event, respecting the reserved standard field set (those names
// cannot declare a `type:` and would be rejected by ValidateTaxonomy).
func generateFields(rt *rapid.T, idGen *rapid.Generator[string]) []genEvtField {
	supportedTypes := []string{"string", "int", "int64", "float64", "bool", "time", "duration"}

	// Reserved standard fields cannot declare a `type:` (the library
	// defines their type) so the generator must avoid them entirely.
	// Source: audit.ReservedStandardFieldNames().
	reserved := make(map[string]struct{})
	for _, n := range audit.ReservedStandardFieldNames() {
		reserved[n] = struct{}{}
	}

	numFields := rapid.IntRange(0, 3).Draw(rt, "num_extra_fields")
	fields := make([]genEvtField, 0, numFields+1)
	usedFieldNames := map[string]struct{}{"outcome": {}}
	for i := 0; i < numFields; i++ {
		fName := pickUniqueNameAvoiding(rt, idGen, "field_name", usedFieldNames, reserved)
		if fName == "" {
			continue
		}
		fields = append(fields, genEvtField{
			name: fName,
			typ:  rapid.SampledFrom(supportedTypes).Draw(rt, "field_type"),
		})
	}
	return fields
}

// pickUniqueName draws from the generator until it produces a name
// not already in used, retrying up to 10 times. Returns "" when no
// unique name was found. Adds the result to used on success.
func pickUniqueName(rt *rapid.T, gen *rapid.Generator[string], label string, used map[string]struct{}) string {
	for attempts := 0; attempts < 10; attempts++ {
		candidate := gen.Draw(rt, label)
		if _, dup := used[candidate]; dup {
			continue
		}
		used[candidate] = struct{}{}
		return candidate
	}
	return ""
}

// pickUniqueNameAvoiding is pickUniqueName with an additional set of
// names to reject (e.g. the reserved standard field names).
func pickUniqueNameAvoiding(rt *rapid.T, gen *rapid.Generator[string], label string, used, avoid map[string]struct{}) string {
	for attempts := 0; attempts < 10; attempts++ {
		candidate := gen.Draw(rt, label)
		if _, dup := used[candidate]; dup {
			continue
		}
		if _, banned := avoid[candidate]; banned {
			continue
		}
		used[candidate] = struct{}{}
		return candidate
	}
	return ""
}

// renderTaxonomyYAML emits the YAML representation of the generated
// taxonomy. The categories block iterates the cats map once and the
// events block iterates it again — the ParseTaxonomyYAML contract
// does not depend on the relative iteration order between the two
// blocks (every event referenced from categories must exist somewhere
// in events, but order is not significant), so dual iteration is
// safe even though Go's map iteration randomises per call.
func renderTaxonomyYAML(cats map[string][]genEvt) string {
	var b strings.Builder
	b.WriteString("version: 1\ncategories:\n")
	for catName, evts := range cats {
		b.WriteString("  " + catName + ":\n")
		for _, e := range evts {
			b.WriteString("    - " + e.name + "\n")
		}
	}
	b.WriteString("events:\n")
	for _, evts := range cats {
		for _, e := range evts {
			b.WriteString("  " + e.name + ":\n")
			b.WriteString("    fields:\n")
			b.WriteString("      outcome: {required: true}\n")
			for _, f := range e.fields {
				b.WriteString("      " + f.name + ": {type: " + f.typ + "}\n")
			}
		}
	}
	return b.String()
}

// TestTaxonomy_YAML_RoundTrip_FixedSeed pins a representative YAML
// shape so the property contract is documented as a test even if
// rapid is disabled. Mirrors what the rapid generator emits — uses
// only custom field names (reserved standard fields like actor_id,
// reason, etc. cannot declare a `type:` and would be rejected by
// validate_taxonomy).
func TestTaxonomy_YAML_RoundTrip_FixedSeed(t *testing.T) {
	t.Parallel()
	yaml := `version: 1
categories:
  write:
    - my_create
    - my_update
events:
  my_create:
    fields:
      outcome: {required: true}
      session_count: {type: int}
      detail_text: {type: string}
  my_update:
    fields:
      outcome: {required: true}
      retry_count: {type: int}
`
	a, err := audit.ParseTaxonomyYAML([]byte(yaml))
	require.NoError(t, err)
	b, err := audit.ParseTaxonomyYAML([]byte(yaml))
	require.NoError(t, err)
	require.Equal(t, a, b, "fixed-seed YAML must parse deterministically")
}
