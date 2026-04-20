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

package audit

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestSortedKeysPool_NewSliceHasAdequateCap pins the pool's initial
// backing-array capacity against accidental regressions.
// [BenchmarkCEFFormatter_Format_LargeEvent_Escaping] and
// [BenchmarkCEFFormatter_Format_Numeric] depend on the pool handing
// out slices large enough to hold a 20-field event without a
// growslice allocation — that assumption breaks silently if the
// initial cap is ever shrunk below [initialPooledKeysCap].
//
// Unit-level guard because benchmarks do NOT fail `make check`
// while this assertion does. See #664.
func TestSortedKeysPool_NewSliceHasAdequateCap(t *testing.T) {
	s, ok := sortedKeysPool.New().(*[]string)
	require.True(t, ok, "sortedKeysPool.New must return *[]string")
	require.GreaterOrEqual(t, cap(*s), initialPooledKeysCap,
		"pool initial cap must be at least initialPooledKeysCap; see #664")
	require.GreaterOrEqual(t, cap(*s), 20,
		"pool initial cap must accommodate the 20-field fixture used by "+
			"BenchmarkCEFFormatter_Format_LargeEvent_Escaping; see #664")
}

// TestSortedKeysPool_CapConstantsConsistent guards against a future
// refactor that puts initialPooledKeysCap above maxPooledKeysCap —
// which would make every pooled slice ineligible for re-pooling on
// putSortedKeysSlice and silently defeat the pool. The two
// constants must satisfy initialPooledKeysCap <= maxPooledKeysCap.
func TestSortedKeysPool_CapConstantsConsistent(t *testing.T) {
	require.LessOrEqual(t, initialPooledKeysCap, maxPooledKeysCap,
		"initialPooledKeysCap must not exceed maxPooledKeysCap; "+
			"otherwise the pool returns every slice directly to GC")
}

// TestAllFieldKeysSortedSlow_EdgeCases pins the dedupe / sort
// contract of the rewritten slow path across edge inputs: empty
// inputs, overlapping sets, and within-slice duplicates from a
// misconfigured third-party caller. The sort+[slices.Compact]
// rewrite in #664 replaced a map[string]bool-based dedupe; this
// table documents that the final output is identical for every
// meaningful input shape.
func TestAllFieldKeysSortedSlow_EdgeCases(t *testing.T) {
	cases := []struct {
		name     string
		required []string
		optional []string
		fields   Fields
		want     []string
	}{
		{
			name: "all_empty",
			// pooled slice is returned len=0 (may be nil or empty);
			// assert len only.
			want: []string{},
		},
		{
			name:     "only_required",
			required: []string{"b", "a"},
			want:     []string{"a", "b"},
		},
		{
			name:     "only_optional",
			optional: []string{"y", "x"},
			want:     []string{"x", "y"},
		},
		{
			name:   "only_fields",
			fields: Fields{"gamma": "g", "alpha": "a"},
			want:   []string{"alpha", "gamma"},
		},
		{
			name:     "required_optional_overlap",
			required: []string{"a", "b"},
			optional: []string{"b", "c"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "fields_overlap_required",
			required: []string{"a", "b"},
			fields:   Fields{"a": "1", "c": "2"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "duplicate_within_required",
			required: []string{"a", "a", "b"},
			want:     []string{"a", "b"},
		},
		{
			name:     "three_way_overlap",
			required: []string{"a", "b"},
			optional: []string{"b", "c"},
			fields:   Fields{"c": "x", "d": "y"},
			want:     []string{"a", "b", "c", "d"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def := &EventDef{Required: tc.required, Optional: tc.optional}
			got, owned := allFieldKeysSortedSlow(def, tc.fields)
			if owned != nil {
				defer putSortedKeysSlice(owned)
			}
			assert.Equal(t, len(tc.want), len(got),
				"allFieldKeysSortedSlow: unexpected output length")
			if len(tc.want) > 0 {
				assert.Equal(t, tc.want, got,
					"allFieldKeysSortedSlow output must be sorted + deduplicated")
			}
		})
	}
}

// TestAllFieldKeysSortedSlow_PropertyMatchesMapDedupe proves
// byte-for-byte algorithmic equivalence between the new
// sort+[slices.Compact] path and a reference map[string]bool-based
// dedupe (the pre-#664 algorithm). rapid generates arbitrary
// Required / Optional string slices plus an arbitrary Fields map
// and asserts both implementations return identical sorted output.
//
// Guards against a future regression that silently drops Sort,
// inverts the order of Compact vs Sort, or otherwise breaks the
// sort(unique(R ∪ O ∪ F)) contract.
func TestAllFieldKeysSortedSlow_PropertyMatchesMapDedupe(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		keyGen := rapid.StringN(1, 16, -1)
		required := rapid.SliceOfN(keyGen, 0, 12).Draw(t, "required")
		optional := rapid.SliceOfN(keyGen, 0, 12).Draw(t, "optional")

		fieldKeys := rapid.SliceOfN(keyGen, 0, 12).Draw(t, "fields")
		fields := make(Fields, len(fieldKeys))
		for _, k := range fieldKeys {
			fields[k] = "v"
		}

		def := &EventDef{Required: required, Optional: optional}

		// Reference implementation: map-based dedupe (pre-#664).
		wantKeys := referenceAllFieldKeysSortedSlow(def, fields)

		gotKeys, owned := allFieldKeysSortedSlow(def, fields)
		if owned != nil {
			defer putSortedKeysSlice(owned)
		}

		// Normalise both nil and []string{} to the same form for
		// comparison — slices.Compact on empty stays nil-like.
		if len(wantKeys) == 0 && len(gotKeys) == 0 {
			return
		}
		if !slices.Equal(wantKeys, gotKeys) {
			t.Fatalf("sort+Compact diverges from reference map-dedupe\nrequired=%v optional=%v fields=%v\nwant=%v\ngot =%v",
				required, optional, fieldKeys, wantKeys, gotKeys)
		}
	})
}

// referenceAllFieldKeysSortedSlow is the pre-#664 map[string]bool
// dedupe algorithm preserved for property-testing parity. Used
// only as an oracle for [TestAllFieldKeysSortedSlow_PropertyMatchesMapDedupe].
func referenceAllFieldKeysSortedSlow(def *EventDef, fields Fields) []string {
	seen := make(map[string]bool, len(def.Required)+len(def.Optional))
	keys := make([]string, 0, len(def.Required)+len(def.Optional)+len(fields))
	for _, k := range def.Required {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, k := range def.Optional {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range fields {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
