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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// TestReservedStandardFieldType_AllNamesHaveTypes asserts that every
// name returned by [audit.ReservedStandardFieldNames] also has an
// entry in the type map exposed via [audit.ReservedStandardFieldType].
// The two are derived from a single private map; the test guards
// future additions that touch one but not the other.
func TestReservedStandardFieldType_AllNamesHaveTypes(t *testing.T) {
	t.Parallel()
	for _, name := range audit.ReservedStandardFieldNames() {
		_, ok := audit.ReservedStandardFieldType(name)
		assert.True(t, ok,
			"reserved standard field %q has no type entry — add it to reservedStandardFieldTypes in std_fields.go",
			name)
	}
}

// TestReservedStandardFieldType_Unknown returns false on a
// non-reserved name.
func TestReservedStandardFieldType_Unknown(t *testing.T) {
	t.Parallel()
	_, ok := audit.ReservedStandardFieldType("definitely_not_a_reserved_field")
	assert.False(t, ok)
}

// TestReservedFieldType_String_RoundTrip exercises every enum value
// to ensure the canonical string label is non-empty and unique.
func TestReservedFieldType_String_RoundTrip(t *testing.T) {
	t.Parallel()
	values := []audit.ReservedFieldType{
		audit.ReservedFieldString,
		audit.ReservedFieldInt,
		audit.ReservedFieldInt64,
		audit.ReservedFieldFloat64,
		audit.ReservedFieldBool,
		audit.ReservedFieldTime,
		audit.ReservedFieldDuration,
	}
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		s := v.String()
		require.NotEmpty(t, s, "type %d has empty String()", v)
		assert.NotEqual(t, "unknown", s, "type %d falls through to default branch", v)
		_, dup := seen[s]
		assert.False(t, dup, "type label %q is shared by two values", s)
		seen[s] = struct{}{}
	}
}

// TestReservedStandardFieldType_KnownPortIsInt locks the contract
// that port-typed reserved fields require int (not string) values.
// Consumer regressions (e.g. accidentally typing a port as string)
// would surface here first.
func TestReservedStandardFieldType_KnownPortIsInt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"source_port", "dest_port", "file_size"} {
		got, ok := audit.ReservedStandardFieldType(name)
		require.True(t, ok, "%q should be a reserved standard field", name)
		assert.Equal(t, audit.ReservedFieldInt, got, "%q should be ReservedFieldInt", name)
	}
}

// TestReservedStandardFieldType_KnownTimestampIsTime locks the
// contract that timestamp reserved fields require time.Time values.
func TestReservedStandardFieldType_KnownTimestampIsTime(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"start_time", "end_time"} {
		got, ok := audit.ReservedStandardFieldType(name)
		require.True(t, ok, "%q should be a reserved standard field", name)
		assert.Equal(t, audit.ReservedFieldTime, got, "%q should be ReservedFieldTime", name)
	}
}
