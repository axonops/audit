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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// asMap is a test helper that fails loudly when v is not a JSON
// object. Lets the schema-shape tests destructure generic JSON
// values without a forest of //nolint:forcetypeassert suppressions.
func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	require.True(t, ok, "expected map[string]any, got %T", v)
	return m
}

// asSlice is the slice equivalent of asMap.
func asSlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	require.True(t, ok, "expected []any, got %T", v)
	return s
}

// fixtureTaxonomy returns a representative taxonomy with two events
// and custom field types covering every supported scalar.
func fixtureTaxonomy(t *testing.T) *audit.Taxonomy {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
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
      marker: {}
      session_count: {type: int}
      retry_after: {type: duration}
      cool_factor: {type: float64}
      enabled: {type: bool}
      seen_at: {type: time}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`))
	require.NoError(t, err)
	return tax
}

func TestGenerateJSONSchema_RootStructure(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, *fixtureTaxonomy(t)))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	assert.Equal(t, "https://json-schema.org/draft/2020-12/schema", root["$schema"])
	assert.Equal(t, "Audit event", root["title"])
	assert.Equal(t, "object", root["type"])
	assert.Equal(t, false, root["unevaluatedProperties"],
		"strict unknown-property rejection lives at the root, not the branch (#548)")

	required := asSlice(t, root["required"])
	assert.ElementsMatch(t,
		[]any{"timestamp", "event_type", "severity", "app_name", "host", "timezone", "pid"},
		required)
}

func TestGenerateJSONSchema_OneOfBranchPerEvent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, *fixtureTaxonomy(t)))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	branches := asSlice(t, root["oneOf"])
	assert.Len(t, branches, 2, "one branch per event type")

	branch0Props := asMap(t, asMap(t, branches[0])["properties"])
	assert.Equal(t, "auth_failure",
		asMap(t, branch0Props["event_type"])["const"])

	branch1Props := asMap(t, asMap(t, branches[1])["properties"])
	assert.Equal(t, "user_create",
		asMap(t, branch1Props["event_type"])["const"])
}

func TestGenerateJSONSchema_CustomFieldTypeInference(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, *fixtureTaxonomy(t)))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	branches := asSlice(t, root["oneOf"])
	props := asMap(t, asMap(t, branches[1])["properties"])

	cases := map[string]struct {
		field, wantType, wantFormat string
	}{
		"int":      {field: "session_count", wantType: "integer"},
		"duration": {field: "retry_after", wantType: "string"},
		"float64":  {field: "cool_factor", wantType: "number"},
		"bool":     {field: "enabled", wantType: "boolean"},
		"time":     {field: "seen_at", wantType: "string", wantFormat: "date-time"},
		"default":  {field: "marker", wantType: "string"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := asMap(t, props[tc.field])
			assert.Equal(t, tc.wantType, entry["type"])
			if tc.wantFormat != "" {
				assert.Equal(t, tc.wantFormat, entry["format"])
			}
		})
	}
}

func TestGenerateJSONSchema_ReservedStandardFieldsAtRoot(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, *fixtureTaxonomy(t)))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	props := asMap(t, root["properties"])
	for _, name := range audit.ReservedStandardFieldNames() {
		entry := asMap(t, props[name])
		assert.NotEmpty(t, entry["type"], "reserved standard field %q has no type", name)
	}
}

func TestGenerateJSONSchema_FrameworkOnlyFallback(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tax := audit.Taxonomy{}
	require.NoError(t, generateJSONSchema(&buf, tax))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	assert.Equal(t, true, root["additionalProperties"])
	assert.NotContains(t, root, "oneOf")
	assert.NotContains(t, root, "unevaluatedProperties")
	desc, ok := root["description"].(string)
	require.True(t, ok)
	assert.Contains(t, desc, "Framework-only")
	assert.Contains(t, desc, "additionalProperties")
}

func TestGenerateJSONSchema_DeterministicOutput(t *testing.T) {
	t.Parallel()
	tax := *fixtureTaxonomy(t)
	var a, b bytes.Buffer
	require.NoError(t, generateJSONSchema(&a, tax))
	require.NoError(t, generateJSONSchema(&b, tax))
	assert.Equal(t, a.String(), b.String())
}

func TestGenerateJSONSchema_UnknownTypeFallsBackToString(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"weird": {Events: []string{"oddball"}},
		},
		Events: map[string]*audit.EventDef{
			"oddball": {
				Categories: []string{"weird"},
				Required:   []string{"odd_field"},
				FieldTypes: map[string]string{"odd_field": "complex128"},
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, tax))
	out := buf.String()
	assert.Contains(t, out, `"odd_field"`)
	assert.Contains(t, out, `"type": "string"`)
}

func TestGenerateJSONSchema_ReservedFieldNotRedundantInBranch(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateJSONSchema(&buf, *fixtureTaxonomy(t)))

	var root map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &root))

	branches := asSlice(t, root["oneOf"])
	for i, branch := range branches {
		props := asMap(t, asMap(t, branch)["properties"])
		_, present := props["actor_id"]
		assert.False(t, present,
			"branch %d should not redundantly type the reserved field actor_id", i)
	}
}

func TestGenerateJSONSchema_TruncatedWriterReturnsError(t *testing.T) {
	t.Parallel()
	w := failingWriter{}
	err := generateJSONSchema(w, *fixtureTaxonomy(t))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "encode json schema"))
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, assert.AnError }
