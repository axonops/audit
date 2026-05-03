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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

func TestGenerateCEFTemplate_HeaderLandmarksPresent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, *fixtureTaxonomy(t)))
	out := buf.String()

	for _, want := range []string{
		"# CEF mapping — github.com/axonops/audit",
		"CEF:0|<vendor>|<product>|<version>",
		"# Framework fields (always emitted):",
		"# Reserved standard fields (emitted when present on the event):",
		"# Custom fields (per-event, in cs1..cs6 allocation order):",
		"# Notes for SIEM rule authors:",
	} {
		assert.Contains(t, out, want, "expected landmark missing from CEF template")
	}
}

func TestGenerateCEFTemplate_EveryReservedFieldMapped(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, *fixtureTaxonomy(t)))
	out := buf.String()

	for src, dst := range audit.DefaultCEFFieldMapping() {
		assert.Contains(t, out, src+" ", "reserved field %q not listed in template", src)
		assert.Contains(t, out, "→ "+dst, "CEF target key %q for %q missing", dst, src)
	}
}

func TestGenerateCEFTemplate_CustomFieldSlotAllocation(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, *fixtureTaxonomy(t)))
	out := buf.String()

	// user_create has six custom fields. The taxonomy parser sorts
	// Optional fields alphabetically when populating EventDef, so the
	// cs1..cs6 slot assignment follows that order.
	require.True(t, strings.Contains(out, "#   user_create"), "user_create event header missing")
	for _, want := range []string{
		"cool_factor                      → cs1 (cs1Label=\"cool_factor\")",
		"enabled                          → cs2 (cs2Label=\"enabled\")",
		"marker                           → cs3 (cs3Label=\"marker\")",
		"retry_after                      → cs4 (cs4Label=\"retry_after\")",
		"seen_at                          → cs5 (cs5Label=\"seen_at\")",
		"session_count                    → cs6 (cs6Label=\"session_count\")",
	} {
		assert.Contains(t, out, want, "expected slot allocation missing")
	}
}

func TestGenerateCEFTemplate_OverflowAfterSlot6(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"big": {Events: []string{"big_event"}},
		},
		Events: map[string]*audit.EventDef{
			"big_event": {
				Categories: []string{"big"},
				Required:   []string{"a", "b", "c", "d", "e", "f", "g"},
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, tax))
	out := buf.String()

	for slot, field := range []string{"a", "b", "c", "d", "e", "f"} {
		assert.Contains(t, out, field+" ", "slot %d (%q) missing", slot+1, field)
	}
	assert.Contains(t, out, "g → (overflow — slots cs1..cs6 exhausted)")
}

func TestGenerateCEFTemplate_ReservedFieldsExcludedFromCustomSlots(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, *fixtureTaxonomy(t)))
	out := buf.String()
	authIdx := strings.Index(out, "#   auth_failure\n")
	assert.Equal(t, -1, authIdx,
		"events with no custom fields must be omitted from the cs1..cs6 list")
}

func TestGenerateCEFTemplate_FrameworkOnlyMode(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, audit.Taxonomy{}))
	out := buf.String()
	assert.Contains(t, out, "No taxonomy events declared.")
	assert.Contains(t, out, "# Framework fields (always emitted):")
}

func TestGenerateCEFTemplate_DeterministicOutput(t *testing.T) {
	t.Parallel()
	tax := *fixtureTaxonomy(t)
	var a, b bytes.Buffer
	require.NoError(t, generateCEFTemplate(&a, tax))
	require.NoError(t, generateCEFTemplate(&b, tax))
	assert.Equal(t, a.String(), b.String())
}

func TestGenerateCEFTemplate_DedupesCustomFields(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"x": {Events: []string{"dup"}},
		},
		Events: map[string]*audit.EventDef{
			"dup": {
				Categories: []string{"x"},
				Required:   []string{"unique_field"},
				Optional:   []string{"unique_field"},
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, generateCEFTemplate(&buf, tax))
	count := strings.Count(buf.String(), "unique_field ")
	assert.Equal(t, 1, count, "duplicated field must collapse to a single slot allocation")
}

func TestGenerateCEFTemplate_TruncatedWriterReturnsError(t *testing.T) {
	t.Parallel()
	err := generateCEFTemplate(failingWriter{}, *fixtureTaxonomy(t))
	require.Error(t, err)
}
