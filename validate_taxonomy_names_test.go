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
	"strings"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsafeNameCases enumerates every class of character-set violation that
// the taxonomy name validator must reject. Each entry pairs the bad name
// with a short description used for the subtest name.
//
//nolint:gochecknoglobals // shared between event-type and field-name tests.
var unsafeNameCases = []struct {
	name string // subtest label
	bad  string // the input value that must be rejected
}{
	{"empty", ""},
	{"leading_uppercase", "UserCreate"},
	{"leading_digit", "1create"},
	{"leading_underscore", "_create"},
	{"contains_uppercase", "user_Create"},
	{"contains_hyphen", "user-create"},
	{"contains_dot", "user.create"},
	{"contains_slash", "user/create"},
	{"contains_colon", "user:create"},
	{"contains_space", "user create"},
	{"contains_tab", "user\tcreate"},
	{"contains_newline", "user\ncreate"},
	{"contains_cr", "user\rcreate"},
	{"contains_nul", "user\x00create"},
	{"contains_del", "user\x7fcreate"},
	{"contains_c1_control", "user\x85create"}, // C1 NEL
	{"contains_pipe_cef_meta", "user|create"},
	{"contains_equals_cef_meta", "user=create"},
	{"contains_backslash_cef_meta", "user\\create"},
	{"contains_double_quote", "user\"create"},
	{"contains_single_quote", "user'create"},
	{"contains_ansi_escape", "user\x1bcreate"},
	{"bidi_override_rtlo", "user\u202ecreate"},           // U+202E RIGHT-TO-LEFT OVERRIDE
	{"bidi_isolate", "user\u2066create"},                 // U+2066 LEFT-TO-RIGHT ISOLATE
	{"zero_width_space", "user\u200bcreate"},             // U+200B
	{"zero_width_nbsp", "user\ufeffcreate"},              // U+FEFF BOM
	{"unicode_confusable_cyrillic_a", "user_cr\u0430te"}, // Cyrillic 'а' U+0430 vs ASCII 'a'
	{"unicode_confusable_greek_o", "user_cr\u03bfate"},   // Greek omicron
	{"full_width_letter", "\uff55ser_create"},            // U+FF55 ｕ
	{"emoji", "user_\U0001f600_create"},
	{"nbsp", "user\u00a0create"},
}

// TestValidateTaxonomy_RejectsUnsafeEventTypeNames verifies that every
// unsafe character class is rejected when used as an event-type map key.
// Fails loudly with [ErrInvalidTaxonomyName] alongside [ErrTaxonomyInvalid].
func TestValidateTaxonomy_RejectsUnsafeEventTypeNames(t *testing.T) {
	t.Parallel()
	for _, tc := range unsafeNameCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{tc.bad}}},
				Events:     map[string]*audit.EventDef{tc.bad: {Required: []string{"f1"}}},
			}
			err := audit.ValidateTaxonomy(tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
				"unsafe event type name %q must wrap ErrInvalidTaxonomyName", tc.bad)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid,
				"unsafe event type name %q must still wrap ErrTaxonomyInvalid", tc.bad)
		})
	}
}

// TestValidateTaxonomy_RejectsUnsafeFieldNames verifies that every
// unsafe character class is rejected when used as a field name — both
// in the Required slot and in the Optional slot (named exactly per
// #477 acceptance criteria). Each row exercises the full table of
// violations against both field positions so a regression in one
// code path cannot mask a regression in the other.
func TestValidateTaxonomy_RejectsUnsafeFieldNames(t *testing.T) {
	t.Parallel()
	positions := []struct {
		mkEvent func(bad string) *audit.EventDef
		name    string
	}{
		{
			name: "required",
			mkEvent: func(bad string) *audit.EventDef {
				return &audit.EventDef{Required: []string{bad}}
			},
		},
		{
			name: "optional",
			mkEvent: func(bad string) *audit.EventDef {
				return &audit.EventDef{
					Required: []string{"actor_id"},
					Optional: []string{bad},
				}
			},
		},
	}
	for _, pos := range positions {
		t.Run(pos.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range unsafeNameCases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					tax := audit.Taxonomy{
						Version: 1,
						Categories: map[string]*audit.CategoryDef{
							"write": {Events: []string{"user_create"}},
						},
						Events: map[string]*audit.EventDef{
							"user_create": pos.mkEvent(tc.bad),
						},
					}
					err := audit.ValidateTaxonomy(tax)
					require.Error(t, err)
					assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
						"unsafe %s field name %q must wrap ErrInvalidTaxonomyName",
						pos.name, tc.bad)
					assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
				})
			}
		})
	}
}

// TestValidateTaxonomy_RejectsUnsafeCategoryNames verifies that every
// unsafe character class is rejected when used as a category map key.
// The sentinel godoc promises category names are covered (#477).
func TestValidateTaxonomy_RejectsUnsafeCategoryNames(t *testing.T) {
	t.Parallel()
	for _, tc := range unsafeNameCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{tc.bad: {Events: []string{"user_create"}}},
				Events:     map[string]*audit.EventDef{"user_create": {Required: []string{"actor_id"}}},
			}
			err := audit.ValidateTaxonomy(tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
				"unsafe category name %q must wrap ErrInvalidTaxonomyName", tc.bad)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
		})
	}
}

// TestValidateTaxonomy_RejectsUnsafeSensitivityLabelNames verifies
// that every unsafe character class is rejected when used as a
// sensitivity label map key.
func TestValidateTaxonomy_RejectsUnsafeSensitivityLabelNames(t *testing.T) {
	t.Parallel()
	for _, tc := range unsafeNameCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"user_create"}}},
				Events: map[string]*audit.EventDef{
					"user_create": {Required: []string{"actor_id"}, Optional: []string{"email"}},
				},
				Sensitivity: &audit.SensitivityConfig{
					Labels: map[string]*audit.SensitivityLabel{
						tc.bad: {Fields: []string{"email"}},
					},
				},
			}
			err := audit.ValidateTaxonomy(tax)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
				"unsafe sensitivity label name %q must wrap ErrInvalidTaxonomyName", tc.bad)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
		})
	}
}

// TestValidateTaxonomy_RejectsOverlongCategoryName guards the 128-byte
// DoS cap for category keys. A long category name flows into every
// emitted event via event_category, so the cap protects downstream log
// line lengths.
func TestValidateTaxonomy_RejectsOverlongCategoryName(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("w", 256)
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{longName: {Events: []string{"user_create"}}},
		Events:     map[string]*audit.EventDef{"user_create": {Required: []string{"actor_id"}}},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName)
	assert.Contains(t, err.Error(), "exceeds maximum length 128 bytes")
}

// TestValidateTaxonomy_RejectsOverlongSensitivityLabelName guards the
// 128-byte cap for sensitivity label keys.
func TestValidateTaxonomy_RejectsOverlongSensitivityLabelName(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("p", 256)
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"user_create"}}},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"actor_id"}, Optional: []string{"email"}},
		},
		Sensitivity: &audit.SensitivityConfig{
			Labels: map[string]*audit.SensitivityLabel{
				longName: {Fields: []string{"email"}},
			},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName)
	assert.Contains(t, err.Error(), "exceeds maximum length 128 bytes")
}

// TestValidateTaxonomy_AcceptsAllValidNames verifies that the validator
// does not regress on well-formed names covering the full allowed
// character class `[a-z][a-z0-9_]*`. Each case pairs an event-type
// name with a required-field name derived from it, trimmed so the
// combined names still fit under the 128-byte cap. `custom_field` is
// used alongside so the optional slot carries a non-reserved,
// non-confusing name — avoiding collisions with reserved standard
// fields (e.g. `reason`).
func TestValidateTaxonomy_AcceptsAllValidNames(t *testing.T) {
	t.Parallel()
	cases := []string{
		"a",                      // minimum length
		"z",                      // end of range
		"user_create",            // common snake_case
		"user123",                // trailing digits
		"u1",                     // letter + digit
		"a_b_c_d_e",              // many underscores
		"http_get_request",       // multi-word
		strings.Repeat("a", 128), // exactly at the length cap
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Event name and required-field name are both `name`. The
			// length cap only rejects names > 128 bytes, so using `name`
			// itself as the field name remains within bounds even at
			// the extreme case. A fixed-length optional field keeps
			// coverage of the Optional code path without risking
			// overflow on the 128-byte case.
			tax := audit.Taxonomy{
				Version:    1,
				Categories: map[string]*audit.CategoryDef{"write": {Events: []string{name}}},
				Events: map[string]*audit.EventDef{
					name: {Required: []string{name}, Optional: []string{"custom_field"}},
				},
			}
			err := audit.ValidateTaxonomy(tax)
			assert.NoError(t, err, "valid name %q was rejected", name)
		})
	}
}

// TestValidateTaxonomy_RejectsOverlongEventTypeName guards the 128-byte
// DoS cap for event-type keys.
func TestValidateTaxonomy_RejectsOverlongEventTypeName(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("a", 129)
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{longName}}},
		Events:     map[string]*audit.EventDef{longName: {Required: []string{"f1"}}},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName)
	assert.Contains(t, err.Error(), "exceeds maximum length 128 bytes")
}

// TestValidateTaxonomy_RejectsOverlongFieldName guards the 128-byte DoS
// cap for field names (required or optional).
func TestValidateTaxonomy_RejectsOverlongFieldName(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("x", 200)
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"user_create"}}},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{longName}},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName)
	assert.Contains(t, err.Error(), "exceeds maximum length 128 bytes")
}

// TestValidateTaxonomy_MultipleNameErrors verifies that the validator
// reports every offending name, not just the first one found. The error
// message MUST be deterministic so consumers can pin test assertions.
func TestValidateTaxonomy_MultipleNameErrors(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"BadEvent", "another_bad-event"}},
		},
		Events: map[string]*audit.EventDef{
			"BadEvent":          {Required: []string{"Bad_Field"}},
			"another_bad-event": {Required: []string{"ok_field"}},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName)
	msg := err.Error()
	// Every offending name must be reported so consumers can fix them
	// all in one pass rather than iteratively.
	assert.Contains(t, msg, "BadEvent")
	assert.Contains(t, msg, "another_bad-event")
	assert.Contains(t, msg, "Bad_Field")
}

// TestValidateTaxonomy_NameErrorUsesQuotedEscapes proves that a
// malicious name containing control or bidi bytes is rendered as Go
// escape sequences in the error message. This prevents a malicious
// taxonomy from hijacking terminal output via bidi overrides or
// control characters (CVE-2021-42574 class).
func TestValidateTaxonomy_NameErrorUsesQuotedEscapes(t *testing.T) {
	t.Parallel()
	evil := "evt\u202eadmin" // RIGHT-TO-LEFT OVERRIDE
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{evil}}},
		Events:     map[string]*audit.EventDef{evil: {Required: []string{"f1"}}},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	msg := err.Error()
	// The raw bidi override byte must NOT appear in the rendered error.
	assert.NotContains(t, msg, "\u202e",
		"error message must not contain raw bidi override byte")
	// The escape form SHOULD appear instead.
	assert.Contains(t, msg, `\u202e`,
		"error message should render bidi override as Go escape")
}

// TestValidateTaxonomy_ValidTaxonomyReturnsNoSentinel confirms that a
// fully valid taxonomy produces no error at all — not even a
// [ErrInvalidTaxonomyName] false positive. `actor_id` is a reserved
// standard field used with Required: true (the permitted form); the
// optional slot uses a consumer-defined name to avoid the
// bare-reserved-standard-field rule.
func TestValidateTaxonomy_ValidTaxonomyReturnsNoSentinel(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"user_create"}}},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"actor_id"}, Optional: []string{"notes"}},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.NoError(t, err)
}

// TestValidateTaxonomy_InvalidNameAlongsideOtherErrors verifies that a
// taxonomy with both a name-shape violation and an unrelated validation
// failure (e.g., nil category) reports both, and that [errors.Is]
// correctly identifies both sentinels.
func TestValidateTaxonomy_InvalidNameAlongsideOtherErrors(t *testing.T) {
	t.Parallel()
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create"}},
			"BadCat":   nil, // two violations: bad category name + nil def
			"good_cat": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"Bad_Field"}},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid,
		"always wraps ErrTaxonomyInvalid")
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
		"also wraps ErrInvalidTaxonomyName when any name is invalid")
}

// TestErrInvalidTaxonomyName_SentinelIdentity verifies that the
// sentinel is itself distinguishable from [ErrTaxonomyInvalid] — both
// return true from [errors.Is] on a joined error, but the sentinels
// themselves are not equivalent.
func TestErrInvalidTaxonomyName_SentinelIdentity(t *testing.T) {
	t.Parallel()
	assert.False(t, errors.Is(audit.ErrInvalidTaxonomyName, audit.ErrTaxonomyInvalid),
		"ErrInvalidTaxonomyName and ErrTaxonomyInvalid must be distinct sentinels")
	assert.False(t, errors.Is(audit.ErrTaxonomyInvalid, audit.ErrInvalidTaxonomyName),
		"ErrTaxonomyInvalid must not imply ErrInvalidTaxonomyName")
}
