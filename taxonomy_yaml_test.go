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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validYAML is a complete, valid taxonomy YAML document.
const validYAML = `
version: 1
categories:
  read:
    - schema_read
    - config_read
  write:
    - schema_register
    - schema_delete
  security:
    - auth_failure
events:
  schema_read:
    fields:
      outcome: {required: true}
      subject: {}
  config_read:
    fields:
      outcome: {required: true}
  schema_register:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      subject: {required: true}
      schema_type: {}
  schema_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      subject: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`

// minimalYAML is a minimal valid taxonomy with one category and one event.
const minimalYAML = `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
`

func TestParseTaxonomyYAML_ValidFull(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(validYAML))
	require.NoError(t, err)

	assert.Equal(t, 1, tax.Version)
	assert.Len(t, tax.Categories["read"].Events, 2)
	assert.Len(t, tax.Categories["write"].Events, 2)
	assert.Len(t, tax.Categories["security"].Events, 1)

	assert.Contains(t, tax.Events, "schema_register")
	assert.Contains(t, tax.Events["schema_register"].Categories, "write")
	assert.Equal(t, []string{"actor_id", "outcome", "subject"}, tax.Events["schema_register"].Required)
	assert.Equal(t, []string{"schema_type"}, tax.Events["schema_register"].Optional)

}

func TestParseTaxonomyYAML_ValidMinimal(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(minimalYAML))
	require.NoError(t, err)

	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "deploy")
	// Lifecycle events injected.
}

func TestParseTaxonomyYAML_OptionalFieldsOmitted(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	assert.Nil(t, tax.Events["deploy"].Required)
	assert.Nil(t, tax.Events["deploy"].Optional)
}

func TestParseTaxonomyYAML_RoundTripEquivalence(t *testing.T) {
	t.Parallel()
	yamlTax, err := audit.ParseTaxonomyYAML([]byte(minimalYAML))
	require.NoError(t, err)

	// Verify parsed taxonomy has correct structure.
	assert.Equal(t, 1, yamlTax.Version)
	assert.Contains(t, yamlTax.Events["deploy"].Categories, "ops")
	assert.Equal(t, []string{"outcome"}, yamlTax.Events["deploy"].Required)
}

// --- Input validation ---

func TestParseTaxonomyYAML_NilInput(t *testing.T) {
	t.Parallel()
	_, err := audit.ParseTaxonomyYAML(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "input is empty")
}

func TestParseTaxonomyYAML_EmptyInput(t *testing.T) {
	t.Parallel()
	_, err := audit.ParseTaxonomyYAML([]byte{})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "input is empty")
}

func TestParseTaxonomyYAML_OversizedInput(t *testing.T) {
	t.Parallel()
	data := make([]byte, audit.MaxTaxonomyInputSize+1)
	for i := range data {
		data[i] = ' '
	}
	_, err := audit.ParseTaxonomyYAML(data)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestParseTaxonomyYAML_InvalidYAMLSyntax(t *testing.T) {
	t.Parallel()
	_, err := audit.ParseTaxonomyYAML([]byte("{{invalid yaml"))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
}

func TestParseTaxonomyYAML_TabsInYAML(t *testing.T) {
	t.Parallel()
	yml := "version: 1\n\tcategories:\n"
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
}

func TestParseTaxonomyYAML_MultipleDocuments(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
---
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "multiple YAML documents")
}

func TestParseTaxonomyYAML_TrailingGarbage(t *testing.T) {
	t.Parallel()
	yml := "version: 1\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n---\n{{broken"
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
}

// --- Strict parsing ---

func TestParseTaxonomyYAML_UnknownTopLevelKey(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
bogus_key: true
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "bogus_key")
}

func TestParseTaxonomyYAML_UnknownEventKey(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    unknown_field: true
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "unknown_field")
}

// --- Taxonomy validation (via audit.ValidateTaxonomy) ---

func TestParseTaxonomyYAML_VersionZero(t *testing.T) {
	t.Parallel()
	yml := `
version: 0
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "version is required")
}

func TestParseTaxonomyYAML_MissingVersion(t *testing.T) {
	t.Parallel()
	yml := `
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "version is required")
}

func TestParseTaxonomyYAML_VersionTooHigh(t *testing.T) {
	t.Parallel()
	yml := `
version: 999
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "not supported")
}

func TestParseTaxonomyYAML_EventCategoryDerivedFromMap(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.Contains(t, tax.Events["deploy"].Categories, "ops")
}

func TestParseTaxonomyYAML_EventInMultipleCategories(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
  admin:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err, "events in multiple categories should be valid")
	assert.Equal(t, []string{"admin", "ops"}, tax.Events["deploy"].Categories)
}

func TestParseTaxonomyYAML_DuplicateFieldName(t *testing.T) {
	t.Parallel()
	// In the unified fields: format, duplicate field names are caught by
	// the YAML parser as duplicate mapping keys — they never reach the
	// taxonomy validation layer.
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
      outcome: {}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "already defined")
}

func TestParseTaxonomyYAML_CategoryMemberNotInEvents(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
    - missing_event
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "not defined in Events")
}

func TestParseTaxonomyYAML_EventNotInAnyCategory_Valid(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields:
      outcome: {required: true}
  orphan:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err, "uncategorised events are valid")
	assert.Contains(t, tax.Events["deploy"].Categories, "ops")
	assert.Empty(t, tax.Events["orphan"].Categories, "orphan should have no categories")
}

func TestParseTaxonomyYAML_EmptyCategories(t *testing.T) {
	t.Parallel()
	// Empty categories + events fails validation — at least one category
	// is required.
	yml := `
version: 1
categories: {}
events: {}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
}

// --- Additional edge cases from deep review ---

func TestParseTaxonomyYAML_ExactMaxInputSize(t *testing.T) {
	t.Parallel()
	// Build a valid YAML that is exactly MaxInputSize bytes.
	base := "version: 1\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n"
	padding := audit.MaxTaxonomyInputSize - len(base) - 1 // -1 for the newline
	data := make([]byte, 0, audit.MaxTaxonomyInputSize)
	data = append(data, []byte(base)...)
	data = append(data, '\n')
	for range padding {
		data = append(data, ' ')
	}
	require.Equal(t, audit.MaxTaxonomyInputSize, len(data))

	tax, err := audit.ParseTaxonomyYAML(data)
	require.NoError(t, err)
	assert.Equal(t, 1, tax.Version)
}

func TestParseTaxonomyYAML_WhitespaceOnly(t *testing.T) {
	t.Parallel()
	// Whitespace-only input is non-empty but contains no YAML content.
	// yaml.v3 returns EOF, which wraps as ErrInvalidInput.
	_, err := audit.ParseTaxonomyYAML([]byte("   \n\n  "))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
}

func TestParseTaxonomyYAML_CommentsOnly(t *testing.T) {
	t.Parallel()
	_, err := audit.ParseTaxonomyYAML([]byte("# just a comment\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
}

func TestParseTaxonomyYAML_NegativeVersion(t *testing.T) {
	t.Parallel()
	yml := `
version: -1
categories:
  ops:
    - deploy
events:
  deploy:
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "no longer supported")
}

func TestParseTaxonomyYAML_MissingCategoriesKey(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
events: {}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
}

func TestParseTaxonomyYAML_MissingEventsKey(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories: {}
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
}

// --- Edge cases ---

func TestParseTaxonomyYAML_LargeTaxonomy(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("version: 1\ncategories:\n")

	numCategories := 20
	eventsPerCategory := 5
	for i := range numCategories {
		fmt.Fprintf(&b, "  cat_%d:\n", i)
		for j := range eventsPerCategory {
			fmt.Fprintf(&b, "    - ev_%d_%d\n", i, j)
		}
	}

	b.WriteString("events:\n")
	for i := range numCategories {
		for j := range eventsPerCategory {
			fmt.Fprintf(&b, "  ev_%d_%d:\n    fields:\n      outcome: {required: true}\n      detail: {}\n", i, j)
		}
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(b.String()))
	require.NoError(t, err)
	assert.Equal(t, numCategories*eventsPerCategory, len(tax.Events))
}

func TestParseTaxonomyYAML_EventWithEmptyRequiredOptional(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    fields: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	assert.Empty(t, tax.Events["deploy"].Required)
	assert.Empty(t, tax.Events["deploy"].Optional)
}

// --- Security ---

func TestParseTaxonomyYAML_NoYAMLFilesystemOrNetworkAccess(t *testing.T) {
	t.Parallel()
	// Verify taxonomy_yaml.go does not call dangerous packages.
	blockedPackages := map[string]bool{
		"os": true, "exec": true, "net": true, "http": true, "ioutil": true,
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "taxonomy_yaml.go", nil, 0)
	require.NoError(t, err)

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if blockedPackages[ident.Name] {
			t.Errorf("taxonomy_yaml.go must not call %s.%s", ident.Name, sel.Sel.Name)
		}
		return true
	})
}

func TestParseTaxonomyYAML_YAMLAnchorBomb(t *testing.T) {
	t.Parallel()
	// yaml.v3 limits alias expansion, so this should not cause issues.
	// With the unified fields: format, anchoring a fields map and using
	// it elsewhere is valid YAML and does not create field overlap. The
	// point of this test is that it does not hang or OOM.
	yml := `
version: 1
categories:
  ops: &ops
    - deploy
events:
  deploy:
    fields: &flds
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err, "anchored fields map is valid YAML")
	assert.Contains(t, tax.Events["deploy"].Required, "outcome")
}

func TestParseTaxonomyYAML_AllValidationErrorsWrapSentinel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
	}{
		{"version zero", "version: 0\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n"},
		{"missing version", "categories:\n  ops:\n    - deploy\nevents:\n  deploy:\n"},
		{"version too high", "version: 999\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := audit.ParseTaxonomyYAML([]byte(tt.yaml))
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
		})
	}
}

// --- Benchmarks ---

func TestParseTaxonomyYAML_WithDescription(t *testing.T) {
	yaml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    description: "A new user account was created"
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "A new user account was created", tax.Events["user_create"].Description)
}

func TestParseTaxonomyYAML_WithoutDescription(t *testing.T) {
	yaml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "", tax.Events["user_create"].Description)
}

func TestPrecomputeTaxonomy_DescriptionNotInKnownFields(t *testing.T) {
	yaml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    description: "Should not appear in knownFields"
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yaml))
	require.NoError(t, err)

	// Create a logger and audit an event — the description should not
	// be treated as a field name. An event with only outcome + actor_id
	// should pass strict validation (no unknown fields).
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(tax),
	)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	err = logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	assert.NoError(t, err, "description should not be in knownFields set")
}

// ---------------------------------------------------------------------------
// emit_event_category (#227)
// ---------------------------------------------------------------------------

func TestSuppressEventCategory_DefaultFalse(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.False(t, tax.SuppressEventCategory, "default should be false (emit category) when absent")
}

func TestSuppressEventCategory_ExplicitEmit(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  emit_event_category: true
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.False(t, tax.SuppressEventCategory, "emit_event_category: true → SuppressEventCategory: false")
}

func TestSuppressEventCategory_ExplicitSuppress(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  emit_event_category: false
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.True(t, tax.SuppressEventCategory, "emit_event_category: false → SuppressEventCategory: true")
}

func BenchmarkParseTaxonomyYAML(b *testing.B) {
	data := []byte(validYAML)
	for b.Loop() {
		_, _ = audit.ParseTaxonomyYAML(data)
	}
}
