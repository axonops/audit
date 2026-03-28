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

	"github.com/axonops/go-audit"
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
default_enabled:
  - write
  - security
events:
  schema_read:
    category: read
    required:
      - outcome
    optional:
      - subject
  config_read:
    category: read
    required:
      - outcome
  schema_register:
    category: write
    required:
      - outcome
      - actor_id
      - subject
    optional:
      - schema_type
  schema_delete:
    category: write
    required:
      - outcome
      - actor_id
      - subject
  auth_failure:
    category: security
    required:
      - outcome
      - actor_id
    optional:
      - reason
`

// minimalYAML is a minimal valid taxonomy with one category and one event.
const minimalYAML = `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: ops
    required:
      - outcome
`

func TestParseTaxonomyYAML_ValidFull(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(validYAML))
	require.NoError(t, err)

	assert.Equal(t, 1, tax.Version)
	assert.Len(t, tax.Categories["read"], 2)
	assert.Len(t, tax.Categories["write"], 2)
	assert.Len(t, tax.Categories["security"], 1)

	assert.Contains(t, tax.Events, "schema_register")
	assert.Equal(t, "write", tax.Events["schema_register"].Category)
	assert.Equal(t, []string{"outcome", "actor_id", "subject"}, tax.Events["schema_register"].Required)
	assert.Equal(t, []string{"schema_type"}, tax.Events["schema_register"].Optional)

	assert.Contains(t, tax.DefaultEnabled, "write")
	assert.Contains(t, tax.DefaultEnabled, "security")
}

func TestParseTaxonomyYAML_ValidMinimal(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(minimalYAML))
	require.NoError(t, err)

	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "deploy")
	// Lifecycle events injected.
	assert.Contains(t, tax.Events, "startup")
	assert.Contains(t, tax.Events, "shutdown")
	assert.Contains(t, tax.Categories, "lifecycle")
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
    category: ops
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	assert.Nil(t, tax.Events["deploy"].Required)
	assert.Nil(t, tax.Events["deploy"].Optional)
}

func TestParseTaxonomyYAML_RoundTripEquivalence(t *testing.T) {
	t.Parallel()
	// Build the same taxonomy in Go code.
	goTax := audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"ops": {"deploy"},
		},
		Events: map[string]audit.EventDef{
			"deploy": {Category: "ops", Required: []string{"outcome"}},
		},
	}
	audit.InjectLifecycleEvents(&goTax)

	yamlTax, err := audit.ParseTaxonomyYAML([]byte(minimalYAML))
	require.NoError(t, err)

	// Compare structurally (categories, events, version).
	assert.Equal(t, goTax.Version, yamlTax.Version)
	assert.Equal(t, goTax.Events["deploy"].Category, yamlTax.Events["deploy"].Category)
	assert.Equal(t, goTax.Events["deploy"].Required, yamlTax.Events["deploy"].Required)
	assert.Contains(t, yamlTax.Events, "startup")
	assert.Contains(t, yamlTax.Events, "shutdown")
}

func TestParseTaxonomyYAML_DefaultEnabledEmpty(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
default_enabled: []
events:
  deploy:
    category: ops
    required:
      - outcome
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// lifecycle is always added to DefaultEnabled.
	assert.Contains(t, tax.DefaultEnabled, "lifecycle")
	// Original empty list should not contain "ops".
	assert.NotContains(t, tax.DefaultEnabled, "ops")
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
    category: ops
    required:
      - outcome
---
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "multiple YAML documents")
}

func TestParseTaxonomyYAML_TrailingGarbage(t *testing.T) {
	t.Parallel()
	yml := "version: 1\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: ops\n---\n{{broken"
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrInvalidInput)
	assert.Contains(t, err.Error(), "trailing content")
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
    category: ops
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
    category: ops
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
    category: ops
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
    category: ops
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
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "not supported")
}

func TestParseTaxonomyYAML_EventReferencesNonExistentCategory(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: nonexistent
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestParseTaxonomyYAML_DuplicateEventAcrossCategories(t *testing.T) {
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
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "multiple categories")
}

func TestParseTaxonomyYAML_FieldInBothRequiredAndOptional(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: ops
    required:
      - outcome
    optional:
      - outcome
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "both Required and Optional")
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
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "not defined in Events")
}

func TestParseTaxonomyYAML_EventNotInAnyCategory(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
events:
  deploy:
    category: ops
  orphan:
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "not listed in Categories")
}

func TestParseTaxonomyYAML_DefaultEnabledNonExistentCategory(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  ops:
    - deploy
default_enabled:
  - ops
  - nonexistent
events:
  deploy:
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestParseTaxonomyYAML_EmptyCategories(t *testing.T) {
	t.Parallel()
	// Empty categories + events still passes because lifecycle injection
	// adds the lifecycle category with startup/shutdown events.
	yml := `
version: 1
categories: {}
events: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.Contains(t, tax.Categories, "lifecycle")
	assert.Contains(t, tax.Events, "startup")
}

// --- Additional edge cases from deep review ---

func TestParseTaxonomyYAML_ExactMaxInputSize(t *testing.T) {
	t.Parallel()
	// Build a valid YAML that is exactly MaxInputSize bytes.
	base := "version: 1\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: ops\n"
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
    category: ops
`
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
	assert.Contains(t, err.Error(), "no longer supported")
}

func TestParseTaxonomyYAML_MissingCategoriesKey(t *testing.T) {
	t.Parallel()
	// categories key absent entirely — lifecycle injection saves it.
	yml := `
version: 1
events: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.Contains(t, tax.Categories, "lifecycle")
}

func TestParseTaxonomyYAML_MissingEventsKey(t *testing.T) {
	t.Parallel()
	// events key absent entirely — lifecycle injection adds startup/shutdown.
	yml := `
version: 1
categories: {}
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)
	assert.Contains(t, tax.Events, "startup")
	assert.Contains(t, tax.Events, "shutdown")
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
			fmt.Fprintf(&b, "  ev_%d_%d:\n    category: cat_%d\n    required:\n      - outcome\n    optional:\n      - detail\n", i, j, i)
		}
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(b.String()))
	require.NoError(t, err)
	assert.Equal(t, numCategories*eventsPerCategory+2, len(tax.Events)) // +2 for lifecycle
}

func TestParseTaxonomyYAML_LifecycleEventsUserDefined(t *testing.T) {
	t.Parallel()
	yml := `
version: 1
categories:
  lifecycle:
    - startup
    - shutdown
  ops:
    - deploy
default_enabled:
  - lifecycle
  - ops
events:
  startup:
    category: lifecycle
    required:
      - custom_startup_field
  shutdown:
    category: lifecycle
    required:
      - custom_shutdown_field
  deploy:
    category: ops
    required:
      - outcome
`
	tax, err := audit.ParseTaxonomyYAML([]byte(yml))
	require.NoError(t, err)

	// User-defined lifecycle events should be preserved.
	assert.Equal(t, []string{"custom_startup_field"}, tax.Events["startup"].Required)
	assert.Equal(t, []string{"custom_shutdown_field"}, tax.Events["shutdown"].Required)
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
    category: ops
    required: []
    optional: []
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
	yml := `
version: 1
categories:
  ops: &ops
    - deploy
events:
  deploy:
    category: ops
    required: &req
      - outcome
    optional: *req
`
	// This should parse (anchors/aliases are valid YAML) but may fail
	// validation if fields overlap. The point is it does not hang or OOM.
	_, err := audit.ParseTaxonomyYAML([]byte(yml))
	// outcome appears in both required and optional via alias.
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid)
}

func TestParseTaxonomyYAML_AllValidationErrorsWrapSentinel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		yaml string
	}{
		{"version zero", "version: 0\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: ops\n"},
		{"missing version", "categories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: ops\n"},
		{"version too high", "version: 999\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: ops\n"},
		{"event references nonexistent category", "version: 1\ncategories:\n  ops:\n    - deploy\nevents:\n  deploy:\n    category: nonexistent\n"},
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

func BenchmarkParseTaxonomyYAML(b *testing.B) {
	data := []byte(validYAML)
	for b.Loop() {
		_, _ = audit.ParseTaxonomyYAML(data)
	}
}
