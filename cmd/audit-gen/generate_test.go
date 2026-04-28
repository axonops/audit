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
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// failWriter returns an error on every Write call.
type failWriter struct{ err error }

func (f *failWriter) Write([]byte) (int, error) { return 0, f.err }

func loadTestTaxonomy(t *testing.T, path string) *audit.Taxonomy {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	tax, err := audit.ParseTaxonomyYAML(data)
	require.NoError(t, err)
	return tax
}

func generateToString(t *testing.T, tax *audit.Taxonomy, opts generateOptions) string {
	t.Helper()
	var buf bytes.Buffer
	err := generate(&buf, *tax, opts)
	require.NoError(t, err)
	return buf.String()
}

func defaultOpts() generateOptions {
	return generateOptions{
		Package:    "testpkg",
		InputFile:  "test.yaml",
		Types:      true,
		Fields:     true,
		Categories: true,
	}
}

// --- Determinism ---

func TestGenerate_Deterministic(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()

	out1 := generateToString(t, tax, opts)
	out2 := generateToString(t, tax, opts)
	assert.Equal(t, out1, out2, "two generations from the same input must be byte-identical")
}

// --- Generated code compiles ---

func TestGenerate_OutputCompiles(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err, "generated code must parse without errors")
}

// --- Content verification via AST ---

func TestGenerate_EventConstants(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())
	consts := extractConstants(t, out)

	// All user-defined events + lifecycle events.
	for eventName := range tax.Events {
		constName := "Event" + toPascalCase(eventName)
		assert.Equal(t, eventName, consts[constName],
			"constant %s should have value %q", constName, eventName)
	}
}

func TestGenerate_CategoryConstants(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())
	consts := extractConstants(t, out)

	for catName := range tax.Categories {
		constName := "Category" + toPascalCase(catName)
		assert.Equal(t, catName, consts[constName],
			"constant %s should have value %q", constName, catName)
	}
}

func TestGenerate_FieldConstants(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())
	consts := extractConstants(t, out)

	// Collect all fields from taxonomy.
	allFields := make(map[string]struct{})
	for _, def := range tax.Events {
		for _, f := range def.Required {
			allFields[f] = struct{}{}
		}
		for _, f := range def.Optional {
			allFields[f] = struct{}{}
		}
	}

	for fieldName := range allFields {
		constName := "Field" + toPascalCase(fieldName)
		assert.Equal(t, fieldName, consts[constName],
			"constant %s should have value %q", constName, fieldName)
	}
}

// --- Flag combinations ---

func TestGenerate_TypesDisabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()
	opts.Types = false
	out := generateToString(t, tax, opts)

	assert.NotContains(t, out, "Event type constants")
	assert.Contains(t, out, "Category constants")
	assert.Contains(t, out, "Field name constants")

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)
}

func TestGenerate_FieldsDisabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()
	opts.Fields = false
	out := generateToString(t, tax, opts)

	assert.Contains(t, out, "Event type constants")
	assert.NotContains(t, out, "Field name constants")

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)
}

func TestGenerate_CategoriesDisabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()
	opts.Categories = false
	out := generateToString(t, tax, opts)

	assert.Contains(t, out, "Event type constants")
	assert.NotContains(t, out, "Category constants")

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)
}

func TestGenerate_AllDisabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()
	opts.Types = false
	opts.Fields = false
	opts.Categories = false
	out := generateToString(t, tax, opts)

	// Should produce a valid Go file with just the header and package.
	assert.Contains(t, out, "package testpkg")
	assert.NotContains(t, out, "const")

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)
}

// --- Minimal taxonomy ---

func TestGenerate_MinimalTaxonomy(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/minimal_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())

	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)

	consts := extractConstants(t, out)
	assert.Equal(t, "health_check", consts["EventHealthCheck"])
	assert.Equal(t, "ops", consts["CategoryOps"])
	assert.Equal(t, "outcome", consts["FieldOutcome"])
}

// --- Custom header ---

func TestGenerate_CustomHeader(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/minimal_taxonomy.yaml")
	opts := defaultOpts()
	opts.Header = "// Custom header for testing."
	opts.InputFile = ""
	out := generateToString(t, tax, opts)

	assert.True(t, strings.HasPrefix(out, "// Custom header for testing."),
		"output should start with custom header")
}

// --- Header includes input file name ---

func TestGenerate_HeaderIncludesInputFile(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	opts := defaultOpts()
	opts.InputFile = "audit_taxonomy.yaml"
	out := generateToString(t, tax, opts)

	assert.Contains(t, out, "audit_taxonomy.yaml")
	assert.Contains(t, out, "DO NOT EDIT")
}

// --- run() integration tests ---

func TestRun_ValidInput(t *testing.T) {
	t.Parallel()
	outFile := filepath.Join(t.TempDir(), "gen.go")
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", outFile,
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitSuccess, code)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "package mypkg")
}

func TestRun_StdoutOutput(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "-",
		"-package", "mypkg",
	}, &stdout, &bytes.Buffer{})

	assert.Equal(t, exitSuccess, code)
	assert.Contains(t, stdout.String(), "package mypkg")
}

func TestRun_MissingInputFlag(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-output", "out.go",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitInvalidArgs, code)
}

func TestRun_MissingOutputFlag(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitInvalidArgs, code)
}

func TestRun_MissingPackageFlag(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "-",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitInvalidArgs, code)
}

func TestRun_InvalidPackageName(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "-",
		"-package", "123bad",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitInvalidArgs, code)
}

// TestRun_InvalidStandardSetters confirms the CLI rejects any value
// outside `{all, explicit}` for -standard-setters with a valid-set
// hint and the invalid-args exit code (#575 B-38).
func TestRun_InvalidStandardSetters(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "-",
		"-package", "mypkg",
		"-standard-setters", "maybe",
	}, &bytes.Buffer{}, &stderr)

	assert.Equal(t, exitInvalidArgs, code)
	msg := stderr.String()
	assert.Contains(t, msg, `"maybe"`, "stderr must echo the rejected value")
	assert.Contains(t, msg, "valid: all, explicit", "stderr must list the valid set")
}

func TestRun_NonexistentInput(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-input", "testdata/does_not_exist.yaml",
		"-output", "-",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitYAMLError, code)
}

func TestRun_InvalidYAML(t *testing.T) {
	t.Parallel()
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("{{invalid yaml"), 0o600))

	code := run([]string{
		"-input", bad,
		"-output", "-",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitYAMLError, code)
}

// TestRun_InvalidEventTypeName verifies that audit-gen rejects a
// taxonomy whose event-type key contains any character outside the safe
// `^[a-z][a-z0-9_]*$` pattern. Relies on [audit.ParseTaxonomyYAML]
// invoking [audit.ValidateTaxonomy] before codegen begins, so the
// generator fails fast with a non-zero exit status (#477). Each row
// covers a different class of violation.
func TestRun_InvalidEventTypeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		evtName string
	}{
		{"uppercase", "UserCreate"},
		{"hyphen", "user-create"},
		{"bidi_override", "user\u202eadmin"},
		{"space", "user create"},
		{"leading_digit", "1create"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := "version: 1\ncategories:\n  write:\n    - \"" + tt.evtName + "\"\nevents:\n  \"" + tt.evtName + "\":\n    fields:\n      actor_id:\n        required: true\n"
			input := filepath.Join(t.TempDir(), "bad.yaml")
			require.NoError(t, os.WriteFile(input, []byte(yaml), 0o600))
			var stderr bytes.Buffer
			code := run([]string{
				"-input", input,
				"-output", "-",
				"-package", "mypkg",
			}, &bytes.Buffer{}, &stderr)
			assert.Equal(t, exitYAMLError, code,
				"codegen must reject unsafe event-type name %q", tt.evtName)
			assert.Contains(t, strings.ToLower(stderr.String()), "invalid",
				"stderr should explain the rejection")
		})
	}
}

// TestRun_InvalidFieldName verifies that audit-gen rejects a taxonomy
// whose field name contains any character outside the safe pattern.
// Without this check the generator could emit Go setters referencing a
// name that [audit.ValidateTaxonomy] will reject at runtime — trapping
// the consumer in a "generates fine, never loads" state (#477).
func TestRun_InvalidFieldName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		fieldName string
	}{
		{"uppercase", "Actor_Id"},
		{"hyphen", "actor-id"},
		{"dot", "actor.id"},
		{"bidi_override", "actor\u202eid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yaml := "version: 1\ncategories:\n  write:\n    - user_create\nevents:\n  user_create:\n    fields:\n      \"" + tt.fieldName + "\":\n        required: true\n"
			input := filepath.Join(t.TempDir(), "bad.yaml")
			require.NoError(t, os.WriteFile(input, []byte(yaml), 0o600))
			var stderr bytes.Buffer
			code := run([]string{
				"-input", input,
				"-output", "-",
				"-package", "mypkg",
			}, &bytes.Buffer{}, &stderr)
			assert.Equal(t, exitYAMLError, code,
				"codegen must reject unsafe field name %q", tt.fieldName)
			assert.Contains(t, strings.ToLower(stderr.String()), "invalid",
				"stderr should explain the rejection")
		})
	}
}

func TestRun_VersionFlag(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	code := run([]string{"-version"}, &stdout, &bytes.Buffer{})

	assert.Equal(t, exitSuccess, code)
	assert.Contains(t, stdout.String(), "audit-gen")
}

func TestRun_OversizedInput(t *testing.T) {
	t.Parallel()
	big := filepath.Join(t.TempDir(), "big.yaml")
	data := make([]byte, maxInputSize+1)
	for i := range data {
		data[i] = 'x'
	}
	require.NoError(t, os.WriteFile(big, data, 0o600))

	var stderr bytes.Buffer
	code := run([]string{
		"-input", big,
		"-output", "-",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &stderr)
	assert.Equal(t, exitYAMLError, code)
	assert.Contains(t, stderr.String(), "exceeds maximum")
}

func TestRun_UnwritableOutput(t *testing.T) {
	t.Parallel()
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "/nonexistent/dir/out.go",
		"-package", "mypkg",
	}, &bytes.Buffer{}, &bytes.Buffer{})

	assert.Equal(t, exitWriteError, code)
}

// --- Sorted output verification ---

func TestGenerate_EventsSortedAlphabetically(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())

	// Extract Event constant names in order from the output.
	var eventNames []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Event") && strings.Contains(line, "=") {
			name := strings.Fields(line)[0]
			eventNames = append(eventNames, name)
		}
	}

	// Verify they are sorted.
	for i := 1; i < len(eventNames); i++ {
		assert.True(t, eventNames[i-1] < eventNames[i],
			"events should be sorted: %s should come before %s", eventNames[i-1], eventNames[i])
	}
}

// --- Helper: extract constants from generated Go source ---

func extractConstants(t *testing.T, src string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "generated.go", src, parser.AllErrors)
	require.NoError(t, err)

	consts := make(map[string]string)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			// Strip quotes from string literal.
			val := strings.Trim(lit.Value, `"`)
			consts[vs.Names[0].Name] = val
		}
	}
	return consts
}

// --- Error path coverage ---

func TestBuildConstants_Collision(t *testing.T) {
	t.Parallel()
	// Two keys that produce the same PascalCase name.
	_, err := buildConstants("Field", []string{"a_b", "a__b"})
	assert.ErrorContains(t, err, "naming collision")
}

func TestBuildConstants_InvalidKey(t *testing.T) {
	t.Parallel()
	_, err := buildConstants("Event", []string{"valid_key", "Invalid-Key"})
	assert.ErrorContains(t, err, "unsafe for code generation")
}

func TestGenerate_WriteError(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	w := &failWriter{err: errors.New("disk full")}
	err := generate(w, *tax, defaultOpts())
	assert.ErrorContains(t, err, "write output")
}

func TestRun_GenerateError_StdoutWriteFails(t *testing.T) {
	t.Parallel()
	w := &failWriter{err: errors.New("broken pipe")}
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", "-",
		"-package", "mypkg",
	}, w, &bytes.Buffer{})
	assert.Equal(t, exitWriteError, code)
}

func TestWriteFileAtomic_Success(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "out.go")
	err := writeFileAtomic(path, []byte("package main\n"))
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "package main\n", string(data))
}

func TestWriteFileAtomic_BadDir(t *testing.T) {
	t.Parallel()
	err := writeFileAtomic("/nonexistent/dir/out.go", []byte("data"))
	assert.ErrorContains(t, err, "create temp file")
}

func TestWriteFileAtomic_RenameFailure(t *testing.T) {
	t.Parallel()
	// Write to a temp file in a valid dir, but rename to a path where
	// the target directory doesn't exist.
	dir := t.TempDir()
	src := filepath.Join(dir, "out.go")
	// Create the file first so CreateTemp succeeds.
	require.NoError(t, os.WriteFile(src, []byte("old"), 0o600))
	// Remove write permission on the directory to prevent rename.
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := writeFileAtomic(src, []byte("new content"))
	// On most systems this fails at CreateTemp (can't create in read-only dir).
	assert.Error(t, err)
}

// --- Description comment tests ---

func TestGenerate_DescriptionAsComment(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())

	// Events with descriptions should have comments.
	assert.Contains(t, out, "// EventSchemaRegister — A new schema version was registered in the registry")
	assert.Contains(t, out, "// EventAuthFailure — An authentication attempt failed")

	// Events without descriptions should NOT have comments.
	assert.NotContains(t, out, "// EventSchemaRead")
	assert.NotContains(t, out, "// EventConfigRead")

	// Must still compile.
	fset := token.NewFileSet()
	_, err := parser.ParseFile(fset, "generated.go", out, parser.AllErrors)
	assert.NoError(t, err)
}

func TestGenerate_NoCommentWhenEmpty(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/minimal_taxonomy.yaml")
	out := generateToString(t, tax, defaultOpts())

	// The health_check event has no description — should have no comment.
	// Lifecycle events (startup/shutdown) get descriptions from InjectLifecycleEvents,
	// so they will have comments. Only check user-defined events.
	assert.NotContains(t, out, "// EventHealthCheck")
}

func TestGenerate_MultiLineDescription(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"test": {Events: []string{"multi_line"}}},
		Events: map[string]*audit.EventDef{
			"multi_line": {
				Description: "First line\nSecond line\n\tTabbed",
				Required:    []string{"outcome"},
			},
		},
	}

	out := generateToString(t, tax, defaultOpts())

	// Multi-line should be collapsed to single line.
	assert.Contains(t, out, "// EventMultiLine — First line Second line Tabbed")
	assert.NotContains(t, out, "Second line\n")
}

func TestGenerate_WhitespaceOnlyDescription(t *testing.T) {
	t.Parallel()
	tax := &audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"test": {Events: []string{"blank_desc"}}},
		Events: map[string]*audit.EventDef{
			"blank_desc": {
				Description: "   \t\n  ",
				Required:    []string{"outcome"},
			},
		},
	}

	out := generateToString(t, tax, defaultOpts())

	// Whitespace-only treated as empty — no comment.
	assert.NotContains(t, out, "// EventBlankDesc")
}

func TestSanitiseComment(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "A schema was registered", "A schema was registered"},
		{"newlines", "First\nSecond\nThird", "First Second Third"},
		{"tabs", "Has\ttabs", "Has tabs"},
		{"whitespace only", "   \t\n  ", ""},
		{"empty", "", ""},
		{"leading trailing", "  hello world  ", "hello world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sanitiseComment(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Label constant generation
// ---------------------------------------------------------------------------

func TestGenerate_LabelConstants(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "taxonomy_with_labels.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package: "myapp",
		Header:  "// test",
		Types:   true,
		Fields:  true,
		Labels:  true,
	})
	require.NoError(t, err)

	src := buf.String()
	assert.Contains(t, src, `LabelFinancial = "financial"`)
	assert.Contains(t, src, `LabelPii = "pii"`)
	assert.Contains(t, src, "LabelFinancial — Financial and payment data")
	assert.Contains(t, src, "LabelPii — Personally identifiable information")

	// Metadata uses constant names, not raw strings.
	assert.Contains(t, src, "FieldEmail:")
	assert.Contains(t, src, "LabelPii")
	assert.Contains(t, src, "EventUserCreate:")
	assert.Contains(t, src, "CategoryWrite:")

	// Verify it's valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "labels.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go")
}

func TestGenerate_LabelConstants_Disabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "taxonomy_with_labels.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package: "myapp",
		Header:  "// test",
		Types:   true,
		Labels:  false, // disabled
	})
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "LabelPii")
	assert.NotContains(t, buf.String(), "LabelFinancial")
}

func TestGenerate_NoLabels_NoSection(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package: "myapp",
		Header:  "// test",
		Labels:  true,
	})
	require.NoError(t, err)
	src := buf.String()
	// No sensitivity labels → no Label constants emitted.
	assert.NotContains(t, src, "LabelPii")
	assert.NotContains(t, src, "LabelFinancial")
	// Metadata vars (EventFields, CategoryEvents) should still be present.
	assert.Contains(t, src, "EventFields")
	assert.Contains(t, src, "CategoryEvents")
}

// ---------------------------------------------------------------------------
// Builder generation tests
// ---------------------------------------------------------------------------

func TestGenerate_Builders(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "taxonomy_with_labels.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Types:    true,
		Fields:   true,
		Labels:   true,
		Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()
	// Builder struct exists.
	assert.Contains(t, src, "type UserCreateEvent struct")
	assert.Contains(t, src, "type UserCreateFields struct")
	// Constructor with required fields.
	assert.Contains(t, src, "func NewUserCreateEvent(")
	// Setter for optional field.
	assert.Contains(t, src, "func (e *UserCreateEvent) SetEmail(")
	// EventType method.
	assert.Contains(t, src, "func (e *UserCreateEvent) EventType()")
	assert.Contains(t, src, "EventUserCreate")
	// Fields method.
	assert.Contains(t, src, "func (e *UserCreateEvent) Fields()")
	// FieldInfo method.
	assert.Contains(t, src, "func (e *UserCreateEvent) FieldInfo()")
	// FieldInfoMap method (#597 — Event interface metadata).
	assert.Contains(t, src, "func (e *UserCreateEvent) FieldInfoMap() map[string]audit.FieldInfo")
	// Categories method.
	assert.Contains(t, src, "func (e *UserCreateEvent) Categories()")
	// Label info in FieldInfo.
	assert.Contains(t, src, "LabelPii")
	// Description method.
	assert.Contains(t, src, "func (e *UserCreateEvent) Description()")

	// Verify it's valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "builders.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go:\n%s", src)
}

func TestGenerate_Builders_StandardSetters(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Types:    true,
		Fields:   true,
		Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()

	// Reserved standard field setters should be generated on every
	// builder even when the field is not declared in the taxonomy.
	// auth_failure has actor_id and outcome as required — those should
	// NOT get standard setters (they're constructor params).
	assert.Contains(t, src, "func (e *AuthFailureEvent) SetSourceIP(v string)")
	assert.Contains(t, src, "func (e *AuthFailureEvent) SetSourcePort(v int)")
	assert.Contains(t, src, "func (e *AuthFailureEvent) SetReason(v string)")
	assert.Contains(t, src, "func (e *AuthFailureEvent) SetTargetID(v string)")
	assert.Contains(t, src, "func (e *AuthFailureEvent) SetMethod(v string)")

	// actor_id is required for auth_failure — no standard setter for it.
	assert.NotContains(t, src, "func (e *AuthFailureEvent) SetActorID(v string)")
	// outcome is required — no standard setter.
	assert.NotContains(t, src, "func (e *AuthFailureEvent) SetOutcome(v string)")

	// Field constants generated for all reserved standard fields.
	assert.Contains(t, src, `FieldSourceIP`)
	assert.Contains(t, src, `"source_ip"`)
	assert.Contains(t, src, `FieldReason`)
	assert.Contains(t, src, `FieldTargetID`)
	assert.Contains(t, src, `FieldProtocol`)

	// UID acronym must be uppercased correctly.
	assert.Contains(t, src, "SetActorUID")
	assert.Contains(t, src, "FieldActorUID")
	assert.Contains(t, src, "SetTargetUID")
	assert.NotContains(t, src, "ActorUid", "uid must be cased as UID")

	// Verify the generated source parses as valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "standard_setters.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source with standard setters must parse")
}

func TestGenerate_Builders_Disabled(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Builders: false,
	})
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "type SchemaRegisterEvent struct")
}

func TestGenerate_Builders_NoLabels(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Types:    true,
		Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()
	// Builders exist even without labels.
	assert.Contains(t, src, "type SchemaRegisterEvent struct")
	assert.Contains(t, src, "func NewSchemaRegisterEvent(")
	// No label references.
	assert.NotContains(t, src, "LabelPii")

	// Valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "builders.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go")
}

func TestToParamName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input, want string
	}{
		{"outcome", "outcome"},
		{"actor_id", "actorID"},
		{"source_ip", "sourceIP"},
		{"id", "id"},
		{"http_server", "httpServer"},
		{"user_create", "userCreate"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, toParamName(tt.input))
		})
	}
}

func TestGenerate_Builders_WithSeverity(t *testing.T) {
	t.Parallel()
	// Taxonomy with category-level severity to test auditIntPtr generation.
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  security:
    severity: 8
    events: [auth_failure]
events:
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Types:    true,
		Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()
	// auditIntPtr should be generated when severity is present (B-15
	// — prefix avoids collision with any consumer-defined intPtr).
	assert.Contains(t, src, "func auditIntPtr(")
	assert.NotContains(t, src, "func intPtr(", "unprefixed intPtr must not be emitted (B-15 collision hazard)")
	// Categories should reference severity via the prefixed helper.
	assert.Contains(t, src, "Severity: auditIntPtr(8)")

	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "sev.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go")
}

func TestGenerate_Builders_NoSeverity_NoIntPtr(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:  "myapp",
		Header:   "// test",
		Types:    true,
		Builders: true,
	})
	require.NoError(t, err)
	// No category has severity → auditIntPtr should NOT be generated.
	assert.NotContains(t, buf.String(), "func auditIntPtr(")
	assert.NotContains(t, buf.String(), "func intPtr(")
}

func TestGenerate_Builders_RuntimeEquivalent(t *testing.T) {
	t.Parallel()
	// Generate code and verify the constructor/setter/method patterns
	// produce correct Go that a consumer would use.
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "taxonomy_with_labels.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package:    "myapp",
		Header:     "// test",
		Types:      true,
		Fields:     true,
		Categories: true,
		Labels:     true,
		Builders:   true,
	})
	require.NoError(t, err)
	src := buf.String()

	// Verify builder struct has fields audit.Fields.
	assert.Contains(t, src, "fields audit.Fields")

	// Verify constructor sets required fields into the map.
	assert.Contains(t, src, "FieldOutcome: outcome")

	// Verify setter writes to the fields map and returns pointer.
	assert.Contains(t, src, "e.fields[FieldEmail] = v")
	assert.Contains(t, src, "return e")

	// Verify EventType returns the correct constant.
	assert.Contains(t, src, "return EventUserCreate")

	// Verify Fields returns the internal map.
	assert.Contains(t, src, "return e.fields")

	// Verify FieldInfo has required flag set correctly.
	assert.Contains(t, src, "Required: true")

	// Verify labels are present in FieldInfo.
	assert.Contains(t, src, "LabelPii")
	assert.Contains(t, src, `Description: "Personally identifiable information"`)

	// Verify concurrency/overwrite doc is present.
	assert.Contains(t, src, "not safe for concurrent use")
	assert.Contains(t, src, "overwrites the previous value")

	// Verify required/optional comments on fields struct.
	assert.Contains(t, src, "// required")
	assert.Contains(t, src, "// optional")

	// Verify //nolint directive.
	assert.Contains(t, src, "//nolint:all")

	// Verify valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "runtime.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go")
}

func TestBuildLabelConstants_NamingCollision(t *testing.T) {
	t.Parallel()
	// Two labels that produce the same PascalCase name.
	sc := &audit.SensitivityConfig{
		Labels: map[string]*audit.SensitivityLabel{
			"my_data":  {Description: "one"},
			"my__data": {Description: "two"},
		},
	}
	_, err := buildLabelConstantsFromConfig(sc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "naming collision")
}

// ---------------------------------------------------------------------------
// #575 typed custom field setters (B-01), auditIntPtr rename (B-15),
// Fields() godoc (B-16), -standard-setters=explicit (B-38)
// ---------------------------------------------------------------------------

// TestGenerate_Builders_TypedCustomFields verifies that the generator
// emits `Set<Name>(v T)` setters with the Go type declared in the
// taxonomy YAML `type:` annotation for each accepted vocabulary value
// (string, int, int64, float64, bool, time, duration) — B-01.
func TestGenerate_Builders_TypedCustomFields(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome:    {required: true}
      actor_id:   {required: true}
      email:      {type: string}
      quota:      {type: int}
      bytes_used: {type: int64}
      score:      {type: float64}
      active:     {type: bool}
      created_at: {type: time}
      ttl:        {type: duration}
`))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = generate(&buf, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		Types: true, Fields: true, Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()
	// Each declared type must produce a matching Go-typed setter.
	assert.Contains(t, src, "SetEmail(v string)", "type: string → string setter")
	assert.Contains(t, src, "SetQuota(v int)", "type: int → int setter")
	assert.Contains(t, src, "SetBytesUsed(v int64)", "type: int64 → int64 setter")
	assert.Contains(t, src, "SetScore(v float64)", "type: float64 → float64 setter")
	assert.Contains(t, src, "SetActive(v bool)", "type: bool → bool setter")
	assert.Contains(t, src, "SetCreatedAt(v time.Time)", "type: time → time.Time setter")
	assert.Contains(t, src, "SetTtl(v time.Duration)", "type: duration → time.Duration setter")
	// The any fallback must not appear for a typed custom field.
	assert.NotContains(t, src, "SetEmail(v any)", "custom fields must never emit `any` when typed")

	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "typed.go", src, parser.AllErrors)
	require.NoError(t, parseErr, "generated source must parse as valid Go:\n%s", src)
}

// TestGenerate_Builders_DefaultTypeString confirms that an optional
// custom field WITHOUT an explicit `type:` annotation emits a
// `Set<Name>(v string)` setter — the documented default (B-01).
func TestGenerate_Builders_DefaultTypeString(t *testing.T) {
	t.Parallel()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write: [user_create]
events:
  user_create:
    fields:
      outcome:  {required: true}
      actor_id: {required: true}
      nickname: {}
`))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = generate(&buf, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		Types: true, Fields: true, Builders: true,
	})
	require.NoError(t, err)

	src := buf.String()
	assert.Contains(t, src, "SetNickname(v string)",
		"custom field with no `type:` defaults to string")
	assert.NotContains(t, src, "SetNickname(v any)",
		"the old `any` default is the #575 gap this issue closes")
}

// TestGenerate_Builders_FieldsGodocContract verifies the generated
// `Fields()` method carries the no-mutation contract note (B-16).
func TestGenerate_Builders_FieldsGodocContract(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		Types: true, Builders: true,
	})
	require.NoError(t, err)
	src := buf.String()
	assert.Contains(t, src, "Callers MUST NOT mutate",
		"Fields() godoc must state the no-mutation contract")
	// The godoc wraps across lines — check the unique phrase that
	// does not break mid-identifier.
	assert.Contains(t, src, "ownership via the [audit.FieldsDonor] fast path",
		"Fields() godoc must cite the ownership transfer contract")
}

// TestGenerate_Builders_StandardSettersExplicit verifies that
// -standard-setters=explicit trims the generated output to only the
// reserved standard fields that appear in the taxonomy's `fields:`
// map — B-38.
func TestGenerate_Builders_StandardSettersExplicit(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))

	var bufExplicit, bufAll bytes.Buffer
	err := generate(&bufExplicit, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		StandardSettersMode: "explicit",
		Types:               true, Builders: true,
	})
	require.NoError(t, err)
	err = generate(&bufAll, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		StandardSettersMode: "all",
		Types:               true, Builders: true,
	})
	require.NoError(t, err)

	explicit := bufExplicit.String()
	all := bufAll.String()

	// Reserved fields NOT declared in the taxonomy's fields: map must
	// be absent in explicit mode.
	assert.NotContains(t, explicit, "SetDestPort(v int)",
		"explicit mode omits setters for reserved fields not in the taxonomy")
	// Same reserved field IS present in `all` mode.
	assert.Contains(t, all, "SetDestPort(v int)",
		"all mode retains setters for every reserved field")
	// Explicit mode is noticeably shorter than all mode.
	assert.Less(t, len(explicit), len(all),
		"explicit mode must trim generator output")

	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "explicit.go", explicit, parser.AllErrors)
	require.NoError(t, parseErr, "explicit output must parse as valid Go")
}

// TestGenerate_Builders_StandardSettersAll_Default confirms the
// default behaviour (-standard-setters=all) is unchanged when the
// mode field is empty (backwards-compatible with pre-#575
// generateOptions) — B-38.
func TestGenerate_Builders_StandardSettersAll_Default(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, filepath.Join("testdata", "valid_taxonomy.yaml"))
	var buf bytes.Buffer
	err := generate(&buf, *tax, generateOptions{
		Package: "myapp", Header: "// test",
		Types: true, Builders: true,
		// StandardSettersMode left empty — should behave like "all".
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "SetDestPort(v int)",
		"empty StandardSettersMode must default to all-setters behaviour")
}

// TestParseTaxonomyYAML_UnknownFieldType_Rejected verifies the
// parse-time error when a custom field declares an unsupported type.
// The error message MUST list the accepted set (matches #447 UX).
func TestParseTaxonomyYAML_UnknownFieldType_Rejected(t *testing.T) {
	t.Parallel()
	_, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write: [user_create]
events:
  user_create:
    fields:
      outcome:  {required: true}
      actor_id: {required: true}
      bogus:    {type: strng}
`))
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, `unknown type "strng"`)
	assert.Contains(t, msg, `bogus`)
	// Valid set listed.
	for _, ty := range []string{"string", "int", "int64", "float64", "bool", "time", "duration"} {
		assert.Contains(t, msg, ty, "valid type %q must appear in error", ty)
	}
}

// TestRun_UnicodeEventNames pins that audit-gen rejects YAML
// taxonomies with Unicode (non-ASCII) event-type names. The
// taxonomy validator (see #477) enforces an ASCII identifier
// charset for event names so generated Go constants compile and
// don't surprise downstream tooling with bidi or homoglyph
// characters. The original issue title framed this as
// "supports Unicode" but the actual contract is rejection;
// this test pins the rejection wording. (#565 G9).
func TestRun_UnicodeEventNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yaml := filepath.Join(dir, "tax.yaml")
	require.NoError(t, os.WriteFile(yaml, []byte(`version: 1
events:
  user_créate:
    fields:
      outcome: {required: true}
`), 0o600))

	var stderr bytes.Buffer
	code := run([]string{
		"-input", yaml,
		"-output", filepath.Join(dir, "out.go"),
		"-package", "mypkg",
	}, &bytes.Buffer{}, &stderr)
	assert.NotEqual(t, exitSuccess, code,
		"taxonomy with non-ASCII event name must be rejected")
	// The validator's diagnostic is the surface — pin "user_créate" so
	// a clearer error wording change is visible in the diff.
	assert.Contains(t, stderr.String(), "user_créate",
		"diagnostic must name the offending event type")
}

// TestGenerate_VeryLargeTaxonomy proves the codegen handles a
// 1000-event taxonomy without timeout, panic, or pathological
// memory growth. The output must compile (Go AST parse) — pinning
// that the template scales to realistic enterprise taxonomies.
// (#565 G9).
func TestGenerate_VeryLargeTaxonomy(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	sb.WriteString("version: 1\ncategories:\n  bulk:\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, "    - large_event_%d\n", i)
	}
	sb.WriteString("events:\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, "  large_event_%d:\n    fields:\n      outcome: {required: true}\n", i)
	}
	tax, err := audit.ParseTaxonomyYAML([]byte(sb.String()))
	require.NoError(t, err, "1000-event taxonomy must parse")

	var buf bytes.Buffer
	require.NoError(t, generate(&buf, *tax, defaultOpts()),
		"generate must handle 1000-event taxonomy without error")
	assert.Greater(t, buf.Len(), 50_000,
		"output for 1000 events must be substantially larger than a small taxonomy")

	// Output must parse as valid Go.
	fset := token.NewFileSet()
	_, parseErr := parser.ParseFile(fset, "gen.go", buf.Bytes(), parser.AllErrors)
	require.NoError(t, parseErr, "generated code must parse as valid Go")
}

// TestRun_OutputFileInNonexistentDirectory pins that the binary
// returns a non-zero exit code (and prints a clear diagnostic)
// when -output points at a path whose parent directory does not
// exist. Operators rely on this surface to detect typos in CI
// pipelines without silently producing partial output. (#565 G9).
func TestRun_OutputFileInNonexistentDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bogusOutput := filepath.Join(dir, "no-such-subdir", "out.go")
	var stderr bytes.Buffer
	code := run([]string{
		"-input", "testdata/valid_taxonomy.yaml",
		"-output", bogusOutput,
		"-package", "mypkg",
	}, &bytes.Buffer{}, &stderr)
	assert.NotEqual(t, exitSuccess, code,
		"output to non-existent parent directory must fail with non-zero exit code")
	// No partial file written.
	_, statErr := os.Stat(bogusOutput)
	assert.True(t, os.IsNotExist(statErr) || errors.Is(statErr, os.ErrNotExist),
		"no partial output file must be created on failure")
}
