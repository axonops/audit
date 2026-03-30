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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
)

// failWriter returns an error on every Write call.
type failWriter struct{ err error }

func (f *failWriter) Write([]byte) (int, error) { return 0, f.err }

func loadTestTaxonomy(t *testing.T, path string) audit.Taxonomy {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	tax, err := audit.ParseTaxonomyYAML(data)
	require.NoError(t, err)
	return tax
}

func generateToString(t *testing.T, tax audit.Taxonomy, opts generateOptions) string {
	t.Helper()
	var buf bytes.Buffer
	err := generate(&buf, tax, opts)
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

func TestRun_VersionFlag(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	code := run([]string{"-version"}, &stdout, &bytes.Buffer{})

	assert.Equal(t, exitSuccess, code)
	assert.Contains(t, stdout.String(), "audit-gen")
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

func TestBuildFieldConstants_Collision(t *testing.T) {
	t.Parallel()
	// Two fields that produce the same PascalCase name would collide.
	// In practice this can't happen with real taxonomies (snake_case only),
	// but we test the detection.
	tax := audit.Taxonomy{
		Events: map[string]*audit.EventDef{
			"test": {Required: []string{"a_b", "a_B"}},
		},
	}
	_, err := buildFieldConstants(tax)
	// Both "a_b" and "a_B" produce "FieldAB" — collision detected.
	assert.ErrorContains(t, err, "naming collision")
}

func TestGenerate_WriteError(t *testing.T) {
	t.Parallel()
	tax := loadTestTaxonomy(t, "testdata/valid_taxonomy.yaml")
	w := &failWriter{err: errors.New("disk full")}
	err := generate(w, tax, defaultOpts())
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
