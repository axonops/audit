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

package outputconfig_test

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
	_ "github.com/axonops/go-audit/file" // register file factory
	"github.com/axonops/go-audit/outputconfig"
)

func testTaxonomy(t *testing.T) audit.Taxonomy {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
    - user_delete
  security:
    - auth_failure
  read:
    - user_read
default_enabled:
  - write
  - security
  - read
events:
  user_create:
    category: write
    required: [outcome, actor_id]
  user_delete:
    category: write
    required: [outcome, actor_id]
  auth_failure:
    category: security
    required: [outcome]
  user_read:
    category: read
    required: [outcome]
`))
	require.NoError(t, err, "test taxonomy parse")
	return tax
}

// --- Valid configs ---

func TestLoad_MinimalStdout(t *testing.T) {
	data, err := os.ReadFile("testdata/minimal_config.yaml")
	require.NoError(t, err)

	tax := testTaxonomy(t)
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Len(t, result.Outputs, 1)
	assert.Equal(t, "console", result.Outputs[0].Name)
	assert.Nil(t, result.Outputs[0].Route)
	assert.Nil(t, result.Outputs[0].Formatter)
	assert.Nil(t, result.DefaultFormatter)
	assert.NotEmpty(t, result.Options)
}

func TestLoad_FileWithRoute(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUDIT_TEST_DIR", dir)

	data, err := os.ReadFile("testdata/valid_config.yaml")
	require.NoError(t, err)

	tax := testTaxonomy(t)
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Len(t, result.Outputs, 2)

	// First output: stdout (console)
	assert.Equal(t, "console", result.Outputs[0].Name)

	// Second output: file with route
	assert.Equal(t, "audit_log", result.Outputs[1].Name)
	require.NotNil(t, result.Outputs[1].Route)
	assert.Equal(t, []string{"write", "security"}, result.Outputs[1].Route.IncludeCategories)

	// Default formatter should be set
	require.NotNil(t, result.DefaultFormatter)
}

func TestLoad_MultipleOutputs(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte(`
version: 1
outputs:
  out1:
    type: stdout
  out2:
    type: file
    file:
      path: ` + filepath.Join(dir, "a.log") + `
  out3:
    type: file
    file:
      path: ` + filepath.Join(dir, "b.log") + `
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 3)

	// Clean up outputs.
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithPerOutputFormatter(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte(`
version: 1
outputs:
  cef_file:
    type: file
    file:
      path: ` + filepath.Join(dir, "cef.log") + `
    formatter:
      type: cef
      vendor: AxonOps
      product: Test
      version: "1.0"
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)

	assert.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Formatter)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledFalse_SkipsOutput(t *testing.T) {
	yaml := []byte(`
version: 1
outputs:
  active:
    type: stdout
  disabled:
    type: stdout
    enabled: false
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)

	assert.Len(t, result.Outputs, 1)
	assert.Equal(t, "active", result.Outputs[0].Name)

	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledTrue_Explicit(t *testing.T) {
	yaml := []byte(`
version: 1
outputs:
  console:
    type: stdout
    enabled: true
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	_ = result.Outputs[0].Output.Close()
}

// --- Error cases ---

func TestLoad_EmptyInput(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(nil, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoad_OversizedInput(t *testing.T) {
	tax := testTaxonomy(t)
	big := make([]byte, outputconfig.MaxOutputConfigSize+1)
	for i := range big {
		big[i] = 'x'
	}
	_, err := outputconfig.Load(big, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestLoad_InvalidYAML(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("{{broken"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_MultiDocument(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\noutputs:\n  c:\n    type: stdout\n---\nversion: 1\n")
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "multiple YAML documents")
}

func TestLoad_Version0(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 0\noutputs:\n  c:\n    type: stdout\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestLoad_Version2(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 2\noutputs:\n  c:\n    type: stdout\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestLoad_NoOutputs(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 1\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "at least one output")
}

func TestLoad_EmptyOutputs(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 1\noutputs: {}\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "at least one output")
}

func TestLoad_MissingType(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\noutputs:\n  bad:\n    enabled: true\n")
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "missing required field 'type'")
}

func TestLoad_UnknownType(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\noutputs:\n  bad:\n    type: kafka\n")
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown output type \"kafka\"")
	assert.Contains(t, err.Error(), "did you import")
}

func TestLoad_DuplicateOutputName(t *testing.T) {
	// yaml.v3 Node parser preserves duplicate mapping keys.
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  dupe:\n    type: stdout\n  dupe:\n    type: stdout\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "duplicate output name")
}

func TestLoad_TwoDistinctNames(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  a:\n    type: stdout\n  b:\n    type: stdout\n")
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 2)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_UnknownTopLevelKey(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\nmetrics: true\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown top-level key")
	assert.Contains(t, err.Error(), "metrics")
}

func TestLoad_AllDisabled(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  a:\n    type: stdout\n    enabled: false\n  b:\n    type: stdout\n    enabled: false\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "all outputs are disabled")
}

func TestLoad_RouteUnknownCategory(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte(`
version: 1
outputs:
  bad:
    type: stdout
    route:
      include_categories: [nonexistent]
`)
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestLoad_RouteMixedIncludeExclude(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte(`
version: 1
outputs:
  bad:
    type: stdout
    route:
      include_categories: [write]
      exclude_categories: [security]
`)
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
}

func TestLoad_EnvVarInConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEST_AUDIT_PATH", filepath.Join(dir, "env.log"))

	yaml := []byte(`
version: 1
outputs:
  env_file:
    type: file
    file:
      path: ${TEST_AUDIT_PATH}
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_MissingEnvVar(t *testing.T) {
	yaml := []byte(`
version: 1
outputs:
  bad:
    type: file
    file:
      path: ${TOTALLY_MISSING_VAR}
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "TOTALLY_MISSING_VAR")
}

func TestLoad_DefaultFormatter(t *testing.T) {
	yaml := []byte(`
version: 1
default_formatter:
  type: json
  timestamp: unix_ms
  omit_empty: true
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)

	require.NotNil(t, result.DefaultFormatter)
	jf, ok := result.DefaultFormatter.(*audit.JSONFormatter)
	require.True(t, ok)
	assert.Equal(t, audit.TimestampUnixMillis, jf.Timestamp)
	assert.True(t, jf.OmitEmpty)

	_ = result.Outputs[0].Output.Close()
}

func TestLoad_InvalidDefaultFormatter(t *testing.T) {
	yaml := []byte(`
version: 1
default_formatter:
  type: protobuf
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "default_formatter")
	assert.Contains(t, err.Error(), "protobuf")
}

func TestLoad_OptionsContainWithNamedOutput(t *testing.T) {
	yaml := []byte(`
version: 1
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yaml, &tax, nil)
	require.NoError(t, err)

	// Options should contain at least one WithNamedOutput.
	assert.NotEmpty(t, result.Options)

	// Verify options can be applied to NewLogger without error.
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestLoad_ConfigKeyMismatch(t *testing.T) {
	yaml := []byte(`
version: 1
outputs:
  bad:
    type: file
    syslog:
      network: tcp
      address: localhost:514
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(yaml, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "does not match type")
}

// --- Additional branch coverage tests (from test-writer review) ---

func TestLoad_TopLevelSequence_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("- item1\n- item2\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_OutputsIsSequence_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 1\noutputs:\n  - stdout\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_OutputValueIsScalar_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 1\noutputs:\n  bad: scalar_value\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
}

func TestLoad_EnabledInvalidValue_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load([]byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    enabled: not_a_bool\n"), &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_TwoTypeConfigBlocks_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    file:\n      path: /tmp/a\n    syslog:\n      network: tcp\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unexpected key")
	assert.Contains(t, err.Error(), "type-specific config block")
}

func TestLoad_RouteUnknownField_Rejected(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    route:\n      include_category: [write]\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_PerOutputFormatterInvalid_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    formatter:\n      type: protobuf\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "protobuf")
}

func TestLoad_RouteWithEventTypes(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  filtered:\n    type: stdout\n    route:\n      include_event_types: [user_create]\n")
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Equal(t, []string{"user_create"}, result.Outputs[0].Route.IncludeEventTypes)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_RouteExcludeEventTypes(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  filtered:\n    type: stdout\n    route:\n      exclude_event_types: [auth_failure]\n")
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Equal(t, []string{"auth_failure"}, result.Outputs[0].Route.ExcludeEventTypes)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledFalseBeforeType(t *testing.T) {
	// Verify enabled: false works regardless of key ordering in YAML.
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  active:\n    type: stdout\n  skipped:\n    enabled: false\n    type: stdout\n")
	result, err := outputconfig.Load(data, &tax, nil)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	assert.Equal(t, "active", result.Outputs[0].Name)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_MissingEnvVarInFormatter(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    formatter:\n      type: json\n      timestamp: ${MISSING_FMT_VAR}\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "MISSING_FMT_VAR")
}

func TestLoad_MissingEnvVarInRoute(t *testing.T) {
	tax := testTaxonomy(t)
	// Route values are string sequences — env var in a sequence element.
	data := []byte("version: 1\noutputs:\n  bad:\n    type: stdout\n    route:\n      include_categories:\n        - ${MISSING_ROUTE_VAR}\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "MISSING_ROUTE_VAR")
}

func TestLoad_EndToEnd_EventsFlowThrough(t *testing.T) {
	dir := t.TempDir()
	yamlCfg := []byte(`
version: 1
outputs:
  all_events:
    type: file
    file:
      path: ` + filepath.Join(dir, "all.log") + `
  write_only:
    type: file
    file:
      path: ` + filepath.Join(dir, "writes.log") + `
    route:
      include_categories: [write]
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(yamlCfg, &tax, nil)
	require.NoError(t, err)

	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	require.NoError(t, err)

	// Emit a write event and a read event.
	require.NoError(t, logger.Audit("user_create", audit.Fields{"outcome": "success", "actor_id": "alice"}))
	require.NoError(t, logger.Audit("user_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, logger.Close())

	// all.log should have both events.
	allData, err := os.ReadFile(filepath.Join(dir, "all.log"))
	require.NoError(t, err)
	assert.Contains(t, string(allData), "user_create")
	assert.Contains(t, string(allData), "user_read")

	// writes.log should have only the write event.
	writesData, err := os.ReadFile(filepath.Join(dir, "writes.log"))
	require.NoError(t, err)
	assert.Contains(t, string(writesData), "user_create")
	assert.NotContains(t, string(writesData), "user_read")
}

// spyOutput tracks whether Close was called, for resource leak tests.
type spyOutput struct {
	closed atomic.Bool
}

func (s *spyOutput) Write([]byte) error { return nil }
func (s *spyOutput) Close() error       { s.closed.Store(true); return nil }
func (s *spyOutput) Name() string       { return "spy" }

func TestLoad_ClosesOutputOnRouteError(t *testing.T) {
	spy := &spyOutput{}
	audit.RegisterOutputFactory("spy", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return spy, nil
	})
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  leak:\n    type: spy\n    route:\n      include_categories: [nonexistent]\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.True(t, spy.closed.Load(), "output must be closed when buildRoute fails")
}

func TestLoad_ClosesOutputOnFormatterError(t *testing.T) {
	spy := &spyOutput{}
	audit.RegisterOutputFactory("spy", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return spy, nil
	})
	tax := testTaxonomy(t)
	data := []byte("version: 1\noutputs:\n  leak:\n    type: spy\n    formatter:\n      type: protobuf\n")
	_, err := outputconfig.Load(data, &tax, nil)
	require.Error(t, err)
	assert.True(t, spy.closed.Load(), "output must be closed when buildOutputFormatter fails")
}
