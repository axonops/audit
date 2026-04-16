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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register file factory
	"github.com/axonops/audit/outputconfig"
	"go.uber.org/goleak"
)

func testTaxonomy(t *testing.T) *audit.Taxonomy {
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
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  user_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
  user_read:
    fields:
      outcome: {required: true}
`))
	require.NoError(t, err, "test taxonomy parse")
	return tax
}

// --- Valid configs ---

func TestLoad_MinimalStdout(t *testing.T) {
	data, err := os.ReadFile("testdata/minimal_config.yaml")
	require.NoError(t, err)

	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
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
	assert.NotEmpty(t, result.Options)
}

func TestLoad_FileWithRoute(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUDIT_TEST_DIR", dir)

	data, err := os.ReadFile("testdata/valid_config.yaml")
	require.NoError(t, err)

	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
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
}

func TestLoad_MultipleOutputs(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte(`
version: 1
app_name: test
host: test
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
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 3)

	// Clean up outputs.
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// lokiStubOutput is a minimal output stub for testing Loki formatter
// validation without depending on the real Loki module.
type lokiStubOutput struct{}

func (l *lokiStubOutput) Write([]byte) error { return nil }
func (l *lokiStubOutput) Close() error       { return nil }
func (l *lokiStubOutput) Name() string       { return "loki-stub" }

func init() {
	audit.RegisterOutputFactory("loki", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return &lokiStubOutput{}, nil
	})
}

func TestLoad_LokiRejectsNonJSONFormatter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		formatter string
	}{
		{"cef", "cef"},
		{"cloudevents", "cloudevents"},
		{"unknown", "protobuf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax := testTaxonomy(t)
			data := []byte(fmt.Sprintf(`
version: 1
app_name: test
host: test
outputs:
  loki_out:
    type: loki
    formatter:
      type: %s
`, tt.formatter))
			_, err := outputconfig.Load(context.Background(), data, tax)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "loki does not support custom formatters")
			assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
		})
	}
}

func TestLoad_LokiAcceptsExplicitJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
	}{
		{
			"explicit json type",
			`
version: 1
app_name: test
host: test
outputs:
  loki_out:
    type: loki
    formatter:
      type: json
`,
		},
		{
			"json with custom timestamp",
			`
version: 1
app_name: test
host: test
outputs:
  loki_out:
    type: loki
    formatter:
      type: json
      timestamp: unix_ms
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax := testTaxonomy(t)
			result, err := outputconfig.Load(context.Background(), []byte(tt.yaml), tax)
			require.NoError(t, err)
			assert.Len(t, result.Outputs, 1)
			require.NotNil(t, result.Outputs[0].Formatter, "explicit JSON should set per-output formatter")
			_, isJSON := result.Outputs[0].Formatter.(*audit.JSONFormatter)
			assert.True(t, isJSON, "formatter should be *audit.JSONFormatter")
			_ = result.Outputs[0].Output.Close()
		})
	}
}

func TestLoad_DefaultFormatterRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
default_formatter:
  type: cef
  vendor: Test
  product: Test
  version: "1.0"
outputs:
  console:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_formatter has been removed")
	assert.Contains(t, err.Error(), "set formatter on each output individually")
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_DefaultFormatterJSON_AlsoRejected(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
default_formatter:
  type: json
outputs:
  console:
    type: stdout
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_formatter has been removed")
}

func TestLoad_NoFormatterDefaultsToJSON(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
  loki_out:
    type: loki
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.Len(t, result.Outputs, 2)
	// Both outputs have nil per-output formatter — they inherit the
	// logger's default JSONFormatter at runtime via effectiveFormatter.
	assert.Nil(t, result.Outputs[0].Formatter)
	assert.Nil(t, result.Outputs[1].Formatter)
	_ = result.Outputs[0].Output.Close()
	_ = result.Outputs[1].Output.Close()
}

func TestLoad_LokiDisabledWithCEF_NoError(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
  loki_out:
    type: loki
    enabled: false
    formatter:
      type: cef
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err, "disabled Loki output with CEF formatter should not cause an error")
	assert.Len(t, result.Outputs, 1, "only the stdout output should be active")
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_LokiRejectsScalarCEF(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  loki_out:
    type: loki
    formatter: cef
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loki does not support custom formatters")
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_WithPerOutputFormatter(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte(`
version: 1
app_name: test
host: test
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
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)

	assert.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Formatter)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledFalse_SkipsOutput(t *testing.T) {
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  active:
    type: stdout
  disabled:
    type: stdout
    enabled: false
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)

	assert.Len(t, result.Outputs, 1)
	assert.Equal(t, "active", result.Outputs[0].Name)

	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledTrue_Explicit(t *testing.T) {
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
    enabled: true
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	_ = result.Outputs[0].Output.Close()
}

// --- Error cases ---

func TestLoad_EmptyInput(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), nil, tax)
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
	_, err := outputconfig.Load(context.Background(), big, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestLoad_InvalidYAML(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("{{broken"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_MultiDocument(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n---\nversion: 1\n")
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "multiple YAML documents")
}

func TestLoad_Version0(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 0\noutputs:\n  c:\n    type: stdout\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestLoad_Version2(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 2\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestLoad_NoOutputs(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 1\napp_name: test\nhost: test\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "at least one output")
}

func TestLoad_EmptyOutputs(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 1\napp_name: test\nhost: test\noutputs: {}\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "at least one output")
}

func TestLoad_MissingType(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    enabled: true\n")
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "missing required field 'type'")
}

func TestLoad_UnknownType(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: kafka\n")
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown output type \"kafka\"")
	assert.Contains(t, err.Error(), "add import")
	assert.Contains(t, err.Error(), "audit/outputs")
	assert.Contains(t, err.Error(), "for all types")
}

func TestLoad_DuplicateOutputName(t *testing.T) {
	// goccy/go-yaml detects duplicate mapping keys at parse time.
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  dupe:\n    type: stdout\n  dupe:\n    type: stdout\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "dupe")
}

func TestLoad_TwoDistinctNames(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  a:\n    type: stdout\n  b:\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 2)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_UnknownTopLevelKey(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\nmetrics: true\noutputs:\n  c:\n    type: stdout\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown top-level key")
	assert.Contains(t, err.Error(), "metrics")
}

func TestLoad_AllDisabled(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  a:\n    type: stdout\n    enabled: false\n  b:\n    type: stdout\n    enabled: false\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "all outputs are disabled")
}

func TestLoad_RouteUnknownCategory(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: stdout
    route:
      include_categories: [nonexistent]
`)
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestLoad_RouteMixedIncludeExclude(t *testing.T) {
	tax := testTaxonomy(t)
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: stdout
    route:
      include_categories: [write]
      exclude_categories: [security]
`)
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
}

func TestLoad_EnvVarInConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEST_AUDIT_PATH", filepath.Join(dir, "env.log"))

	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  env_file:
    type: file
    file:
      path: ${TEST_AUDIT_PATH}
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_MissingEnvVar(t *testing.T) {
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: file
    file:
      path: ${TOTALLY_MISSING_VAR}
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "TOTALLY_MISSING_VAR")
}

func TestLoad_OptionsContainWithNamedOutput(t *testing.T) {
	defer goleak.VerifyNone(t)
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), yaml, tax)
	require.NoError(t, err)

	// Options should contain at least one WithNamedOutput.
	assert.NotEmpty(t, result.Options)

	// Verify options can be applied to NewLogger without error.
	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(opts...)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestLoad_ConfigKeyMismatch(t *testing.T) {
	yaml := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: file
    syslog:
      network: tcp
      address: localhost:514
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), yaml, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "does not match type")
}

// --- Additional branch coverage tests (from test-writer review) ---

func TestLoad_TopLevelSequence_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("- item1\n- item2\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_OutputsIsSequence_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  - stdout\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_OutputValueIsScalar_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad: scalar_value\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "bad")
}

func TestLoad_EnabledInvalidValue_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    enabled: not_a_bool\n"), tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_TwoTypeConfigBlocks_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    file:\n      path: /tmp/a\n    syslog:\n      network: tcp\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unexpected key")
	assert.Contains(t, err.Error(), "type-specific config block")
}

func TestLoad_RouteUnknownField_Rejected(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    route:\n      include_category: [write]\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_PerOutputFormatterInvalid_ReturnsError(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    formatter:\n      type: protobuf\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "protobuf")
}

func TestLoad_RouteWithEventTypes(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  filtered:\n    type: stdout\n    route:\n      include_event_types: [user_create]\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Equal(t, []string{"user_create"}, result.Outputs[0].Route.IncludeEventTypes)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_RouteExcludeEventTypes(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  filtered:\n    type: stdout\n    route:\n      exclude_event_types: [auth_failure]\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Equal(t, []string{"auth_failure"}, result.Outputs[0].Route.ExcludeEventTypes)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_EnabledFalseBeforeType(t *testing.T) {
	// Verify enabled: false works regardless of key ordering in YAML.
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  active:\n    type: stdout\n  skipped:\n    enabled: false\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	assert.Len(t, result.Outputs, 1)
	assert.Equal(t, "active", result.Outputs[0].Name)
	_ = result.Outputs[0].Output.Close()
}

func TestLoad_MissingEnvVarInFormatter(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    formatter:\n      type: json\n      timestamp: ${MISSING_FMT_VAR}\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "MISSING_FMT_VAR")
}

func TestLoad_MissingEnvVarInRoute(t *testing.T) {
	tax := testTaxonomy(t)
	// Route values are string sequences — env var in a sequence element.
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  bad:\n    type: stdout\n    route:\n      include_categories:\n        - ${MISSING_ROUTE_VAR}\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "MISSING_ROUTE_VAR")
}

func TestLoad_EndToEnd_EventsFlowThrough(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := t.TempDir()
	yamlCfg := []byte(`
version: 1
app_name: test
host: test
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
	result, err := outputconfig.Load(context.Background(), yamlCfg, tax)
	require.NoError(t, err)

	opts := []audit.Option{audit.WithTaxonomy(tax)}
	opts = append(opts, result.Options...)
	logger, err := audit.NewLogger(opts...)
	require.NoError(t, err)

	// Emit a write event and a read event.
	require.NoError(t, logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success", "actor_id": "alice"})))
	require.NoError(t, logger.AuditEvent(audit.NewEvent("user_read", audit.Fields{"outcome": "success"})))
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
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  leak:\n    type: spy\n    route:\n      include_categories: [nonexistent]\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.True(t, spy.closed.Load(), "output must be closed when buildRoute fails")
}

func TestLoad_ClosesOutputOnFormatterError(t *testing.T) {
	spy := &spyOutput{}
	audit.RegisterOutputFactory("spy", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return spy, nil
	})
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  leak:\n    type: spy\n    formatter:\n      type: protobuf\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.True(t, spy.closed.Load(), "output must be closed when buildOutputFormatter fails")
}

func TestLoad_ClosesEarlierOutputsWhenLaterFails(t *testing.T) {
	spy := &spyOutput{}
	audit.RegisterOutputFactory("spy", func(_ string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return spy, nil
	})
	tax := testTaxonomy(t)
	// First output (spy) succeeds. Second output (unknown type) fails.
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  good:\n    type: spy\n  bad:\n    type: nonexistent_type\n")
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.True(t, spy.closed.Load(),
		"first output must be closed when second output construction fails")
}

func TestLoadResult_String_NoCredentials(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  console:\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	s := result.String()
	assert.Contains(t, s, "console")
	assert.Contains(t, s, "options: 3") // WithAppName + WithHost + WithNamedOutput
	assert.NotContains(t, s, "Authorization")
	assert.NotContains(t, s, "Bearer")
}

func TestLoadResult_String_Nil(t *testing.T) {
	var r *outputconfig.LoadResult
	assert.Equal(t, "<nil>", r.String())
}

func TestNamedOutput_String_NoCredentials(t *testing.T) {
	no := &outputconfig.NamedOutput{
		Name: "test_output",
	}
	s := no.String()
	assert.Contains(t, s, "test_output")
	assert.NotContains(t, s, "Authorization")
}

func TestNamedOutput_String_Nil(t *testing.T) {
	var no *outputconfig.NamedOutput
	assert.Equal(t, "<nil>", no.String())
}

// --- Severity routing YAML tests (#187) ---

func TestLoad_RouteWithMinSeverity(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  alerts:
    type: stdout
    route:
      min_severity: 7
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Route)
	require.NotNil(t, result.Outputs[0].Route.MinSeverity)
	assert.Equal(t, 7, *result.Outputs[0].Route.MinSeverity)
	assert.Nil(t, result.Outputs[0].Route.MaxSeverity)
}

func TestLoad_RouteWithMaxSeverity(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  debug:
    type: stdout
    route:
      max_severity: 3
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Nil(t, result.Outputs[0].Route.MinSeverity)
	require.NotNil(t, result.Outputs[0].Route.MaxSeverity)
	assert.Equal(t, 3, *result.Outputs[0].Route.MaxSeverity)
}

func TestLoad_RouteWithMinAndMaxSeverity(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  band:
    type: stdout
    route:
      min_severity: 3
      max_severity: 7
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Route)
	require.NotNil(t, result.Outputs[0].Route.MinSeverity)
	require.NotNil(t, result.Outputs[0].Route.MaxSeverity)
	assert.Equal(t, 3, *result.Outputs[0].Route.MinSeverity)
	assert.Equal(t, 7, *result.Outputs[0].Route.MaxSeverity)
}

func TestLoad_RouteWithSeverityOmitted(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  plain:
    type: stdout
    route:
      include_categories: [write]
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Nil(t, result.Outputs[0].Route.MinSeverity,
		"severity omitted should be nil, not pointer-to-zero")
	assert.Nil(t, result.Outputs[0].Route.MaxSeverity)
}

func TestLoad_RouteMinSeverityOutOfRange(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: stdout
    route:
      min_severity: 11
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_severity 11 out of range 0-10")
}

func TestLoad_RouteMaxSeverityOutOfRange(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: stdout
    route:
      max_severity: -1
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_severity -1 out of range 0-10")
}

func TestLoad_RouteMinGreaterThanMax(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  bad:
    type: stdout
    route:
      min_severity: 8
      max_severity: 3
`)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_severity 8 exceeds max_severity 3")
}

func TestLoad_RouteSeverityZeroIsValid(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  zero:
    type: stdout
    route:
      min_severity: 0
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err, "severity 0 is a valid value, not rejected as zero-value")
	require.NotNil(t, result.Outputs[0].Route.MinSeverity)
	assert.Equal(t, 0, *result.Outputs[0].Route.MinSeverity,
		"severity 0 must be pointer-to-zero, not nil")
}

func TestLoad_RouteSeverityWithCategories(t *testing.T) {
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  combined:
    type: stdout
    route:
      include_categories: [security]
      min_severity: 7
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].Route)
	assert.Equal(t, []string{"security"}, result.Outputs[0].Route.IncludeCategories)
	require.NotNil(t, result.Outputs[0].Route.MinSeverity)
	assert.Equal(t, 7, *result.Outputs[0].Route.MinSeverity)
}

// ---------------------------------------------------------------------------
// exclude_labels YAML parsing
// ---------------------------------------------------------------------------

func testTaxonomyWithSensitivity(t *testing.T) *audit.Taxonomy {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
sensitivity:
  labels:
    pii:
      fields: [email]
    financial:
      fields: [card_number]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      email: {}
      card_number: {}
`))
	require.NoError(t, err)
	return tax
}

func TestLoad_OutputWithExcludeLabels(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
    exclude_labels:
      - pii
      - financial
`)
	tax := testTaxonomyWithSensitivity(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Equal(t, []string{"pii", "financial"}, result.Outputs[0].ExcludeLabels)
}

func TestLoad_OutputWithExcludeLabels_Empty(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
    exclude_labels: []
`)
	tax := testTaxonomyWithSensitivity(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Empty(t, result.Outputs[0].ExcludeLabels)
}

func TestLoad_OutputWithExcludeLabels_NoSensitivity(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
    exclude_labels:
      - pii
`)
	tax := testTaxonomy(t) // no sensitivity config
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	// The Load itself succeeds — validation happens at NewLogger time.
	// Verify the labels are stored and will be passed through.
	require.Len(t, result.Outputs, 1)
	assert.Equal(t, []string{"pii"}, result.Outputs[0].ExcludeLabels)
}

// ---------------------------------------------------------------------------
// Logger config from YAML (#183)
// ---------------------------------------------------------------------------

func TestLoad_LoggerConfig_Defaults(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.Equal(t, 0, result.Config.QueueSize, "zero means applyDefaults will set 10000")
	assert.Equal(t, time.Duration(0), result.Config.DrainTimeout, "zero means applyDefaults will set 5s")
	assert.Equal(t, audit.ValidationMode(""), result.Config.ValidationMode, "empty means applyDefaults will set strict")
	assert.False(t, result.Config.OmitEmpty)
}

func TestLoad_LoggerConfig_AllFields(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  enabled: true
  queue_size: 50000
  drain_timeout: "30s"
  validation_mode: warn
  omit_empty: true
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.Equal(t, 50000, result.Config.QueueSize)
	assert.Equal(t, 30*time.Second, result.Config.DrainTimeout)
	assert.Equal(t, audit.ValidationMode("warn"), result.Config.ValidationMode)
	assert.True(t, result.Config.OmitEmpty)
}

func TestLoad_LoggerConfig_PartialFields(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  queue_size: 25000
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.Equal(t, 25000, result.Config.QueueSize)
	assert.Equal(t, time.Duration(0), result.Config.DrainTimeout, "default drain timeout")
}

func TestLoad_LoggerConfig_EnabledFalse(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  enabled: false
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
}

func TestLoad_LoggerConfig_EnvVars(t *testing.T) {
	t.Setenv("TEST_BUFFER_SIZE", "75000")
	t.Setenv("TEST_DRAIN_TIMEOUT", "15s")

	data := []byte(`
version: 1
app_name: test
host: test
logger:
  queue_size: ${TEST_BUFFER_SIZE}
  drain_timeout: "${TEST_DRAIN_TIMEOUT}"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.Equal(t, 75000, result.Config.QueueSize)
	assert.Equal(t, 15*time.Second, result.Config.DrainTimeout)
}

func TestLoad_LoggerConfig_EnvVars_Boolean(t *testing.T) {
	t.Setenv("TEST_ENABLED", "false")
	t.Setenv("TEST_OMIT_EMPTY", "true")

	data := []byte(`
version: 1
app_name: test
host: test
logger:
  enabled: ${TEST_ENABLED}
  omit_empty: ${TEST_OMIT_EMPTY}
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	assert.True(t, result.Config.OmitEmpty)
}

func TestLoad_LoggerConfig_NotAMapping(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger: "not a mapping"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "logger")
}

func TestLoad_LoggerConfig_UnknownField(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  enabled: true
  bogus_field: 42
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "logger")
}

func TestLoad_LoggerConfig_NegativeBufferSize(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  queue_size: -1
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "non-negative")
}

func TestLoad_LoggerConfig_BufferSizeExceedsMax(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  queue_size: 2000000
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestLoad_LoggerConfig_NegativeDrainTimeout(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  drain_timeout: "-5s"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "non-negative")
}

func TestLoad_LoggerConfig_DrainTimeoutExceedsMax(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  drain_timeout: "120s"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestLoad_LoggerConfig_InvalidDrainTimeout(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  drain_timeout: "not-a-duration"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "duration")
}

func TestLoad_LoggerConfig_InvalidValidationMode(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
logger:
  validation_mode: invalid
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown mode")
}

func TestLoad_LoggerConfig_ValidationModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"strict", "warn", "permissive"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			data := []byte(fmt.Sprintf(`
version: 1
app_name: test
host: test
logger:
  validation_mode: %s
outputs:
  console:
    type: stdout
`, mode))
			tax := testTaxonomy(t)
			result, err := outputconfig.Load(context.Background(), data, tax)
			require.NoError(t, err)
			assert.Equal(t, audit.ValidationMode(mode), result.Config.ValidationMode)
		})
	}
}

// ---------------------------------------------------------------------------
// Global TLS policy (#220)
// ---------------------------------------------------------------------------

func TestLoad_GlobalTLSPolicy_AcceptedAtTopLevel(t *testing.T) {
	t.Parallel()
	// Global tls_policy with allow_tls12. The stdout output doesn't use
	// TLS, but the config should still parse without error.
	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: true
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
}

func TestLoad_GlobalTLSPolicy_NoGlobal(t *testing.T) {
	t.Parallel()
	// No global tls_policy — outputs should still work.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
}

func TestLoad_GlobalTLSPolicy_NotInjectedIntoFileOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Global tls_policy should NOT be injected into file outputs
	// (file doesn't support TLS), so this must succeed.
	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: true
outputs:
  audit_file:
    type: file
    file:
      path: "` + dir + `/audit.log"
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// testOutput is a minimal audit.Output for testing factory injection.
type testOutput struct{ name string }

func (o *testOutput) Write([]byte) error { return nil }
func (o *testOutput) Close() error       { return nil }
func (o *testOutput) Name() string       { return o.name }

func TestLoad_GlobalTLSPolicy_InjectedViaFactory(t *testing.T) {
	t.Parallel()
	// Register a test factory under the "webhook" type name so
	// the injection logic recognises it as TLS-capable.
	var captured atomic.Value
	audit.RegisterOutputFactory("webhook", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: true
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://example.com"
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)

	raw, ok := captured.Load().(string)
	require.True(t, ok, "factory should have been called")
	assert.Contains(t, raw, "tls_policy")
	assert.Contains(t, raw, "allow_tls12")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_GlobalTLSPolicy_PerOutputOverride(t *testing.T) {
	t.Parallel()
	var captured atomic.Value
	audit.RegisterOutputFactory("syslog", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: false
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "localhost:6514"
      tls_policy:
        allow_tls12: true
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)

	raw, ok := captured.Load().(string)
	require.True(t, ok)
	// Per-output override should be present, NOT the global one.
	assert.Contains(t, raw, "allow_tls12: true")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_GlobalTLSPolicy_UnknownField(t *testing.T) {
	t.Parallel()
	// The global tls_policy is validated eagerly by parseTopLevel using
	// KnownFields(true), regardless of output type. An unknown field
	// must be rejected at parse time.
	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: true
  bogus_field: true
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "tls_policy")
}

func TestLoad_GlobalTLSPolicy_MissingEnvVar(t *testing.T) {
	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: ${TOTALLY_MISSING_TLS_VAR}
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "tls_policy")
}

// ---------------------------------------------------------------------------
// HMAC config parsing (#216)
// ---------------------------------------------------------------------------

func TestLoad_HMAC_FullConfig(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "this-is-a-test-salt!"
      hash: HMAC-SHA-256
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.True(t, result.Outputs[0].HMACConfig.Enabled)
	assert.Equal(t, "v1", result.Outputs[0].HMACConfig.SaltVersion)
	assert.Equal(t, "HMAC-SHA-256", result.Outputs[0].HMACConfig.Algorithm)
}

func TestLoad_HMAC_Disabled_Default(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Nil(t, result.Outputs[0].HMACConfig)
}

func TestLoad_HMAC_ExplicitlyDisabled(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
    hmac:
      enabled: false
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.Len(t, result.Outputs, 1)
	assert.Nil(t, result.Outputs[0].HMACConfig, "disabled HMAC should be nil")
}

func TestLoad_HMAC_SaltTooShort(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "short"
      hash: HMAC-SHA-256
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least")
}

func TestLoad_HMAC_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "valid-salt-sixteen-b!"
      hash: MD5
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown")
}

func TestLoad_HMAC_MissingSalt(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      hash: HMAC-SHA-256
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "salt")
}

func TestLoad_HMAC_MissingHash(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "valid-salt-sixteen-b!"
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "algorithm")
}

func TestLoad_HMAC_SaltEnvVar(t *testing.T) {
	t.Setenv("TEST_HMAC_SALT", "env-salt-value-sixteen!")

	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "${TEST_HMAC_SALT}"
      hash: HMAC-SHA-256
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result.Outputs[0].HMACConfig)
	assert.Equal(t, []byte("env-salt-value-sixteen!"), result.Outputs[0].HMACConfig.SaltValue)
}

func TestLoad_HMAC_SaltNotInError(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  audit_log:
    type: stdout
    hmac:
      enabled: true
      salt:
        version: "v1"
        value: "short"
      hash: HMAC-SHA-256
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	// Salt value must NOT appear in the error message.
	assert.NotContains(t, err.Error(), "short")
}

// ---------------------------------------------------------------------------
// parseStandardFields — Gap 1
// ---------------------------------------------------------------------------

func TestLoad_StandardFields_ValidFields(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
standard_fields:
  source_ip: "10.0.0.1"
  reason: "default"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	require.NotNil(t, result.StandardFields)
	assert.Equal(t, "10.0.0.1", result.StandardFields["source_ip"])
	assert.Equal(t, "default", result.StandardFields["reason"])
}

func TestLoad_StandardFields_UnknownField(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
standard_fields:
  bogus_field: "x"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "unknown field")
	assert.Contains(t, err.Error(), "bogus_field")
}

func TestLoad_StandardFields_EmptyValue(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
standard_fields:
  source_ip: ""
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "non-empty")
}

func TestLoad_StandardFields_EnvVar(t *testing.T) {
	t.Setenv("MY_TEST_IP", "192.168.99.1")

	data := []byte(`
version: 1
app_name: test
host: test
standard_fields:
  source_ip: "${MY_TEST_IP}"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	require.NotNil(t, result.StandardFields)
	assert.Equal(t, "192.168.99.1", result.StandardFields["source_ip"])
}

func TestLoad_StandardFields_EnvVarMissing(t *testing.T) {
	// Use a variable name that is guaranteed to be absent. The test
	// does NOT call t.Parallel() because it relies on the variable being
	// unset — running sequentially avoids a race with any parallel test
	// that might set the same variable name.
	const missingVar = "OUTPUTCONFIG_TEST_MISSING_SF_VAR_9c2b4e1f"
	os.Unsetenv(missingVar) //nolint:errcheck // test cleanup — error irrelevant

	data := []byte("version: 1\napp_name: test\nhost: test\nstandard_fields:\n  source_ip: \"${" + missingVar + "}\"\noutputs:\n  console:\n    type: stdout\n")
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), missingVar)
}

func TestLoad_StandardFields_NotAMapping(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
standard_fields: "not a mapping"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
}

func TestLoad_StandardFields_MultipleValidFields(t *testing.T) {
	t.Parallel()
	// Verify that multiple valid fields all land in the result map and
	// no entry is silently dropped.
	data := []byte(`
version: 1
app_name: test
host: test
standard_fields:
  source_ip: "10.1.2.3"
  reason: "scheduled-job"
  session_id: "sess-abc"
  role: "admin"
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	require.NotNil(t, result.StandardFields)
	assert.Equal(t, "10.1.2.3", result.StandardFields["source_ip"])
	assert.Equal(t, "scheduled-job", result.StandardFields["reason"])
	assert.Equal(t, "sess-abc", result.StandardFields["session_id"])
	assert.Equal(t, "admin", result.StandardFields["role"])
	assert.Len(t, result.StandardFields, 4)
}

// ---------------------------------------------------------------------------
// LoadResult fields — Gap 2
// ---------------------------------------------------------------------------

func TestLoad_AppNameAndHost_Populated(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: myapp
host: myhost.example.com
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Equal(t, "myapp", result.AppName)
	assert.Equal(t, "myhost.example.com", result.Host)
}

func TestLoad_Timezone_Populated(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
host: test
timezone: UTC
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Equal(t, "UTC", result.Timezone)
}

func TestLoad_Timezone_Omitted(t *testing.T) {
	t.Parallel()
	// No timezone key — result.Timezone must be empty string, not some default.
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Equal(t, "", result.Timezone, "omitted timezone must be empty string")
}

func TestLoad_MissingAppName_Rejected(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
host: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "app_name is required")
}

func TestLoad_MissingHost_Rejected(t *testing.T) {
	t.Parallel()
	data := []byte(`
version: 1
app_name: test
outputs:
  console:
    type: stdout
`)
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "host is required")
}

func TestLoad_AppNameTooLong_Rejected(t *testing.T) {
	t.Parallel()
	// 256 bytes — one byte over the 255-byte limit.
	longName := strings.Repeat("a", 256)
	data := []byte("version: 1\napp_name: " + longName + "\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "app_name exceeds maximum length")
}

func TestLoad_HostTooLong_Rejected(t *testing.T) {
	t.Parallel()
	// 256 bytes — one byte over the 255-byte limit.
	longHost := strings.Repeat("h", 256)
	data := []byte("version: 1\napp_name: test\nhost: " + longHost + "\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "host exceeds maximum length")
}

func TestLoad_TimezoneTooLong_Rejected(t *testing.T) {
	t.Parallel()
	// 65 bytes — one byte over the 64-byte limit.
	longTZ := strings.Repeat("Z", 65)
	data := []byte("version: 1\napp_name: test\nhost: test\ntimezone: " + longTZ + "\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "timezone exceeds maximum length")
}

func TestLoad_TimezoneEmptyString_Rejected(t *testing.T) {
	t.Parallel()
	data := []byte("version: 1\napp_name: test\nhost: test\ntimezone: \"\"\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	_, err := outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err)
	assert.ErrorIs(t, err, outputconfig.ErrOutputConfigInvalid)
	assert.Contains(t, err.Error(), "timezone must be non-empty")
}

func TestLoad_AppNameAtMaxLength_Accepted(t *testing.T) {
	t.Parallel()
	// 255 bytes — exactly at the limit.
	maxName := strings.Repeat("a", 255)
	data := []byte("version: 1\napp_name: " + maxName + "\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err, "255-byte app_name is exactly at the limit and must be accepted")
	assert.Equal(t, maxName, result.AppName)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_HostAtMaxLength_Accepted(t *testing.T) {
	t.Parallel()
	// 255 bytes — exactly at the limit.
	maxHost := strings.Repeat("h", 255)
	data := []byte("version: 1\napp_name: test\nhost: " + maxHost + "\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err, "255-byte host is exactly at the limit and must be accepted")
	assert.Equal(t, maxHost, result.Host)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_TimezoneAtMaxLength_Accepted(t *testing.T) {
	t.Parallel()
	// 64 bytes — exactly at the limit.
	maxTZ := strings.Repeat("Z", 64)
	data := []byte("version: 1\napp_name: test\nhost: test\ntimezone: " + maxTZ + "\noutputs:\n  c:\n    type: stdout\n")
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err, "64-byte timezone is exactly at the limit and must be accepted")
	assert.Equal(t, maxTZ, result.Timezone)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// ---------------------------------------------------------------------------
// injectStringField — Gap 3 (tested indirectly via Load)
// ---------------------------------------------------------------------------

// TestLoad_InjectStringField_SyslogHostnameNotOverridden verifies that
// when a syslog output already declares a hostname, the global host is
// NOT injected (the per-output value is preserved).
//
// Note: not parallel — this test overwrites the global "syslog" factory
// registration and must run exclusively with other syslog factory tests.
func TestLoad_InjectStringField_SyslogHostnameNotOverridden(t *testing.T) {
	var captured atomic.Value
	audit.RegisterOutputFactory("syslog", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: test
host: global-host.example.com
outputs:
  siem:
    type: syslog
    syslog:
      network: tcp
      address: localhost:514
      hostname: per-output-hostname
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	raw, ok := captured.Load().(string)
	require.True(t, ok, "syslog factory must have been invoked")

	// The per-output hostname must win; the global host must not appear.
	assert.Contains(t, raw, "per-output-hostname",
		"per-output hostname must be present in factory config")
	assert.NotContains(t, raw, "global-host.example.com",
		"global host must not be injected when per-output hostname is already set")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// TestLoad_InjectStringField_SyslogHostnameInjected verifies that when a
// syslog output does NOT declare a hostname, the global host value is
// injected into the factory config.
//
// Note: not parallel — this test overwrites the global "syslog" factory
// registration and must run exclusively with other syslog factory tests.
func TestLoad_InjectStringField_SyslogHostnameInjected(t *testing.T) {
	var captured atomic.Value
	audit.RegisterOutputFactory("syslog", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: test
host: injected.example.com
outputs:
  siem:
    type: syslog
    syslog:
      network: tcp
      address: localhost:514
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	raw, ok := captured.Load().(string)
	require.True(t, ok, "syslog factory must have been invoked")

	assert.Contains(t, raw, "hostname",
		"hostname key must be injected into syslog config")
	assert.Contains(t, raw, "injected.example.com",
		"global host value must appear in injected syslog config")
	assert.Contains(t, raw, "app_name",
		"app_name key must be injected into syslog config")
	assert.Contains(t, raw, "test",
		"global app_name value must appear in injected syslog config")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// TestLoad_InjectStringField_SyslogAppNameNotOverridden verifies that
// when a syslog output explicitly declares app_name, the global value
// does not override it.
func TestLoad_InjectStringField_SyslogAppNameNotOverridden(t *testing.T) {
	var captured atomic.Value
	audit.RegisterOutputFactory("syslog", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: global-app
host: test-host
outputs:
  siem:
    type: syslog
    syslog:
      network: tcp
      address: localhost:514
      app_name: per-output-app
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	raw, ok := captured.Load().(string)
	require.True(t, ok, "syslog factory must have been invoked")

	assert.Contains(t, raw, "per-output-app",
		"per-output app_name must be preserved")
	assert.NotContains(t, raw, "global-app",
		"global app_name must not override per-output value")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// TestLoad_InjectStringField_NonSyslogOutputNoInjection verifies that
// the global host is NOT injected into output types other than "syslog".
//
// Note: not parallel — this test overwrites the global "webhook" factory
// registration and must run exclusively with other webhook factory tests.
func TestLoad_InjectStringField_NonSyslogOutputNoInjection(t *testing.T) {
	var captured atomic.Value
	audit.RegisterOutputFactory("webhook", func(name string, rawConfig []byte, _ audit.Metrics) (audit.Output, error) {
		captured.Store(string(rawConfig))
		return &testOutput{name: name}, nil
	})

	data := []byte(`
version: 1
app_name: test
host: global-host.example.com
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://example.com/hook"
`)
	tax := testTaxonomy(t)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)

	raw, _ := captured.Load().(string)
	assert.NotContains(t, raw, "hostname",
		"hostname must not be injected into non-syslog outputs")

	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

// TestLoad_Timezone_PassedAsOption verifies that a non-empty timezone
// results in a WithTimezone option being added to result.Options, and
// that omitting timezone produces no WithTimezone option.
func TestLoad_Timezone_PassedAsOption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		yaml     string
		wantErr  bool
		wantOpts int // minimum expected option count
	}{
		{
			name: "timezone present adds option",
			yaml: `
version: 1
app_name: test
host: test
timezone: Europe/London
outputs:
  console:
    type: stdout
`,
			wantOpts: 4, // WithAppName + WithHost + WithTimezone + WithNamedOutput
		},
		{
			name: "timezone omitted skips option",
			yaml: `
version: 1
app_name: test
host: test
outputs:
  console:
    type: stdout
`,
			wantOpts: 3, // WithAppName + WithHost + WithNamedOutput
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tax := testTaxonomy(t)
			result, err := outputconfig.Load(context.Background(), []byte(tt.yaml), tax)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(result.Options), tt.wantOpts,
				"got %d options, want at least %d", len(result.Options), tt.wantOpts)
			for _, o := range result.Outputs {
				_ = o.Output.Close()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// toInt conversion tests (#325)
// ---------------------------------------------------------------------------

func TestToInt_Float64_WholeNumber(t *testing.T) {
	n, err := outputconfig.ToIntForTest(float64(42))
	require.NoError(t, err)
	assert.Equal(t, 42, n)
}

func TestToInt_Float64_Zero(t *testing.T) {
	n, err := outputconfig.ToIntForTest(float64(0))
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestToInt_Float64_Fractional_ReturnsError(t *testing.T) {
	_, err := outputconfig.ToIntForTest(float64(10.7))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fractional")
}

func TestToInt_Float64_NegativeFractional_ReturnsError(t *testing.T) {
	_, err := outputconfig.ToIntForTest(float64(-3.5))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fractional")
}

// ---------------------------------------------------------------------------
// LoadOption tests
// ---------------------------------------------------------------------------

func TestLoad_DefaultSecretTimeout(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 10*time.Second, outputconfig.DefaultSecretTimeout)
}

func TestLoad_WithSecretTimeout_Accepted(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretTimeout(5*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_MultipleLoadOptions_Compose(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	// Multiple options applied — last write wins for timeout.
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithSecretTimeout(5*time.Second),
		outputconfig.WithSecretTimeout(20*time.Second),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithOutputMetrics(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  log:\n    type: stdout\n")
	var called int
	factory := func(outputType, outputName string) audit.OutputMetrics {
		called++
		assert.Equal(t, "stdout", outputType)
		assert.Equal(t, "log", outputName)
		return audit.NoOpOutputMetrics{}
	}
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithOutputMetrics(factory),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, called, "factory should be called once for stdout output")
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithOutputMetrics_NilFactory(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithOutputMetrics(nil),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_WithFactory(t *testing.T) {
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\noutputs:\n  custom:\n    type: test-custom\n")
	customFactory := func(name string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		so, soErr := audit.NewStdoutOutput(audit.StdoutConfig{})
		if soErr != nil {
			return nil, soErr
		}
		return audit.WrapOutput(so, name), nil
	}
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithFactory("test-custom", customFactory),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Outputs, 1)
	assert.Equal(t, "test-custom", result.Outputs[0].Type)
	assert.Equal(t, "custom", result.Outputs[0].Name)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_RouteWithExcludeCategories(t *testing.T) {
	// Exercises toStringSlice and deepCopyValue's []any branch via
	// route.exclude_categories which is a YAML sequence.
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  log:
    type: stdout
    route:
      exclude_categories:
        - security
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestLoad_QueueSizeInLoggerSection(t *testing.T) {
	// Exercises toInt path through logger.queue_size.
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte("version: 1\napp_name: test\nhost: test\nlogger:\n  queue_size: 200\noutputs:\n  c:\n    type: stdout\n")
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 200, result.Config.QueueSize)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}

func TestToString_NilInput(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToStringForTest(nil)
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestToString_NumericInput(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToStringForTest(42)
	require.NoError(t, err)
	assert.Equal(t, "42", result)
}

func TestToString_BoolInput(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToStringForTest(true)
	require.NoError(t, err)
	assert.Equal(t, "true", result)
}

func TestToInt_Int64Input(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToIntForTest(int64(42))
	require.NoError(t, err)
	assert.Equal(t, 42, result)
}

func TestToInt_Uint64Input(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToIntForTest(uint64(42))
	require.NoError(t, err)
	assert.Equal(t, 42, result)
}

func TestToInt_Float64Input(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToIntForTest(float64(42))
	require.NoError(t, err)
	assert.Equal(t, 42, result)
}

func TestToInt_Float64Fractional(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToIntForTest(42.5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fractional")
}

func TestToInt_StringInput(t *testing.T) {
	t.Parallel()
	result, err := outputconfig.ToIntForTest("123")
	require.NoError(t, err)
	assert.Equal(t, 123, result)
}

func TestToInt_InvalidString(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToIntForTest("not-a-number")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid integer")
}

func TestToInt_UnsupportedType(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToIntForTest([]string{"nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected integer")
}

func TestToBool_UnsupportedType(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToBoolForTest(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected boolean")
}

func TestToBool_InvalidString(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToBoolForTest("not-bool")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid boolean")
}

func TestToStringSlice_NonStringElement(t *testing.T) {
	t.Parallel()
	_, err := outputconfig.ToStringSliceForTest([]any{"a", 42})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected string")
}

func TestDeepCopyValue_SliceCopy(t *testing.T) {
	t.Parallel()
	orig := []any{"a", "b", map[string]any{"key": "val"}}
	cp, ok := outputconfig.DeepCopyValueForTest(orig).([]any)
	require.True(t, ok, "expected []any from deepCopyValue")
	require.Len(t, cp, 3)
	assert.Equal(t, "a", cp[0])
	assert.Equal(t, "b", cp[1])
	// Mutating the original should not affect the copy.
	orig[0] = "CHANGED"
	assert.Equal(t, "a", cp[0])
}

func TestDeepCopyValue_ScalarPassthrough(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "hello", outputconfig.DeepCopyValueForTest("hello"))
	assert.Equal(t, 42, outputconfig.DeepCopyValueForTest(42))
	assert.Equal(t, true, outputconfig.DeepCopyValueForTest(true))
	assert.Nil(t, outputconfig.DeepCopyValueForTest(nil))
}

func TestOutputMetricsFactory_ScopedToOutputName(t *testing.T) {
	// Verify the factory is called with the output NAME, not just the type.
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
outputs:
  compliance_log:
    type: stdout
`)
	var calledWith struct {
		outputType string
		outputName string
	}
	var callCount atomic.Int64
	factory := func(outputType, outputName string) audit.OutputMetrics {
		callCount.Add(1)
		calledWith.outputType = outputType
		calledWith.outputName = outputName
		return audit.NoOpOutputMetrics{}
	}
	result, err := outputconfig.Load(
		context.Background(), data, tax,
		outputconfig.WithOutputMetrics(factory),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Cleanup(func() {
		for _, o := range result.Outputs {
			_ = o.Output.Close()
		}
	})

	assert.Equal(t, int64(1), callCount.Load(),
		"factory should be called once")
	assert.Equal(t, "stdout", calledWith.outputType,
		"factory should receive the output type")
	assert.Equal(t, "compliance_log", calledWith.outputName,
		"factory should receive the output NAME, not the type")
}

func TestLoad_GlobalTLSPolicy_WithStdout(t *testing.T) {
	// Exercises the tls_policy top-level key parsing path.
	t.Parallel()
	tax := testTaxonomy(t)
	data := []byte(`
version: 1
app_name: test
host: test
tls_policy:
  allow_tls12: true
outputs:
  c:
    type: stdout
`)
	result, err := outputconfig.Load(context.Background(), data, tax)
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, o := range result.Outputs {
		_ = o.Output.Close()
	}
}
