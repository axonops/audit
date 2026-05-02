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
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
)

// parseFormatterValue parses a YAML string into the value type that
// buildFormatter expects (map[string]any for mappings, string for scalars).
func parseFormatterValue(t *testing.T, yamlStr string) any {
	t.Helper()
	var v any
	require.NoError(t, yaml.Unmarshal([]byte(yamlStr), &v))
	return v
}

func TestBuildFormatter_Nil_ReturnsNil(t *testing.T) {
	f, err := outputconfig.BuildFormatterForTest(nil)
	assert.NoError(t, err)
	assert.Nil(t, f)
}

func TestBuildFormatter_EmptyString_ReturnsNil(t *testing.T) {
	f, err := outputconfig.BuildFormatterForTest("")
	assert.NoError(t, err)
	assert.Nil(t, f)
}

func TestBuildFormatter_JSON_Default(t *testing.T) {
	v := parseFormatterValue(t, "type: json\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)
	require.NotNil(t, f)

	jf, ok := f.(*audit.JSONFormatter)
	require.True(t, ok)
	assert.Equal(t, audit.TimestampRFC3339Nano, jf.Timestamp)
	assert.False(t, jf.OmitEmpty)
}

func TestBuildFormatter_JSON_EmptyType_DefaultsToJSON(t *testing.T) {
	v := parseFormatterValue(t, "timestamp: unix_ms\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)
	require.NotNil(t, f)

	jf, ok := f.(*audit.JSONFormatter)
	require.True(t, ok)
	assert.Equal(t, audit.TimestampUnixMillis, jf.Timestamp)
}

func TestBuildFormatter_JSON_UnixMs(t *testing.T) {
	v := parseFormatterValue(t, "type: json\ntimestamp: unix_ms\nomit_empty: true\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)

	jf, ok := f.(*audit.JSONFormatter)
	require.True(t, ok)
	assert.Equal(t, audit.TimestampUnixMillis, jf.Timestamp)
	assert.True(t, jf.OmitEmpty)
}

func TestBuildFormatter_JSON_InvalidTimestamp_Error(t *testing.T) {
	v := parseFormatterValue(t, "type: json\ntimestamp: epoch_seconds\n")
	_, err := outputconfig.BuildFormatterForTest(v)
	require.Error(t, err)
	// text-only: buildFormatter helpers (formatter.go:73,77,86,93,104,115)
	// return raw fmt.Errorf without a sentinel wrap. The ErrOutputConfigInvalid
	// wrap is added by Load() upstream (outputconfig.go).
	assert.Contains(t, err.Error(), "unknown timestamp format")
	assert.Contains(t, err.Error(), "epoch_seconds")
}

func TestBuildFormatter_CEF_WithVendorProduct(t *testing.T) {
	v := parseFormatterValue(t, "type: cef\nvendor: AxonOps\nproduct: SchemaRegistry\nversion: \"1.0\"\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)

	cf, ok := f.(*audit.CEFFormatter)
	require.True(t, ok)
	assert.Equal(t, "AxonOps", cf.Vendor)
	assert.Equal(t, "SchemaRegistry", cf.Product)
	assert.Equal(t, "1.0", cf.Version)
}

func TestBuildFormatter_CEF_OmitEmpty(t *testing.T) {
	v := parseFormatterValue(t, "type: cef\nomit_empty: true\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)

	cf, ok := f.(*audit.CEFFormatter)
	require.True(t, ok)
	assert.True(t, cf.OmitEmpty)
}

func TestBuildFormatter_CEF_NoSeverityFunc(t *testing.T) {
	v := parseFormatterValue(t, "type: cef\nvendor: Test\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)

	cf, ok := f.(*audit.CEFFormatter)
	require.True(t, ok)
	assert.Nil(t, cf.SeverityFunc, "SeverityFunc should be nil (not configurable via YAML)")
}

func TestBuildFormatter_CEF_Defaults(t *testing.T) {
	v := parseFormatterValue(t, "type: cef\n")
	f, err := outputconfig.BuildFormatterForTest(v)
	require.NoError(t, err)

	cf, ok := f.(*audit.CEFFormatter)
	require.True(t, ok)
	assert.Empty(t, cf.Vendor)
	assert.Empty(t, cf.Product)
	assert.Empty(t, cf.Version)
	assert.False(t, cf.OmitEmpty)
	assert.Nil(t, cf.SeverityFunc)
	assert.Nil(t, cf.DescriptionFunc)
	assert.Nil(t, cf.FieldMapping)
}

func TestBuildFormatter_CEF_RejectsTimestamp(t *testing.T) {
	v := parseFormatterValue(t, "type: cef\ntimestamp: unix_ms\nvendor: Test\n")
	_, err := outputconfig.BuildFormatterForTest(v)
	require.Error(t, err)
	// text-only: buildFormatter helper, see TestBuildFormatter_JSON_InvalidTimestamp_Error.
	assert.Contains(t, err.Error(), "cef does not support timestamp")
}

func TestBuildFormatter_JSON_RejectsVendorProductVersion(t *testing.T) {
	v := parseFormatterValue(t, "type: json\nvendor: AxonOps\n")
	_, err := outputconfig.BuildFormatterForTest(v)
	require.Error(t, err)
	// text-only: buildFormatter helper, see TestBuildFormatter_JSON_InvalidTimestamp_Error.
	assert.Contains(t, err.Error(), "json does not support vendor")
}

func TestBuildFormatter_UnknownType_Error(t *testing.T) {
	v := parseFormatterValue(t, "type: protobuf\n")
	_, err := outputconfig.BuildFormatterForTest(v)
	require.Error(t, err)
	// text-only: buildFormatter helper, see TestBuildFormatter_JSON_InvalidTimestamp_Error.
	assert.Contains(t, err.Error(), "unknown type")
	assert.Contains(t, err.Error(), "protobuf")
}

func TestBuildFormatter_InvalidStructure_Error(t *testing.T) {
	// Pass a slice where a mapping is expected.
	v := []any{"item"}
	_, err := outputconfig.BuildFormatterForTest(v)
	require.Error(t, err)
	// text-only: buildFormatter helper, see TestBuildFormatter_JSON_InvalidTimestamp_Error.
	assert.Contains(t, err.Error(), "formatter")
}

func TestExtractFormatterType(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"nil value", "", ""},
		{"scalar cef", "cef", "cef"},
		{"scalar json", "json", "json"},
		{"mapping with type", "type: cef", "cef"},
		{"mapping with type json", "type: json\ntimestamp: unix_ms", "json"},
		{"mapping without type", "timestamp: unix_ms", ""},
		{"empty scalar", `""`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.yaml == "" {
				assert.Equal(t, "", outputconfig.ExtractFormatterTypeForTest(nil))
				return
			}
			v := parseFormatterValue(t, tt.yaml)
			assert.Equal(t, tt.want, outputconfig.ExtractFormatterTypeForTest(v))
		})
	}
}
