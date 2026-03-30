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

package outputconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func parseYAML(t *testing.T, s string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(s), &doc))
	return &doc
}

func getScalar(t *testing.T, doc *yaml.Node, key string) string {
	t.Helper()
	// doc is DocumentNode → Content[0] is MappingNode
	mapping := doc.Content[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1].Value
		}
	}
	t.Fatalf("key %q not found", key)
	return ""
}

func TestExpandEnv_Simple(t *testing.T) {
	t.Setenv("TEST_HOST", "syslog.example.com")
	doc := parseYAML(t, "address: ${TEST_HOST}:514\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "syslog.example.com:514", getScalar(t, doc, "address"))
}

func TestExpandEnv_WithDefault(t *testing.T) {
	// Variable is set — use its value, not the default.
	t.Setenv("TEST_PORT", "6514")
	doc := parseYAML(t, "port: ${TEST_PORT:-514}\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "6514", getScalar(t, doc, "port"))
}

func TestExpandEnv_UnsetWithDefault_UsesDefault(t *testing.T) {
	// Variable is NOT set — use the default.
	doc := parseYAML(t, "port: ${UNSET_PORT_VAR:-514}\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "514", getScalar(t, doc, "port"))
}

func TestExpandEnv_UnsetNoDefault_Error(t *testing.T) {
	doc := parseYAML(t, "host: ${UNSET_HOST_NO_DEFAULT}\n")

	err := expandEnvInNode(doc, "config")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UNSET_HOST_NO_DEFAULT")
	assert.Contains(t, err.Error(), "not set")
}

func TestExpandEnv_EscapedDollar(t *testing.T) {
	doc := parseYAML(t, "literal: $${NOT_A_VAR}\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "${NOT_A_VAR}", getScalar(t, doc, "literal"))
}

func TestExpandEnv_NoRecursive(t *testing.T) {
	// Inner expansion should NOT happen.
	t.Setenv("TEST_INNER", "${SHOULD_NOT_EXPAND}")
	doc := parseYAML(t, "value: ${TEST_INNER}\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	// The result contains the literal string, not a further expansion.
	assert.Equal(t, "${SHOULD_NOT_EXPAND}", getScalar(t, doc, "value"))
}

func TestExpandEnv_OnlyStringValues_NotKeys(t *testing.T) {
	t.Setenv("TEST_KEY_VAR", "injected")
	// The key should NOT be expanded, only the value.
	yamlStr := "${TEST_KEY_VAR}: some_value\naddress: ${TEST_KEY_VAR}\n"
	doc := parseYAML(t, yamlStr)

	require.NoError(t, expandEnvInNode(doc, ""))

	// Key remains literal.
	mapping := doc.Content[0]
	assert.Equal(t, "${TEST_KEY_VAR}", mapping.Content[0].Value)
	// Value is expanded.
	assert.Equal(t, "injected", mapping.Content[3].Value)
}

func TestExpandEnv_NestedYAML(t *testing.T) {
	t.Setenv("TEST_NESTED_HOST", "deep.example.com")
	yamlStr := "output:\n  syslog:\n    address: ${TEST_NESTED_HOST}:514\n"
	doc := parseYAML(t, yamlStr)

	require.NoError(t, expandEnvInNode(doc, ""))

	// Navigate to nested value.
	outer := doc.Content[0]            // MappingNode
	outputVal := outer.Content[1]      // MappingNode for "output"
	syslogVal := outputVal.Content[1]  // MappingNode for "syslog"
	addressVal := syslogVal.Content[1] // ScalarNode for "address"
	assert.Equal(t, "deep.example.com:514", addressVal.Value)
}

func TestExpandEnv_EmptyString(t *testing.T) {
	doc := parseYAML(t, "value: \"\"\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "", getScalar(t, doc, "value"))
}

func TestExpandEnv_MultipleVarsInOneValue(t *testing.T) {
	t.Setenv("TEST_PROTO", "tcp+tls")
	t.Setenv("TEST_ADDR", "syslog.local")
	doc := parseYAML(t, "url: ${TEST_PROTO}://${TEST_ADDR}:514\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "tcp+tls://syslog.local:514", getScalar(t, doc, "url"))
}

func TestExpandEnv_UnclosedBrace_Error(t *testing.T) {
	doc := parseYAML(t, "bad: ${UNCLOSED\n")

	err := expandEnvInNode(doc, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unclosed")
}

func TestExpandEnv_EmptyVarName_Error(t *testing.T) {
	doc := parseYAML(t, "bad: ${}\n")

	err := expandEnvInNode(doc, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty variable name")
}

func TestExpandEnv_SequenceValues(t *testing.T) {
	t.Setenv("TEST_CAT", "security")
	yamlStr := "categories:\n  - ${TEST_CAT}\n  - write\n"
	doc := parseYAML(t, yamlStr)

	require.NoError(t, expandEnvInNode(doc, ""))

	// Navigate to sequence.
	mapping := doc.Content[0]
	seq := mapping.Content[1]
	assert.Equal(t, "security", seq.Content[0].Value)
	assert.Equal(t, "write", seq.Content[1].Value)
}

func TestExpandEnv_NoVars_Passthrough(t *testing.T) {
	doc := parseYAML(t, "plain: no variables here\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "no variables here", getScalar(t, doc, "plain"))
}

func TestExpandEnv_NilNode(t *testing.T) {
	assert.NoError(t, expandEnvInNode(nil, ""))
}

func TestExpandEnv_IntegerNotExpanded(t *testing.T) {
	// Integer scalars should not be touched.
	doc := parseYAML(t, "port: 514\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	mapping := doc.Content[0]
	assert.Equal(t, "514", mapping.Content[1].Value)
	assert.Equal(t, "!!int", mapping.Content[1].Tag)
}

func TestExpandEnv_BooleanNotExpanded(t *testing.T) {
	doc := parseYAML(t, "enabled: true\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	mapping := doc.Content[0]
	assert.Equal(t, "true", mapping.Content[1].Value)
	assert.Equal(t, "!!bool", mapping.Content[1].Tag)
}

func TestExpandEnv_ErrorIncludesFieldPath(t *testing.T) {
	yamlStr := "outputs:\n  syslog:\n    address: ${MISSING_VAR}\n"
	doc := parseYAML(t, yamlStr)

	err := expandEnvInNode(doc, "config")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MISSING_VAR")
	assert.Contains(t, err.Error(), "config.outputs.syslog.address")
}

func TestExpandEnv_YAMLInjectionSafe(t *testing.T) {
	// Core security invariant: env var values cannot alter YAML tree structure.
	t.Setenv("TEST_INJECT", "value\nnewkey: injected")
	doc := parseYAML(t, "key: ${TEST_INJECT}\n")

	require.NoError(t, expandEnvInNode(doc, ""))
	assert.Equal(t, "value\nnewkey: injected", getScalar(t, doc, "key"))
	// Tree structure unchanged — still one mapping with one key-value pair.
	assert.Equal(t, 2, len(doc.Content[0].Content))
}

func TestExpandEnv_InvalidVarName_Error(t *testing.T) {
	doc := parseYAML(t, "bad: ${../../etc/passwd}\n")

	err := expandEnvInNode(doc, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid variable name")
}

func TestExpandEnv_BashSyntax_Rejected(t *testing.T) {
	// Bash-style ${VAR:+alt} should be rejected as invalid var name.
	doc := parseYAML(t, "val: ${VAR:+alternate}\n")

	err := expandEnvInNode(doc, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid variable name")
}

func TestParseVarExpr_Simple(t *testing.T) {
	name, def, has := parseVarExpr("MY_VAR")
	assert.Equal(t, "MY_VAR", name)
	assert.Equal(t, "", def)
	assert.False(t, has)
}

func TestParseVarExpr_WithDefault(t *testing.T) {
	name, def, has := parseVarExpr("MY_VAR:-fallback")
	assert.Equal(t, "MY_VAR", name)
	assert.Equal(t, "fallback", def)
	assert.True(t, has)
}

func TestParseVarExpr_EmptyDefault(t *testing.T) {
	name, def, has := parseVarExpr("MY_VAR:-")
	assert.Equal(t, "MY_VAR", name)
	assert.Equal(t, "", def)
	assert.True(t, has)
}

func TestParseVarExpr_DefaultWithColon(t *testing.T) {
	name, def, has := parseVarExpr("HOST:-localhost:8080")
	assert.Equal(t, "HOST", name)
	assert.Equal(t, "localhost:8080", def)
	assert.True(t, has)
}
