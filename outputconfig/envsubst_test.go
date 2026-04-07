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

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseToMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(s), &m))
	return m
}

func TestExpandEnv_Simple(t *testing.T) {
	t.Setenv("TEST_HOST", "syslog.example.com")
	m := parseToMap(t, "address: ${TEST_HOST}:514\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "syslog.example.com:514", m["address"])
}

func TestExpandEnv_WithDefault(t *testing.T) {
	t.Setenv("TEST_PORT", "6514")
	m := parseToMap(t, "port: ${TEST_PORT:-514}\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "6514", m["port"])
}

func TestExpandEnv_UnsetWithDefault_UsesDefault(t *testing.T) {
	m := parseToMap(t, "port: ${UNSET_PORT_VAR:-514}\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "514", m["port"])
}

func TestExpandEnv_UnsetNoDefault_Error(t *testing.T) {
	m := parseToMap(t, "host: ${UNSET_HOST_NO_DEFAULT}\n")

	_, err := expandEnvInValue(m, "config")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UNSET_HOST_NO_DEFAULT")
	assert.Contains(t, err.Error(), "not set")
}

func TestExpandEnv_EscapedDollar(t *testing.T) {
	m := parseToMap(t, "literal: $${NOT_A_VAR}\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "${NOT_A_VAR}", m["literal"])
}

func TestExpandEnv_NoRecursive(t *testing.T) {
	t.Setenv("TEST_INNER", "${SHOULD_NOT_EXPAND}")
	m := parseToMap(t, "value: ${TEST_INNER}\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "${SHOULD_NOT_EXPAND}", m["value"])
}

func TestExpandEnv_OnlyStringValues_NotKeys(t *testing.T) {
	t.Setenv("TEST_KEY_VAR", "injected")
	m := parseToMap(t, "${TEST_KEY_VAR}: some_value\naddress: ${TEST_KEY_VAR}\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)

	// Key remains literal (map keys are not expanded).
	_, keyExists := m["${TEST_KEY_VAR}"]
	assert.True(t, keyExists, "key should remain literal")
	// Value is expanded.
	assert.Equal(t, "injected", m["address"])
}

func TestExpandEnv_NestedYAML(t *testing.T) {
	t.Setenv("TEST_NESTED_HOST", "deep.example.com")
	m := parseToMap(t, "output:\n  syslog:\n    address: ${TEST_NESTED_HOST}:514\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)

	output, ok := m["output"].(map[string]any)
	require.True(t, ok)
	syslogMap, ok := output["syslog"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "deep.example.com:514", syslogMap["address"])
}

func TestExpandEnv_EmptyString(t *testing.T) {
	m := parseToMap(t, "value: \"\"\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "", m["value"])
}

func TestExpandEnv_MultipleVarsInOneValue(t *testing.T) {
	t.Setenv("TEST_PROTO", "tcp+tls")
	t.Setenv("TEST_ADDR", "syslog.local")
	m := parseToMap(t, "url: ${TEST_PROTO}://${TEST_ADDR}:514\n")

	_, err := expandEnvInValue(m, "")
	require.NoError(t, err)
	assert.Equal(t, "tcp+tls://syslog.local:514", m["url"])
}

func TestExpandEnv_UnclosedBrace_Error(t *testing.T) {
	m := parseToMap(t, "bad: ${UNCLOSED\n")

	_, err := expandEnvInValue(m, "test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unclosed")
}
