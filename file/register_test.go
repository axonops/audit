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

package file_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

func TestFileFactory_RegisteredByInit(t *testing.T) {
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory, "file factory must be registered by init()")
}

func TestFileFactory_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	yaml := []byte("path: " + path + "\npermissions: \"0600\"\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	out, err := factory("compliance_file", yaml, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "compliance_file", out.Name(), "name should be the YAML-configured name")
	assert.NoError(t, out.Write([]byte(`{"test":true}`+"\n")))
}

func TestFileFactory_InvalidConfig_ReturnsError(t *testing.T) {
	yaml := []byte("path: \"\"\n") // empty path

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("bad_file", yaml, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad_file")
}

func TestFileFactory_UnknownYAMLField_Rejected(t *testing.T) {
	yaml := []byte("path: /tmp/test.log\nunknown_field: true\n")

	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("test", yaml, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_field")
}

func TestFileFactory_EmptyConfig_ReturnsError(t *testing.T) {
	factory := audit.LookupOutputFactory("file")
	require.NotNil(t, factory)

	_, err := factory("empty", nil, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestFileNewFactory_WithMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.log")
	yaml := []byte("path: " + path + "\n")

	metrics := &mockFileMetrics{}
	factory := file.NewFactory(metrics)

	out, err := factory("with_metrics", yaml, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "with_metrics", out.Name())
}

func TestFileNewFactory_NilMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.log")
	yaml := []byte("path: " + path + "\n")

	factory := file.NewFactory(nil)

	out, err := factory("nil_metrics", yaml, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "nil_metrics", out.Name())
}

type mockFileMetrics struct{}

func (m *mockFileMetrics) RecordFileRotation(_ string) {}
