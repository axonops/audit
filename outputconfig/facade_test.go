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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var facadeTaxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`)

var facadeOutputsYAML = []byte(`
version: 1
app_name: facade-test
host: test-host
outputs:
  console:
    type: stdout
`)

func TestNew_BasicEndToEnd(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	auditor, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, path, nil)
	require.NoError(t, err)
	require.NotNil(t, auditor)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_WithOptions_UserOptionsTakePrecedence(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	// User option WithDisabled should take precedence over config.
	auditor, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, path, nil,
		audit.WithDisabled(),
	)
	require.NoError(t, err)
	require.NotNil(t, auditor)

	// Disabled auditor returns nil without delivering.
	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"}))
	assert.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_EmptyPath_StdoutDevLogger(t *testing.T) {
	t.Parallel()

	auditor, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, "", nil)
	require.NoError(t, err)
	require.NotNil(t, auditor)

	err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestNew_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, "/nonexistent/path/outputs.yaml", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist), "should wrap os.ErrNotExist, got: %v", err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestNew_InvalidTaxonomy(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	_, err := outputconfig.New(context.Background(), []byte("not: valid: taxonomy"), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "taxonomy")
}

func TestNew_InvalidOutputConfig(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", []byte("not: [valid: config"))

	_, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load")
}

func TestNew_EmptyTaxonomy(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	_, err := outputconfig.New(context.Background(), nil, path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "taxonomy")
}

func TestNew_Close_FlushesEvents(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	auditor, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, path, nil)
	require.NoError(t, err)

	// Send events then close — should not panic or error.
	for range 10 {
		_ = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{"outcome": "success"}))
	}
	require.NoError(t, auditor.Close())
}

func TestNew_NotRegularFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Directories are not regular files.
	_, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}

func TestNew_WithLoadOptions(t *testing.T) {
	t.Parallel()
	path := writeTempFile(t, "outputs-*.yaml", facadeOutputsYAML)

	auditor, err := outputconfig.New(context.Background(), facadeTaxonomyYAML, path,
		[]outputconfig.LoadOption{outputconfig.WithCoreMetrics(nil)},
	)
	require.NoError(t, err)
	require.NotNil(t, auditor)
	require.NoError(t, auditor.Close())
}

// writeTempFile creates a temporary file with the given content and
// returns its path. The file is cleaned up after the test.
func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}
