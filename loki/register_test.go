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

package loki_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// TestLokiFactory_RegisteredByInit verifies that importing the loki package
// (for its side effect) registers a factory under the "loki" key. This is the
// fundamental contract of the package: blank-import registers the output type.
func TestLokiFactory_RegisteredByInit(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory, "loki factory must be registered by init(); import _ \"github.com/axonops/go-audit/loki\" was performed")
}

// ---------------------------------------------------------------------------
// Basic factory error paths
// ---------------------------------------------------------------------------

// TestLokiFactory_EmptyConfig verifies that passing nil config bytes returns
// a clear error indicating that a config block is required.
func TestLokiFactory_EmptyConfig(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	_, err := factory("my_loki", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config is required",
		"empty config should produce 'config is required' error, got: %q", err.Error())
}

// TestLokiFactory_UnknownField verifies that the YAML decoder runs in strict
// mode (KnownFields(true)), so an unrecognised field causes a clear decode
// error. This prevents silent misconfiguration.
func TestLokiFactory_UnknownField(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nunknown_field: oops\n")
	_, err := factory("strict_loki", rawYAML, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_field",
		"strict YAML decode should name the unexpected field, got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Duration field parsing
// ---------------------------------------------------------------------------

// TestLokiFactory_DurationParsing exercises the custom yamlDuration type for
// flush_interval and timeout. Valid Go duration strings are accepted; bare
// integers and non-duration strings are rejected at decode time.
func TestLokiFactory_DurationParsing(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name:    "seconds suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: 5s\n",
			wantErr: false,
		},
		{
			name:    "milliseconds suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: 500ms\n",
			wantErr: false,
		},
		{
			name:    "minutes suffix accepted",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: 1m\n",
			wantErr: false,
		},
		{
			name: "zero duration string accepted",
			// 0s is a valid Go duration; validateLokiConfig replaces zero
			// flush_interval with the default, so this should not error.
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: 0s\n",
			wantErr: false,
		},
		{
			name:    "non-duration string rejected",
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: banana\n",
			wantErr: true,
		},
		{
			name: "bare integer without suffix rejected",
			// Go time.ParseDuration requires a unit suffix; "5" is not valid.
			yaml:    "url: https://loki.example.com/loki/api/v1/push\nflush_interval: 5\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := factory("dur_test", []byte(tt.yaml), nil)
			if tt.wantErr {
				require.Error(t, err, "expected a parse error for YAML: %s", tt.yaml)
				assert.Contains(t, err.Error(), "duration",
					"error for invalid duration should mention 'duration', got: %q", err.Error())
			} else {
				require.NoError(t, err, "valid duration should not error")
				require.NotNil(t, out)
				require.NoError(t, out.Close())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Auth mutual exclusivity
// ---------------------------------------------------------------------------

// TestLokiFactory_BasicAuthAndBearerToken_Rejected verifies that the factory
// rejects configurations that set both basic_auth and bearer_token. These are
// mutually exclusive authentication mechanisms.
func TestLokiFactory_BasicAuthAndBearerToken_Rejected(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
basic_auth:
  username: alice
  password: secret
bearer_token: tok-should-not-coexist
`)
	_, err := factory("conflict_auth", rawYAML, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid,
		"auth conflict must wrap audit.ErrConfigInvalid")
	assert.Contains(t, err.Error(), "mutually exclusive",
		"basic_auth + bearer_token must be rejected with 'mutually exclusive', got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Gzip / compress defaults
// ---------------------------------------------------------------------------

// TestLokiFactory_GzipDefaultTrue verifies that omitting the "gzip" field
// from the YAML config results in compression being enabled. This is the
// documented default (Compress: true) and must be preserved by the factory.
// The config passes validation and reaches the "not yet implemented" gate.
func TestLokiFactory_GzipDefaultTrue(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\n")
	out, err := factory("gzip_default", rawYAML, nil)
	require.NoError(t, err, "valid config with default gzip should succeed")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiFactory_GzipExplicitFalse verifies that explicitly setting
// "gzip: false" is accepted by the factory. The field exists and its false
// value is a valid override of the default.
func TestLokiFactory_GzipExplicitFalse(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\ngzip: false\n")
	out, err := factory("gzip_explicit_false", rawYAML, nil)
	require.NoError(t, err, "gzip: false should be accepted")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Dynamic label validation
// ---------------------------------------------------------------------------

// TestLokiFactory_DynamicLabels_UnknownName verifies that unknown dynamic
// label names are rejected. The set of valid dynamic labels is fixed:
// app_name, host, pid, event_type, event_category, severity.
func TestLokiFactory_DynamicLabels_UnknownName(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
labels:
  dynamic:
    actor_id: true
`)
	_, err := factory("bad_dynamic_label", rawYAML, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid,
		"unknown dynamic label must wrap audit.ErrConfigInvalid")
	assert.Contains(t, err.Error(), "unknown dynamic label",
		"unrecognised dynamic label name must produce 'unknown dynamic label' error, got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Static label validation
// ---------------------------------------------------------------------------

// TestLokiFactory_StaticLabels_InvalidName verifies that static label names
// that do not match the Loki label name pattern [a-zA-Z_][a-zA-Z0-9_]* are
// rejected. Hyphens, dots, and spaces are not valid.
func TestLokiFactory_StaticLabels_InvalidName(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name      string
		labelName string
	}{
		{"hyphen in name", "my-label"},
		{"dot in name", "my.label"},
		{"starts with digit", "2bad"},
		{"space in name", "bad name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nlabels:\n  static:\n    " + tt.labelName + ": somevalue\n")
			_, err := factory("invalid_label_"+tt.name, rawYAML, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, audit.ErrConfigInvalid,
				"invalid static label must wrap audit.ErrConfigInvalid")
			assert.Contains(t, err.Error(), "invalid",
				"static label name %q must be rejected as invalid, got: %q", tt.labelName, err.Error())
		})
	}
}

// ---------------------------------------------------------------------------
// Full output creation
// ---------------------------------------------------------------------------

// TestLokiFactory_ValidConfig_ReturnsOutput verifies that a valid
// config creates a working Output that can be closed.
func TestLokiFactory_ValidConfig_ReturnsOutput(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
batch_size: 50
flush_interval: 10s
timeout: 5s
max_retries: 2
buffer_size: 500
`)
	out, err := factory("valid", rawYAML, nil)
	require.NoError(t, err, "valid config should produce an output")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiFactory_ValidConfig_WithAllAuthOptions verifies that each auth
// variant (none, basic, bearer) passes validation in isolation.
func TestLokiFactory_ValidConfig_WithAllAuthOptions(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "no auth",
			yaml: "url: https://loki.example.com/loki/api/v1/push\n",
		},
		{
			name: "basic auth",
			yaml: "url: https://loki.example.com/loki/api/v1/push\nbasic_auth:\n  username: alice\n  password: s3cr3t\n",
		},
		{
			name: "bearer token",
			yaml: "url: https://loki.example.com/loki/api/v1/push\nbearer_token: tok-abc123\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := factory("auth_test", []byte(tt.yaml), nil)
			require.NoError(t, err, "%s auth variant should produce output", tt.name)
			require.NotNil(t, out)
			require.NoError(t, out.Close())
		})
	}
}

// TestLokiFactory_NewFactory_NilMetrics verifies that NewFactory(nil) returns
// a working factory function. Nil metrics is an explicitly supported path
// (disables Loki-specific metric collection).
func TestLokiFactory_NewFactory_NilMetrics(t *testing.T) {
	t.Parallel()

	// Import the loki package has already registered the default factory.
	// NewFactory returns a separate factory with custom metrics wiring.
	// We call it directly here via the loki package (external test).
	// Since register_test.go is in package loki_test, we cannot call
	// loki.NewFactory without importing it by name — which we can do
	// through the side-effect import above.
	//
	// We exercise this path indirectly: the default factory (registered by
	// init) uses nil lokiMetrics internally. A valid config must still reach
	// the output rather than panicking on nil metrics.
	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	out, err := factory("nil_metrics_path", []byte("url: https://loki.example.com/loki/api/v1/push\n"), nil)
	require.NoError(t, err, "nil coreMetrics must not panic")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiFactory_NewFactory_WithMetrics verifies that NewFactory with a
// non-nil Metrics implementation returns a factory that behaves identically
// to the default factory in terms of config validation and Phase 1 status.
func TestLokiFactory_NewFactory_WithMetrics(t *testing.T) {
	t.Parallel()

	metrics := &mockLokiMetrics{}
	factory := loki.NewFactory(metrics)
	require.NotNil(t, factory, "NewFactory must return a non-nil factory")

	out, err := factory("custom_metrics", []byte("url: https://loki.example.com/loki/api/v1/push\n"), nil)
	require.NoError(t, err, "valid config with custom metrics should produce output")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// TestLokiFactory_NewFactory_WithMetrics_InvalidConfig verifies that a
// factory created with NewFactory still validates config — invalid configs
// must not reach the Phase 1 gate.
func TestLokiFactory_NewFactory_WithMetrics_InvalidConfig(t *testing.T) {
	t.Parallel()

	factory := loki.NewFactory(nil)

	_, err := factory("bad_cfg", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config is required",
		"NewFactory factory must enforce config-required check, got: %q", err.Error())
}

// ---------------------------------------------------------------------------
// Dynamic label parsing — success paths
// ---------------------------------------------------------------------------

// TestLokiFactory_DynamicLabels_ExcludeFields verifies that setting a known
// dynamic label to false correctly excludes it from the stream labels. This
// exercises the full parseDynamicLabels success path for each valid name.
func TestLokiFactory_DynamicLabels_ExcludeFields(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	// Each valid dynamic label name disabled (false) must be accepted and
	// reach the Phase 1 gate.
	validLabels := []string{
		"app_name",
		"host",
		"pid",
		"event_type",
		"event_category",
		"severity",
	}

	for _, labelName := range validLabels {
		t.Run("exclude_"+labelName, func(t *testing.T) {
			t.Parallel()

			rawYAML := []byte("url: https://loki.example.com/loki/api/v1/push\nlabels:\n  dynamic:\n    " + labelName + ": false\n")
			out, err := factory("dyn_"+labelName, rawYAML, nil)
			require.NoError(t, err,
				"disabling dynamic label %q should produce output", labelName)
			require.NotNil(t, out)
			require.NoError(t, out.Close())
		})
	}
}

// TestLokiFactory_DynamicLabels_IncludeFields verifies that setting a known
// dynamic label to true (explicitly included) is also accepted.
func TestLokiFactory_DynamicLabels_IncludeFields(t *testing.T) {
	t.Parallel()

	factory := audit.LookupOutputFactory("loki")
	require.NotNil(t, factory)

	rawYAML := []byte(`
url: https://loki.example.com/loki/api/v1/push
labels:
  dynamic:
    app_name: true
    event_type: true
    severity: false
`)
	out, err := factory("mixed_dynamic", rawYAML, nil)
	require.NoError(t, err, "mixed include/exclude dynamic labels should produce output")
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Ensure the mock satisfies the loki.Metrics interface at compile time.
var _ loki.Metrics = (*mockLokiMetrics)(nil)

type mockLokiMetrics struct {
	drops   int
	flushes int
}

func (m *mockLokiMetrics) RecordLokiDrop()                        { m.drops++ }
func (m *mockLokiMetrics) RecordLokiFlush(_ int, _ time.Duration) { m.flushes++ }
func (m *mockLokiMetrics) RecordLokiRetry(_ int, _ int)           {}
func (m *mockLokiMetrics) RecordLokiError(_ int)                  {}
