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

package audit_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/tests/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger_ConfigVersionZero(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 0, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "version is required")
}

func TestNewLogger_ConfigVersionTooHigh(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 999, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "not supported")
}

func TestNewLogger_ConfigVersionNegative(t *testing.T) {
	// Negative version is treated as below minimum supported.
	_, err := audit.NewLogger(
		audit.Config{Version: -1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "no longer supported")
}

func TestNewLogger_InvalidValidationMode(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "bogus"},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "invalid validation mode")
}

func TestNewLogger_BufferSizeDefault(t *testing.T) {
	// BufferSize 0 should not cause an error; it defaults to 10,000.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 0},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_DrainTimeoutDefault(t *testing.T) {
	// DrainTimeout 0 should not cause an error; it defaults to 5s.
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, DrainTimeout: 0},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_CustomDrainTimeout(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, DrainTimeout: 10 * time.Second},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}

func TestNewLogger_DisabledNoOp(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: false},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Audit on disabled logger returns nil.
	err = logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	})
	assert.NoError(t, err)

	require.NoError(t, logger.Close())
}

func TestBuildOutputs_StdoutAndFile(t *testing.T) {
	dir := t.TempDir()
	opts, err := audit.BuildOutputs(audit.OutputsConfig{
		Stdout: &audit.StdoutConfig{},
		File:   &audit.FileConfig{Path: filepath.Join(dir, "audit.log")},
	})
	require.NoError(t, err)
	assert.Len(t, opts, 2)
}

func TestBuildOutputs_ExtraNamedFileOutputs(t *testing.T) {
	dir := t.TempDir()
	opts, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{
				Name: "security-log",
				Type: "file",
				File: &audit.FileConfig{Path: filepath.Join(dir, "security.log")},
				Route: audit.EventRoute{
					IncludeCategories: []string{"security"},
				},
			},
			{
				Name: "all-events",
				Type: "file",
				File: &audit.FileConfig{Path: filepath.Join(dir, "all.log")},
			},
		},
	})
	require.NoError(t, err)
	assert.Len(t, opts, 2)
}

func TestBuildOutputs_DuplicateName(t *testing.T) {
	dir := t.TempDir()
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "dup", Type: "file", File: &audit.FileConfig{Path: filepath.Join(dir, "a.log")}},
			{Name: "dup", Type: "file", File: &audit.FileConfig{Path: filepath.Join(dir, "b.log")}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate output name")
}

func TestBuildOutputs_EmptyName(t *testing.T) {
	dir := t.TempDir()
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "", Type: "file", File: &audit.FileConfig{Path: filepath.Join(dir, "a.log")}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name must not be empty")
}

func TestBuildOutputs_UnknownType(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "kafka"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown output type")
}

func TestBuildOutputs_DuplicateFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.log")
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		File: &audit.FileConfig{Path: path},
		Extra: []audit.NamedOutputConfig{
			{Name: "extra", Type: "file", File: &audit.FileConfig{Path: path}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share the same path")
}

func TestBuildOutputs_DuplicateFilePathNormalised(t *testing.T) {
	dir := t.TempDir()
	// Same path but written differently.
	path1 := filepath.Join(dir, "audit.log")
	path2 := filepath.Join(dir, ".", "audit.log")
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "out1", Type: "file", File: &audit.FileConfig{Path: path1}},
			{Name: "out2", Type: "file", File: &audit.FileConfig{Path: path2}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "share the same path")
}

func TestBuildOutputs_SyslogTypeMissingConfig(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "syslog", Syslog: nil},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires Syslog config")
}

func TestBuildOutputs_SyslogInvalidConfig(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "syslog", Syslog: &audit.SyslogConfig{
				// Missing address — should fail validation.
			}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestBuildOutputs_WebhookTypeMissingConfig(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "webhook", Webhook: nil},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires Webhook config")
}

func TestBuildOutputs_WebhookInvalidConfig(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "webhook", Webhook: &audit.WebhookConfig{
				// Missing URL — should fail validation.
			}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestBuildOutputs_TypeConfigMismatch(t *testing.T) {
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{Name: "test", Type: "file", Stdout: &audit.StdoutConfig{}},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires File config")
}

func TestBuildOutputs_PartialFailure_ClosesWebhook(t *testing.T) {
	// Create a valid webhook (starts batch goroutine) then an invalid Extra.
	// BuildOutputs should close the webhook on failure.
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Webhook: &audit.WebhookConfig{
			URL:                "http://localhost:1/webhook",
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
		},
		Extra: []audit.NamedOutputConfig{
			{Name: "bad", Type: "file", File: &audit.FileConfig{Path: ""}}, // invalid
		},
	})
	require.Error(t, err)
	// If cleanup works, the webhook batch goroutine exits.
	// goleak.VerifyTestMain in audit_test.go will catch leaks.
}

func TestBuildOutputs_PartialFailure_MultipleOutputs(t *testing.T) {
	dir := t.TempDir()
	_, err := audit.BuildOutputs(audit.OutputsConfig{
		Stdout: &audit.StdoutConfig{},
		File:   &audit.FileConfig{Path: filepath.Join(dir, "a.log")},
		Extra: []audit.NamedOutputConfig{
			{Name: "bad", Type: "webhook", Webhook: &audit.WebhookConfig{}}, // empty URL
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestBuildOutputs_SuccessPath_Unchanged(t *testing.T) {
	dir := t.TempDir()
	opts, err := audit.BuildOutputs(audit.OutputsConfig{
		Stdout: &audit.StdoutConfig{},
		File:   &audit.FileConfig{Path: filepath.Join(dir, "audit.log")},
	})
	require.NoError(t, err)
	assert.Len(t, opts, 2)
}

func TestBuildOutputs_NamedOutputUsedWithLogger(t *testing.T) {
	dir := t.TempDir()
	outputOpts, err := audit.BuildOutputs(audit.OutputsConfig{
		Extra: []audit.NamedOutputConfig{
			{
				Name: "security-file",
				Type: "file",
				File: &audit.FileConfig{Path: filepath.Join(dir, "sec.log")},
				Route: audit.EventRoute{
					IncludeCategories: []string{"security"},
				},
			},
			{
				Name: "all-file",
				Type: "file",
				File: &audit.FileConfig{Path: filepath.Join(dir, "all.log")},
			},
		},
	})
	require.NoError(t, err)

	loggerOpts := append([]audit.Option{
		audit.WithTaxonomy(testhelper.TestTaxonomy()),
	}, outputOpts...)

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		loggerOpts...,
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}
