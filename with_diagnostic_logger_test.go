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
	"bytes"
	"log/slog"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithDiagnosticLogger_CustomLogger_ReceivesMessages(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	customLogger := slog.New(slog.NewTextHandler(&buf, nil))

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithDiagnosticLogger(customLogger),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	// The "auditor created" and "shutdown" messages should appear in buf.
	assert.Contains(t, buf.String(), "auditor created")
	assert.Contains(t, buf.String(), "shutdown")
}

func TestWithDiagnosticLogger_NilLogger_UsesDefault(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	// nil auditor should not panic — falls back to slog.Default().
	auditor, err := audit.New(
		audit.WithDiagnosticLogger(nil),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())
}

func TestWithDiagnosticLogger_DiscardLogger_SilencesOutput(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	discardLogger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.Level(100), // above all levels — silences everything
	}))

	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithDiagnosticLogger(discardLogger),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	assert.Empty(t, buf.String(), "discard auditor should produce no output")
}
