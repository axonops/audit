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
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
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
	out := testhelper.NewMockOutput("disabled-check")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: false},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Audit on disabled logger returns nil.
	err = logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	assert.NoError(t, err)

	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.EventCount(), "disabled logger must not deliver events")
}

func TestNewLogger_NegativeBufferSize_DefaultsCorrectly(t *testing.T) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: -1},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(testhelper.NewMockOutput("test")),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}
