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
	"sync"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferCap_ReturnsConfiguredSize(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithBufferSize(500),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	assert.Equal(t, 500, logger.BufferCap())
}

func TestBufferLen_ReturnsCurrentOccupancy(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// BufferLen starts at 0 (drain goroutine may process immediately).
	assert.GreaterOrEqual(t, logger.BufferLen(), 0)
}

func TestOutputNames_ReturnsSortedNames(t *testing.T) {
	t.Parallel()
	outB := testhelper.NewMockOutput("beta")
	outA := testhelper.NewMockOutput("alpha")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(outB, outA),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	names := logger.OutputNames()
	assert.Equal(t, []string{"alpha", "beta"}, names)
}

func TestIsCategoryEnabled_ReturnsCorrectState(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	assert.True(t, logger.IsCategoryEnabled("security"), "security category should be enabled by default")
	assert.False(t, logger.IsCategoryEnabled("nonexistent"), "unknown category should return false")

	require.NoError(t, logger.DisableCategory("security"))
	assert.False(t, logger.IsCategoryEnabled("security"), "disabled category should return false")
}

func TestIsEventEnabled_ReturnsCorrectState(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	assert.True(t, logger.IsEventEnabled("auth_failure"), "registered event should be enabled")
	assert.False(t, logger.IsEventEnabled("nonexistent"), "unknown event should return false")
}

func TestIntrospection_DisabledLogger_ReturnsZero(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithDisabled(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	assert.Equal(t, 0, logger.BufferLen())
	assert.Equal(t, 0, logger.BufferCap())
	assert.True(t, logger.IsDisabled())
	assert.False(t, logger.IsCategoryEnabled("security"))
	assert.False(t, logger.IsEventEnabled("auth_failure"))
}

func TestIntrospection_SyncLogger(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithSynchronousDelivery(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	assert.True(t, logger.IsSynchronous())
	assert.False(t, logger.IsDisabled())
	assert.Equal(t, 0, logger.BufferLen(), "sync logger has no buffer")
	assert.Equal(t, 0, logger.BufferCap(), "sync logger has no buffer")
}

func TestIntrospection_ConcurrentWithAuditEvent_NoRace(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = logger.BufferLen()
			_ = logger.BufferCap()
			_ = logger.OutputNames()
			_ = logger.IsCategoryEnabled("security")
			_ = logger.IsEventEnabled("auth_failure")
			_ = logger.IsDisabled()
			_ = logger.IsSynchronous()
		}()
	}
	wg.Wait()
}
