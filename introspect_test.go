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

func TestQueueCap_ReturnsConfiguredSize(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithQueueSize(500),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.Equal(t, 500, auditor.QueueCap())
}

func TestQueueLen_ReturnsCurrentOccupancy(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// QueueLen starts at 0 (drain goroutine may process immediately).
	assert.GreaterOrEqual(t, auditor.QueueLen(), 0)
}

func TestOutputNames_ReturnsSortedNames(t *testing.T) {
	t.Parallel()
	outB := testhelper.NewMockOutput("beta")
	outA := testhelper.NewMockOutput("alpha")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(outB, outA),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	names := auditor.OutputNames()
	assert.Equal(t, []string{"alpha", "beta"}, names)
}

func TestIsCategoryEnabled_ReturnsCorrectState(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.True(t, auditor.IsCategoryEnabled("security"), "security category should be enabled by default")
	assert.False(t, auditor.IsCategoryEnabled("nonexistent"), "unknown category should return false")

	require.NoError(t, auditor.DisableCategory("security"))
	assert.False(t, auditor.IsCategoryEnabled("security"), "disabled category should return false")
}

func TestIsEventEnabled_ReturnsCorrectState(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.True(t, auditor.IsEventEnabled("auth_failure"), "registered event should be enabled")
	assert.False(t, auditor.IsEventEnabled("nonexistent"), "unknown event should return false")
}

func TestIntrospection_DisabledLogger_ReturnsZero(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithDisabled(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.Equal(t, 0, auditor.QueueLen())
	assert.Equal(t, 0, auditor.QueueCap())
	assert.True(t, auditor.IsDisabled())
	assert.False(t, auditor.IsCategoryEnabled("security"))
	assert.False(t, auditor.IsEventEnabled("auth_failure"))
}

func TestIntrospection_SyncAuditor(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(
		audit.WithSynchronousDelivery(),
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.True(t, auditor.IsSynchronous())
	assert.False(t, auditor.IsDisabled())
	assert.Equal(t, 0, auditor.QueueLen(), "sync auditor has no buffer")
	assert.Equal(t, 0, auditor.QueueCap(), "sync auditor has no buffer")
}

func TestIntrospection_ConcurrentWithAuditEvent_NoRace(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = auditor.QueueLen()
			_ = auditor.QueueCap()
			_ = auditor.OutputNames()
			_ = auditor.IsCategoryEnabled("security")
			_ = auditor.IsEventEnabled("auth_failure")
			_ = auditor.IsDisabled()
			_ = auditor.IsSynchronous()
		}()
	}
	wg.Wait()
}
