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
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reportingMockOutput is a minimal audit.Output that also implements
// audit.LastDeliveryReporter — used to drive the LastDeliveryAge
// introspection tests against a controllable timestamp source (#753).
type reportingMockOutput struct {
	name              string
	lastDeliveryNanos atomic.Int64
}

func (m *reportingMockOutput) Name() string                 { return m.name }
func (m *reportingMockOutput) Write([]byte) error           { return nil }
func (m *reportingMockOutput) Close() error                 { return nil }
func (m *reportingMockOutput) LastDeliveryNanos() int64     { return m.lastDeliveryNanos.Load() }
func (m *reportingMockOutput) setLastDeliveryNanos(v int64) { m.lastDeliveryNanos.Store(v) }

// nonReportingMockOutput is a minimal audit.Output that does NOT
// implement audit.LastDeliveryReporter — drives the "type-assert
// fails → return 0" code path in Auditor.LastDeliveryAge.
type nonReportingMockOutput struct{ name string }

func (m *nonReportingMockOutput) Name() string       { return m.name }
func (m *nonReportingMockOutput) Write([]byte) error { return nil }
func (m *nonReportingMockOutput) Close() error       { return nil }

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

func TestLastDeliveryAge_UnknownOutputReturnsZero(t *testing.T) {
	t.Parallel()
	out := &reportingMockOutput{name: "mock"}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.Equal(t, time.Duration(0), auditor.LastDeliveryAge("not-configured"),
		"unknown output name must return zero duration")
}

func TestLastDeliveryAge_NeverDeliveredReturnsZero(t *testing.T) {
	t.Parallel()
	out := &reportingMockOutput{name: "mock"}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Output exists, but lastDeliveryNanos is still zero — the
	// "no successful delivery yet" arm.
	assert.Equal(t, time.Duration(0), auditor.LastDeliveryAge(out.Name()),
		"never-delivered output must return zero duration")
}

func TestLastDeliveryAge_NonReporterOutputReturnsZero(t *testing.T) {
	t.Parallel()
	// Output exists but doesn't implement LastDeliveryReporter —
	// telemetry unavailable, signal is zero (the "no info" sentinel).
	out := &nonReportingMockOutput{name: "plain"}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.Equal(t, time.Duration(0), auditor.LastDeliveryAge(out.Name()),
		"non-reporter output must return zero duration")
}

func TestLastDeliveryAge_AdvancesWithRecentDelivery(t *testing.T) {
	t.Parallel()
	out := &reportingMockOutput{name: "mock"}
	auditor, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	// Set delivery to 50ms ago.
	out.setLastDeliveryNanos(time.Now().Add(-50 * time.Millisecond).UnixNano())
	age := auditor.LastDeliveryAge(out.Name())
	// Age should be ≥ 50ms and within a tight window — a bug that
	// returns a constant value of any kind would fail the upper
	// bound, and a bug that returns an off-by-orders-of-magnitude
	// value (e.g., time.Since(time.Unix(0, 0))) would also fail.
	assert.GreaterOrEqual(t, age, 50*time.Millisecond,
		"age must be at least the elapsed time since recorded delivery")
	assert.Less(t, age, 500*time.Millisecond,
		"age must be approximately the elapsed time, not stale")
}

func TestLastDeliveryAge_DisabledAuditorReturnsZero(t *testing.T) {
	t.Parallel()
	auditor, err := audit.New(audit.WithDisabled())
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	assert.Equal(t, time.Duration(0), auditor.LastDeliveryAge("anything"),
		"disabled auditor must return zero duration regardless of name")
}
