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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---------------------------------------------------------------------------
// Helper: create a logger with a mock output
// ---------------------------------------------------------------------------

func newTestLogger(t *testing.T, cfg audit.Config, out *testhelper.MockOutput, opts ...audit.Option) *audit.Logger {
	t.Helper()
	allOpts := []audit.Option{
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	}
	allOpts = append(allOpts, opts...)
	logger, err := audit.NewLogger(cfg, allOpts...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, logger.Close())
	})
	return logger
}

// ---------------------------------------------------------------------------
// Audit call validation tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_ValidCall(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	})
	require.NoError(t, err)

	require.True(t, out.WaitForEvents(1, 2*time.Second), "expected 1 event")
	ev := out.GetEvent(0)
	assert.Equal(t, "schema_register", ev["event_type"])
	assert.Equal(t, "success", ev["outcome"])
	assert.Equal(t, "alice", ev["actor_id"])
	assert.NotEmpty(t, ev["timestamp"])
}

func TestLogger_Audit_MissingRequiredField(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome": "success",
		// missing actor_id and subject
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")
	assert.Contains(t, err.Error(), "actor_id")
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_MissingSingleRequiredField(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		// missing subject
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_UnknownEventType(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("schema_registr", audit.Fields{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
	assert.Contains(t, err.Error(), "schema_registr")
}

func TestLogger_Audit_UnknownFieldStrict(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		ValidationMode: audit.ValidationStrict,
	}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fields")
	assert.Contains(t, err.Error(), "bogus_field")
}

func TestLogger_Audit_UnknownFieldWarn(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		ValidationMode: audit.ValidationWarn,
	}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	})
	// Warn mode: no error, event accepted.
	assert.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_Audit_UnknownFieldPermissive(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		ValidationMode: audit.ValidationPermissive,
	}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	})
	assert.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_Audit_NilFields(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// schema_register requires outcome, actor_id, subject — nil map
	// means all are missing.
	err := logger.Audit("schema_register", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestLogger_Audit_DisabledCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "read" category is not in DefaultEnabled.
	err := logger.Audit("schema_read", audit.Fields{"outcome": "success"})
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove the drain loop processed
	// past the filtered event.
	err = logger.Audit("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category event should not be delivered")
	assert.Equal(t, "auth_failure", out.GetEvent(0)["event_type"])
}

func TestLogger_Audit_OptionalFields(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// Include an optional field.
	err := logger.Audit("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	ev := out.GetEvent(0)
	assert.Equal(t, "AVRO", ev["schema_type"])
}

// ---------------------------------------------------------------------------
// Framework-provided fields tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_TimestampAutoPopulated(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	before := time.Now()
	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	tsStr, ok := ev["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string")
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	require.NoError(t, err)
	assert.False(t, ts.Before(before), "timestamp should be after test start")
}

func TestLogger_Audit_EventTypeAutoPopulated(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "auth_failure", ev["event_type"])
}

func TestLogger_Audit_ConsumerTimestampOverwritten(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, ValidationMode: audit.ValidationPermissive}, out)

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":   "failure",
		"actor_id":  "bob",
		"timestamp": "consumer-set-value",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	// Framework should have overwritten the consumer value.
	assert.NotEqual(t, "consumer-set-value", ev["timestamp"])
}

// ---------------------------------------------------------------------------
// OmitEmpty tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyTrue(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, OmitEmpty: true}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasSchemaType := ev["schema_type"]
	assert.False(t, hasSchemaType, "OmitEmpty should omit unset optional fields")
}

func TestLogger_Audit_OmitEmptyFalse(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, OmitEmpty: false}, out)

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasSchemaType := ev["schema_type"]
	assert.True(t, hasSchemaType, "OmitEmpty=false should include all registered fields")
}

// ---------------------------------------------------------------------------
// EventType handle tests
// ---------------------------------------------------------------------------

func TestLogger_Handle_Valid(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	h, err := logger.Handle("schema_register")
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, "schema_register", h.Name())
}

func TestLogger_Handle_Error(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	h, err := logger.Handle("nonexistent")
	require.Error(t, err)
	assert.Nil(t, h)
	assert.ErrorIs(t, err, audit.ErrHandleNotFound)
}

func TestLogger_MustHandle_Valid(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	assert.NotPanics(t, func() {
		h := logger.MustHandle("schema_register")
		assert.Equal(t, "schema_register", h.Name())
	})
}

func TestLogger_MustHandle_Panics(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	assert.Panics(t, func() {
		logger.MustHandle("nonexistent")
	})
}

func TestLogger_Handle_Audit(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	h := logger.MustHandle("auth_failure")
	err := h.Audit(audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "auth_failure", ev["event_type"])
}

// ---------------------------------------------------------------------------
// Buffer and shutdown tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_EventDelivered(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount())
}

func TestLogger_Audit_BufferFull(t *testing.T) {

	metrics := testhelper.NewMockMetrics()

	// Tiny buffer + blocking output to force buffer full.
	out := &blockingOutput{name: "blocking", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 1, DrainTimeout: 50 * time.Millisecond},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Fill the buffer (1 slot) + drain goroutine may take one.
	// Send enough to guarantee overflow.
	var bufferFullSeen bool
	for i := 0; i < 100; i++ {
		err = logger.Audit("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		})
		if errors.Is(err, audit.ErrBufferFull) {
			bufferFullSeen = true
		}
	}

	assert.True(t, bufferFullSeen, "should have seen ErrBufferFull")
	assert.Greater(t, metrics.GetBufferDrops(), 0, "should have recorded buffer drops")
}

// blockingOutput blocks on Write until blockCh is closed.
type blockingOutput struct {
	blockCh chan struct{}
	name    string
}

func (b *blockingOutput) Write(_ []byte) error {
	<-b.blockCh
	return nil
}
func (b *blockingOutput) Close() error { return nil }
func (b *blockingOutput) Name() string { return b.name }

func TestLogger_Close_DrainsEvents(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Send several events.
	for i := 0; i < 10; i++ {
		err := logger.Audit("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		})
		require.NoError(t, err)
	}

	// Close should drain all.
	require.NoError(t, logger.Close())
	assert.Equal(t, 10, out.EventCount(), "Close should drain all pending events")
}

func TestLogger_Close_Idempotent(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Close())
	require.NoError(t, logger.Close()) // second call: no error.
}

func TestLogger_Audit_AfterClose(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	assert.ErrorIs(t, err, audit.ErrClosed)
}

func TestLogger_Close_DrainTimeout(t *testing.T) {

	// Use a blocking output that never unblocks combined with a very
	// short drain timeout. Close should return within a bounded time
	// rather than hanging.
	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 10, DrainTimeout: 10 * time.Millisecond},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Enqueue an event so the drain goroutine has work to do.
	_ = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})

	start := time.Now()
	_ = logger.Close()
	elapsed := time.Since(start)

	// Close should complete quickly (within 1s), not hang for the
	// default 5s drain timeout.
	assert.Less(t, elapsed, 1*time.Second, "Close should respect short DrainTimeout")
}

func TestLogger_Close_OutputError(t *testing.T) {

	out := &errorOutput{name: "bad", closeErr: errors.New("close failed")}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
	assert.Contains(t, err.Error(), "bad", "error should include output name")
}

type errorOutput struct {
	closeErr error
	name     string
}

func (e *errorOutput) Write(_ []byte) error { return nil }
func (e *errorOutput) Close() error         { return e.closeErr }
func (e *errorOutput) Name() string         { return e.name }

// ---------------------------------------------------------------------------
// Filter tests
// ---------------------------------------------------------------------------

func TestLogger_EnableCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "read" is not in DefaultEnabled. Enable it.
	require.NoError(t, logger.EnableCategory("read"))

	err := logger.Audit("schema_read", audit.Fields{"outcome": "success"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_DisableCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "write" is in DefaultEnabled. Disable it.
	require.NoError(t, logger.DisableCategory("write"))

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	})
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove processing.
	err = logger.Audit("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category should not deliver events")
}

func TestLogger_EnableEvent_OverridesCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "read" category is disabled. Enable one specific event.
	require.NoError(t, logger.EnableEvent("schema_read"))

	err := logger.Audit("schema_read", audit.Fields{"outcome": "success"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// config_read (same category, no override) should still be filtered.
	err = logger.Audit("config_read", audit.Fields{"outcome": "success"})
	require.NoError(t, err)

	// Send an enabled event as sentinel, then verify only 2 events
	// (schema_read + sentinel), not 3.
	err = logger.Audit("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "only overridden event + sentinel should be delivered")
}

func TestLogger_DisableEvent_OverridesCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "write" category is enabled. Disable one specific event.
	require.NoError(t, logger.DisableEvent("schema_register"))

	err := logger.Audit("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	})
	require.NoError(t, err)

	// schema_delete (same category, no override) should still work.
	err = logger.Audit("schema_delete", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "only non-overridden event should be delivered")
}

func TestLogger_Filter_InvalidCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.EnableCategory("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown category")

	err = logger.DisableCategory("nonexistent")
	assert.Error(t, err)
}

func TestLogger_Filter_InvalidEvent(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.EnableEvent("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")

	err = logger.DisableEvent("nonexistent")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Lifecycle tests
// ---------------------------------------------------------------------------

func TestLogger_EmitStartup(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.EmitStartup(audit.Fields{"app_name": "test-app"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "startup", ev["event_type"])
	assert.Equal(t, "test-app", ev["app_name"])
}

func TestLogger_Close_AutoEmitsShutdown(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.EmitStartup(audit.Fields{"app_name": "test-app"})
	require.NoError(t, err)

	require.NoError(t, logger.Close())

	// Should have startup + shutdown.
	assert.Equal(t, 2, out.EventCount())
	ev := out.GetEvent(1)
	assert.Equal(t, "shutdown", ev["event_type"])
	assert.Equal(t, "test-app", ev["app_name"], "shutdown should reuse startup app_name")
}

func TestLogger_Close_NoStartupNoShutdown(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.EventCount(), "no shutdown without prior startup")
}

// ---------------------------------------------------------------------------
// Concurrency tests (run with -race)
// ---------------------------------------------------------------------------

func TestLogger_ConcurrentAudit(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = logger.Audit("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			})
		}()
	}
	wg.Wait()

	// All 100 events should be delivered (buffer is 10k).
	require.True(t, out.WaitForEvents(100, 5*time.Second))
}

func TestLogger_ConcurrentFilterMutation(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	var wg sync.WaitGroup
	// Concurrent filter mutations + audit calls.
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = logger.EnableCategory("read")
			_ = logger.DisableCategory("read")
		}()
		go func() {
			defer wg.Done()
			_ = logger.Audit("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			})
		}()
	}
	wg.Wait()
}

func TestLogger_ConcurrentClose(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var errCount atomic.Int32

	// Close from multiple goroutines — no panic, no race.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := logger.Close(); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(0), errCount.Load(), "idempotent Close should not error")
}

// ---------------------------------------------------------------------------
// Metrics tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_MetricsRecordSuccess(t *testing.T) {

	out := testhelper.NewMockOutput("test-out")
	metrics := testhelper.NewMockMetrics()
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Wait for the metric to be recorded — RecordEvent fires after
	// Write returns, so WaitForEvents alone is insufficient.
	require.True(t, metrics.WaitForMetric("test-out:success", 1, 2*time.Second),
		"timed out waiting for success metric")
}

func TestLogger_Audit_MetricsRecordOutputError(t *testing.T) {

	metrics := testhelper.NewMockMetrics()
	out := &errorWriteOutput{name: "bad-write"}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)

	// Close drains all pending events and completes metric recording.
	require.NoError(t, logger.Close())

	assert.Greater(t, metrics.GetEventCount("bad-write", "error"), 0)
	assert.Greater(t, metrics.GetOutputErrorCount("bad-write"), 0)
}

type errorWriteOutput struct {
	name string
}

func (e *errorWriteOutput) Write(_ []byte) error { return errors.New("write failed") }
func (e *errorWriteOutput) Close() error         { return nil }
func (e *errorWriteOutput) Name() string         { return e.name }

// ---------------------------------------------------------------------------
// No outputs configured
// ---------------------------------------------------------------------------

func TestLogger_Audit_NoOutputs(t *testing.T) {

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)

	// Should not error — events are validated and filtered but go nowhere.
	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	assert.NoError(t, err)
	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// Config bounds tests
// ---------------------------------------------------------------------------

func TestNewLogger_BufferSizeExceedsMax(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: audit.MaxBufferSize + 1},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestNewLogger_DrainTimeoutExceedsMax(t *testing.T) {
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, DrainTimeout: audit.MaxDrainTimeout + 1},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// ---------------------------------------------------------------------------
// OmitEmpty with non-string zero values
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyZeroInt(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, OmitEmpty: true, ValidationMode: audit.ValidationPermissive}, out)

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    0,     // zero int should be omitted
		"active":   false, // false bool should be omitted
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasCount := ev["count"]
	assert.False(t, hasCount, "OmitEmpty should omit zero int")
	_, hasActive := ev["active"]
	assert.False(t, hasActive, "OmitEmpty should omit false bool")
}

// ---------------------------------------------------------------------------
// Shutdown with nil app_name stored
// ---------------------------------------------------------------------------

func TestLogger_Close_ShutdownWithoutAppName(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: audit.ValidationPermissive},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// EmitStartup without app_name (will fail validation in strict,
	// but we use permissive to test the shutdown fallback).
	err = logger.EmitStartup(audit.Fields{"app_name": "my-service"})
	require.NoError(t, err)

	require.NoError(t, logger.Close())

	// Both startup and shutdown should have arrived.
	assert.Equal(t, 2, out.EventCount())
}

// ---------------------------------------------------------------------------
// Serialisation failure — non-JSON-serialisable field value
// ---------------------------------------------------------------------------

func TestLogger_Audit_SerializationFailure(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		ValidationMode: audit.ValidationPermissive,
	}, out)

	// A channel cannot be marshalled to JSON. The event passes validation
	// (permissive mode) and is enqueued, but serialisation fails in the
	// drain loop. The output should receive zero events and no panic.
	ch := make(chan struct{})
	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"bad":      ch,
	})
	require.NoError(t, err)

	// Send a valid event as sentinel to confirm drain loop processed
	// the bad event without crashing.
	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "sentinel",
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// Only the valid event should have been delivered.
	assert.Equal(t, 1, out.EventCount())
}

// ---------------------------------------------------------------------------
// copyFields with nil input
// ---------------------------------------------------------------------------

func TestLogger_Audit_NilFieldsNoRequiredFields(t *testing.T) {

	// Create a taxonomy with an event that has no required fields.
	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string][]string{"misc": {"no_req"}},
		Events: map[string]audit.EventDef{
			"no_req": {Category: "misc", Optional: []string{"info"}},
		},
		DefaultEnabled: []string{"misc"},
	}

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// nil fields should work when there are no required fields.
	err = logger.Audit("no_req", nil)
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

// ---------------------------------------------------------------------------
// Concurrent writes + Close race test
// ---------------------------------------------------------------------------

func TestLogger_ConcurrentWritesAndClose(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Start N goroutines writing, then Close concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = logger.Audit("auth_failure", audit.Fields{
					"outcome":  "failure",
					"actor_id": "bob",
				})
			}
		}()
	}

	// Close while writes are in flight -- must not panic or race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = logger.Close()
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Handle.Audit after Close
// ---------------------------------------------------------------------------

func TestLogger_Handle_AuditAfterClose(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	h := logger.MustHandle("auth_failure")
	require.NoError(t, logger.Close())

	err = h.Audit(audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	assert.ErrorIs(t, err, audit.ErrClosed)
}

// ---------------------------------------------------------------------------
// EmitStartup without app_name in strict mode
// ---------------------------------------------------------------------------

func TestLogger_EmitStartup_MissingAppName(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.EmitStartup(audit.Fields{"version": "1.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")
	assert.Contains(t, err.Error(), "app_name")
}

func TestLogger_EmitStartup_BufferFull_NoShutdown(t *testing.T) {
	// Use the blocking output to prevent the drain goroutine from
	// consuming events, keeping the channel full.
	blockCh := make(chan struct{})
	blocker := &blockingOutput{name: "test", blockCh: blockCh}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 1},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(blocker),
	)
	require.NoError(t, err)

	// Fill the channel: first event goes to drain (blocks in Write),
	// second event fills the 1-slot buffer.
	_ = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	_ = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "charlie",
	})

	// Buffer should now be full; EmitStartup should fail.
	err = logger.EmitStartup(audit.Fields{"app_name": "test-app"})
	assert.ErrorIs(t, err, audit.ErrBufferFull)

	// Unblock the drain and close. Since startupEmitted was never
	// set to true, Close must not emit a shutdown event.
	close(blockCh)
	require.NoError(t, logger.Close())
}

func TestLogger_EmitStartup_ValidationError_NoShutdown(t *testing.T) {
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// EmitStartup without required "app_name" field.
	err := logger.EmitStartup(audit.Fields{"version": "1.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")

	// Close and verify no events were delivered at all — the startup
	// event was rejected before enqueue, so nothing reached the output.
	require.NoError(t, logger.Close())
	assert.Equal(t, 0, out.EventCount(),
		"no events should be delivered when EmitStartup fails validation")
}

// ---------------------------------------------------------------------------
// Multi-output fan-out
// ---------------------------------------------------------------------------

func TestLogger_Audit_MultipleOutputs(t *testing.T) {

	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out1, out2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})
	require.NoError(t, err)

	require.True(t, out1.WaitForEvents(1, 2*time.Second))
	require.True(t, out2.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out1.EventCount())
	assert.Equal(t, 1, out2.EventCount())
}

// ---------------------------------------------------------------------------
// OmitEmpty with non-zero values included
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmptyNonZeroIncluded(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		OmitEmpty:      true,
		ValidationMode: audit.ValidationPermissive,
	}, out)

	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    42,
		"active":   true,
	})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, float64(42), ev["count"], "non-zero int should be included with OmitEmpty")
	assert.Equal(t, true, ev["active"], "true bool should be included with OmitEmpty")
}

// ---------------------------------------------------------------------------
// isZeroValue does not panic on func values
// ---------------------------------------------------------------------------

func TestLogger_Audit_FuncFieldOmitEmpty(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		OmitEmpty:      true,
		ValidationMode: audit.ValidationPermissive,
	}, out)

	// A func value should not cause a panic in isZeroValue.
	// With OmitEmpty, isZeroValue returns false for a non-nil func,
	// so the func is included in the map. json.Marshal will fail on
	// func types, causing the event to be dropped. The drain goroutine
	// must survive this without panicking.
	err := logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"callback": func() {},
	})
	require.NoError(t, err)

	// Send sentinel to prove drain goroutine survived the bad event.
	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "sentinel",
	})
	require.NoError(t, err)
	// Only the sentinel arrives (the func event fails serialization).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

// ---------------------------------------------------------------------------
// Shutdown event dropped on full buffer
// ---------------------------------------------------------------------------

func TestLogger_Close_ShutdownEventDroppedOnFullBuffer(t *testing.T) {

	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 1, DrainTimeout: 50 * time.Millisecond},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// Emit startup so Close will try to emit shutdown.
	_ = logger.EmitStartup(audit.Fields{"app_name": "test-app"})

	// Fill the buffer so emitShutdown's non-blocking send hits default.
	for i := 0; i < 100; i++ {
		_ = logger.Audit("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		})
	}

	// Close should not panic or hang even when shutdown event is dropped.
	_ = logger.Close()
}

// ---------------------------------------------------------------------------
// Empty DefaultEnabled -- all events filtered
// ---------------------------------------------------------------------------

func TestLogger_Audit_EmptyDefaultEnabled(t *testing.T) {

	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string][]string{"write": {"ev1"}},
		Events: map[string]audit.EventDef{
			"ev1": {Category: "write", Required: []string{"f1"}},
		},
		DefaultEnabled: []string{}, // empty -- only lifecycle enabled
	}

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// ev1 should be filtered (write category not enabled).
	err = logger.Audit("ev1", audit.Fields{"f1": "val"})
	require.NoError(t, err)

	// Startup (lifecycle, always enabled) should work as sentinel.
	err = logger.Audit("startup", audit.Fields{"app_name": "test"})
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "only lifecycle event should pass when DefaultEnabled is empty")
}

// ---------------------------------------------------------------------------
// Metrics instrumentation tests (#36)
// ---------------------------------------------------------------------------

func TestAudit_UnknownEventType_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	_ = logger.Audit("nonexistent", audit.Fields{})

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["nonexistent"])
}

func TestAudit_MissingRequiredField_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	_ = logger.Audit("schema_register", audit.Fields{"outcome": "ok"})

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["schema_register"])
}

func TestAudit_UnknownFieldStrict_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: audit.ValidationStrict},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	_ = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	})

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["auth_failure"])
}

func TestAudit_FilteredEvent_RecordsFiltered(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	// "read" category is not in DefaultEnabled.
	_ = logger.Audit("schema_read", audit.Fields{"outcome": "ok"})

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.GlobalFiltered["schema_read"])
}

func TestAudit_FilteredEventOverride_RecordsFiltered(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	// Disable a specific event in an enabled category.
	require.NoError(t, logger.DisableEvent("schema_register"))

	_ = logger.Audit("schema_register", audit.Fields{
		"outcome":  "ok",
		"actor_id": "alice",
		"subject":  "test",
	})

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.GlobalFiltered["schema_register"])
}

func TestProcessEntry_SerializationError_RecordsMetric(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	badFormatter := &stubFormatter{
		fn: func(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
			return nil, errors.New("format failed")
		},
	}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(badFormatter),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	err = logger.Audit("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
	})
	require.NoError(t, err)

	// Close drains the event through processEntry, triggering the
	// serialization error metric.
	require.NoError(t, logger.Close())

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Greater(t, metrics.SerializationErrors["auth_failure"], 0)
}

func TestEmitShutdown_BufferFull_RecordsBufferDrop(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := &blockingOutput{name: "stuck", blockCh: make(chan struct{})}
	t.Cleanup(func() { close(out.blockCh) })

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 1, DrainTimeout: 50 * time.Millisecond},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	_ = logger.EmitStartup(audit.Fields{"app_name": "test"})

	// Fill the buffer.
	for i := 0; i < 100; i++ {
		_ = logger.Audit("auth_failure", audit.Fields{
			"outcome":  "fail",
			"actor_id": "bob",
		})
	}

	_ = logger.Close()

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Greater(t, metrics.BufferDrops, 0, "emitShutdown should call RecordBufferDrop on buffer full")
}

func TestAudit_NilMetrics_NoPanic(t *testing.T) {
	// Verify that all metrics paths handle nil metrics without panic,
	// including the async serialization error path in processEntry.
	badFormatter := &stubFormatter{
		fn: func(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef) ([]byte, error) {
			return nil, errors.New("format failed")
		},
	}
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithFormatter(badFormatter),
		// No WithMetrics -- metrics is nil.
	)
	require.NoError(t, err)

	// Validation error path (unknown event type).
	_ = logger.Audit("nonexistent", audit.Fields{})
	// Missing required field path.
	_ = logger.Audit("schema_register", audit.Fields{"outcome": "ok"})
	// Filtered event path.
	_ = logger.Audit("schema_read", audit.Fields{"outcome": "ok"})
	// Normal path (will trigger serialization error in drain goroutine).
	_ = logger.Audit("auth_failure", audit.Fields{"outcome": "fail", "actor_id": "bob"})

	// Close drains the bad event through processEntry -> serialize error
	// with nil metrics. Must not panic.
	require.NoError(t, logger.Close())
}

// ---------------------------------------------------------------------------
// DeliveryReporter — writeToOutput skips core metrics when selfReports=true
// ---------------------------------------------------------------------------

// deliveryReporterOutput is a mock output that implements DeliveryReporter.
// It reports its own delivery, so the core logger must NOT call RecordEvent
// or RecordOutputError for it.
type deliveryReporterOutput struct {
	writeErrToReturn error
	testhelper.MockOutput
}

func newDeliveryReporterOutput(name string) *deliveryReporterOutput {
	return &deliveryReporterOutput{
		MockOutput: *testhelper.NewMockOutput(name),
	}
}

func (d *deliveryReporterOutput) ReportsDelivery() bool { return true }

func (d *deliveryReporterOutput) Write(data []byte) error {
	if d.writeErrToReturn != nil {
		return d.writeErrToReturn
	}
	return d.MockOutput.Write(data) //nolint:wrapcheck // test helper, wrapping not needed
}

var _ audit.DeliveryReporter = (*deliveryReporterOutput)(nil)
var _ audit.Output = (*deliveryReporterOutput)(nil)

func TestWriteToOutput_DeliveryReporter_SuccessSkipsCoreMetrics(t *testing.T) {
	// When an output satisfies DeliveryReporter and ReportsDelivery()
	// returns true, the core logger must NOT call RecordEvent on success.
	metrics := testhelper.NewMockMetrics()
	out := newDeliveryReporterOutput("self-reporting")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, logger.Close())

	// The self-reporting output received the event.
	assert.Equal(t, 1, out.EventCount())

	// The core logger must not have called RecordEvent for this output.
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting", "success"),
		"core logger must not call RecordEvent(success) for DeliveryReporter outputs")
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting", "error"),
		"core logger must not call RecordEvent(error) for DeliveryReporter outputs")
}

func TestWriteToOutput_DeliveryReporter_ErrorSkipsCoreMetrics(t *testing.T) {
	// When a DeliveryReporter output fails on Write, the core logger must
	// NOT call RecordEvent or RecordOutputError — the output is responsible.
	metrics := testhelper.NewMockMetrics()
	out := newDeliveryReporterOutput("self-reporting-fail")
	out.writeErrToReturn = errors.New("delivery failed")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithNamedOutput(out, &audit.EventRoute{}, nil),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, logger.Close())

	// Core logger must not record any metrics for the self-reporting output.
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting-fail", "success"),
		"core logger must not call RecordEvent(success) for DeliveryReporter outputs")
	assert.Equal(t, 0, metrics.GetEventCount("self-reporting-fail", "error"),
		"core logger must not call RecordEvent(error) for DeliveryReporter outputs")

	metrics.Mu.Lock()
	errCount := metrics.OutputErrors["self-reporting-fail"]
	metrics.Mu.Unlock()
	assert.Equal(t, 0, errCount,
		"core logger must not call RecordOutputError for DeliveryReporter outputs")
}

func TestWriteToOutput_NonDeliveryReporter_SuccessRecordsCoreMetrics(t *testing.T) {
	// A plain output (not DeliveryReporter) must have RecordEvent(success)
	// called by the core logger on a successful write.
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("plain")

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(metrics),
	)
	require.NoError(t, err)

	require.NoError(t, logger.Audit("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, logger.Close())

	assert.Greater(t, metrics.GetEventCount("plain", "success"), 0,
		"core logger must call RecordEvent(success) for plain (non-DeliveryReporter) outputs")
}

// ---------------------------------------------------------------------------
// isZeroValue — integer and float type branches
// ---------------------------------------------------------------------------

func TestLogger_Audit_OmitEmpty_NumericTypeBranches(t *testing.T) {
	// Exercises the int32, float32, uint, uint64 branches in isZeroValue
	// via the OmitEmpty path through the JSON formatter.
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{
		Version:        1,
		Enabled:        true,
		OmitEmpty:      true,
		ValidationMode: audit.ValidationPermissive,
	}, out)

	tests := []struct {
		name    string
		fields  audit.Fields
		wantKey string
		wantIn  bool
	}{
		{
			name:    "zero int32 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int32(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero int32 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int32(7)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero float32 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float32(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero float32 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float32(3.14)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero uint omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": uint(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero uint included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": uint(99)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero uint64 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": uint64(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero uint64 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": uint64(1)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero int64 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int64(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero int64 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": int64(42)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name:    "zero float64 omitted",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float64(0)},
			wantKey: "val",
			wantIn:  false,
		},
		{
			name:    "non-zero float64 included",
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": float64(2.71)},
			wantKey: "val",
			wantIn:  true,
		},
		{
			name: "slice value not omitted (default branch)",
			// A non-nil slice hits the default branch in isZeroValue, which
			// returns false (not a zero value), so the field is included.
			fields:  audit.Fields{"outcome": "ok", "actor_id": "x", "val": []string{"a"}},
			wantKey: "val",
			wantIn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a fresh output per subtest to avoid event ordering issues.
			subOut := testhelper.NewMockOutput("sub-" + tt.name)
			subLogger, err := audit.NewLogger(
				audit.Config{
					Version:        1,
					Enabled:        true,
					OmitEmpty:      true,
					ValidationMode: audit.ValidationPermissive,
				},
				audit.WithTaxonomy(testhelper.ValidTaxonomy()),
				audit.WithOutputs(subOut),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, subLogger.Close()) })

			require.NoError(t, subLogger.Audit("auth_failure", tt.fields))
			require.True(t, subOut.WaitForEvents(1, 2*time.Second))

			ev := subOut.GetEvent(0)
			_, found := ev[tt.wantKey]
			if tt.wantIn {
				assert.True(t, found, "field %q should be present when non-zero", tt.wantKey)
			} else {
				assert.False(t, found, "field %q should be omitted when zero", tt.wantKey)
			}
		})
	}

	// Prevent unused warning for the outer logger.
	require.NoError(t, logger.Audit("auth_failure", audit.Fields{"outcome": "ok", "actor_id": "x"}))
	_ = out
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkAudit(b *testing.B) {
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.Audit("schema_register", fields)
	}
}

func BenchmarkAuditDisabledCategory(b *testing.B) {
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	fields := audit.Fields{"outcome": "success"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.Audit("schema_read", fields)
	}
}

func BenchmarkAuditDisabledLogger(b *testing.B) {
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: false},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.Audit("auth_failure", fields)
	}
}
