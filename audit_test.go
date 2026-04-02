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
	"io"
	"log/slog"
	"strings"
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome": "success",
		// missing actor_id and subject
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")
	assert.Contains(t, err.Error(), "actor_id")
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_MissingSingleRequiredField(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		// missing subject
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject")
}

func TestLogger_Audit_UnknownEventType(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	err := logger.AuditEvent(audit.NewEvent("schema_registr", audit.Fields{}))
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"bogus_field": "value",
	}))
	assert.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_Audit_NilFields(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// schema_register requires outcome, actor_id, subject — nil map
	// means all are missing.
	err := logger.AuditEvent(audit.NewEvent("schema_register", nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required fields")
}

func TestLogger_Audit_DisabledCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// Disable the "read" category at runtime.
	require.NoError(t, logger.DisableCategory("read"))

	err := logger.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove the drain loop processed
	// past the filtered event.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category event should not be delivered")
	assert.Equal(t, "auth_failure", out.GetEvent(0)["event_type"])
}

func TestLogger_Audit_OptionalFields(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// Include an optional field.
	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
	}))
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
	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	assert.Equal(t, "auth_failure", ev["event_type"])
}

func TestLogger_Audit_ConsumerTimestampOverwritten(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, ValidationMode: audit.ValidationPermissive}, out)

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":   "failure",
		"actor_id":  "bob",
		"timestamp": "consumer-set-value",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	ev := out.GetEvent(0)
	_, hasSchemaType := ev["schema_type"]
	assert.False(t, hasSchemaType, "OmitEmpty should omit unset optional fields")
}

func TestLogger_Audit_OmitEmptyFalse(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true, OmitEmpty: false}, out)

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type (optional) not provided
	}))
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

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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
		err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
		if errors.Is(err, audit.ErrBufferFull) {
			bufferFullSeen = true
		}
	}

	assert.True(t, bufferFullSeen, "should have seen ErrBufferFull")
	assert.Greater(t, metrics.GetBufferDrops(), 0, "should have recorded buffer drops")
}

// blockingOutput blocks on Write until blockCh is closed.
// enteredCh is signalled (once) when Write is first entered, allowing
// tests to synchronise on the drain goroutine reaching the blocking point.
type blockingOutput struct {
	blockCh   chan struct{}
	enteredCh chan struct{}
	name      string
}

func (b *blockingOutput) Write(_ []byte) error {
	if b.enteredCh != nil {
		select {
		case b.enteredCh <- struct{}{}:
		default:
		}
	}
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
		err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
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

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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
	_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))

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

	// Disable "read", then re-enable it.
	require.NoError(t, logger.DisableCategory("read"))
	require.NoError(t, logger.EnableCategory("read"))

	err := logger.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
}

func TestLogger_DisableCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// Disable "write" at runtime.
	require.NoError(t, logger.DisableCategory("write"))

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	require.NoError(t, err)

	// Send an enabled event as sentinel to prove processing.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "disabled category should not deliver events")
}

func TestLogger_EnableEvent_OverridesCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// Disable "read" category, then enable one specific event from it.
	require.NoError(t, logger.DisableCategory("read"))
	require.NoError(t, logger.EnableEvent("schema_read"))

	err := logger.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	// config_read (same category, no override) should still be filtered.
	err = logger.AuditEvent(audit.NewEvent("config_read", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	// Send an enabled event as sentinel, then verify only 2 events
	// (schema_read + sentinel), not 3.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure", "actor_id": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "only overridden event + sentinel should be delivered")
}

func TestLogger_DisableEvent_OverridesCategory(t *testing.T) {

	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out)

	// "write" category is enabled. Disable one specific event.
	require.NoError(t, logger.DisableEvent("schema_register"))

	err := logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
	require.NoError(t, err)

	// schema_delete (same category, no override) should still work.
	err = logger.AuditEvent(audit.NewEvent("schema_delete", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test",
	}))
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

func TestLogger_MultiCategory_DeliveredPerCategory(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	// Create a taxonomy where auth_failure is in both security and access.
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}},
			"access":   {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Event in 2 categories → 2 deliveries to the unrouted output.
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "multi-category event should be delivered twice")
}

func TestLogger_MultiCategory_DisableOneCategory(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}},
			"access":   {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Disable one category.
	require.NoError(t, logger.DisableCategory("security"))

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Only the access pass should deliver.
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "should deliver once — only access category enabled")
}

func TestLogger_MultiCategory_DisableAllCategories(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_failure"}},
			"access":   {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	require.NoError(t, logger.DisableCategory("security"))
	require.NoError(t, logger.DisableCategory("access"))

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Both categories disabled → event enters channel but no category
	// pass runs. Send a sentinel to prove processing completed.
	require.NoError(t, logger.EnableCategory("security"))
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "sentinel"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "only sentinel should arrive — first event had all categories disabled")
}

func TestLogger_Uncategorised_DeliveredToUnroutedOutput(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	// data_export is not in any category.
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"outcome"}},
			"data_export": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("data_export", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)

	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "uncategorised event should be delivered to unrouted output")
}

func TestLogger_MultiCategory_EnableEventOverride(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	// Disable both categories, then force-enable the event.
	require.NoError(t, logger.DisableCategory("security"))
	require.NoError(t, logger.DisableCategory("compliance"))
	require.NoError(t, logger.EnableEvent("auth_failure"))

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// EnableEvent should override disabled categories — event delivered
	// on ALL category passes (both security and compliance).
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	assert.Equal(t, 2, out.EventCount(), "EnableEvent should deliver on all category passes")
}

func TestLogger_MultiCategory_IncludeRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Output includes only security — should get 1 delivery (security pass),
	// not 2 (compliance pass is filtered by the route).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "include route should match only one category pass")
}

func TestLogger_MultiCategory_ExcludeRoute(t *testing.T) {
	out := testhelper.NewMockOutput("test")

	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"auth_failure"}},
			"compliance": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(out, &audit.EventRoute{
			ExcludeCategories: []string{"security"},
		}, nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)

	// Output excludes security — should get 1 delivery (compliance pass only).
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "exclude route should skip security, deliver compliance")
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
			_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
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
			_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
				"outcome":  "failure",
				"actor_id": "bob",
			}))
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

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    0,     // zero int should be omitted
		"active":   false, // false bool should be omitted
	}))
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
	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"bad":      ch,
	}))
	require.NoError(t, err)

	// Send a valid event as sentinel to confirm drain loop processed
	// the bad event without crashing.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "sentinel",
	}))
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
		Categories: map[string]*audit.CategoryDef{"misc": {Events: []string{"no_req"}}},
		Events: map[string]*audit.EventDef{
			"no_req": {Optional: []string{"info"}},
		},
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
	err = logger.AuditEvent(audit.NewEvent("no_req", nil))
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
				_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
					"outcome":  "failure",
					"actor_id": "bob",
				}))
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
// Handle.AuditEvent after Close
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

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	}))
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

	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"count":    42,
		"active":   true,
	}))
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
	err := logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
		"callback": func() {},
	}))
	require.NoError(t, err)

	// Send sentinel to prove drain goroutine survived the bad event.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "sentinel",
	}))
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

	// Fill the buffer so emitShutdown's non-blocking send hits default.
	for i := 0; i < 100; i++ {
		_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		}))
	}

	// Close should not panic or hang even when shutdown event is dropped.
	_ = logger.Close()
}

// ---------------------------------------------------------------------------
// All categories enabled by default
// ---------------------------------------------------------------------------

func TestLogger_Audit_AllCategoriesEnabledByDefault(t *testing.T) {

	tax := audit.Taxonomy{
		Version:    1,
		Categories: map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1": {Required: []string{"f1"}},
		},
	}

	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// ev1 should be delivered — all categories enabled by default.
	err = logger.AuditEvent(audit.NewEvent("ev1", audit.Fields{"f1": "val"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, 1, out.EventCount(), "event should be delivered — all categories enabled by default")
}

// ---------------------------------------------------------------------------
// Metrics instrumentation tests (#36)
// ---------------------------------------------------------------------------

func TestAudit_UnknownEventType_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	_ = logger.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["nonexistent"])
}

func TestAudit_MissingRequiredField_RecordsValidationError(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	_ = logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{"outcome": "ok"}))

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

	_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
		"bogus":    "val",
	}))

	metrics.Mu.Lock()
	defer metrics.Mu.Unlock()
	assert.Equal(t, 1, metrics.ValidationErrors["auth_failure"])
}

func TestAudit_FilteredEvent_RecordsFiltered(t *testing.T) {
	metrics := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	logger := newTestLogger(t, audit.Config{Version: 1, Enabled: true}, out,
		audit.WithMetrics(metrics))

	// Disable "read" category at runtime, then emit an event.
	require.NoError(t, logger.DisableCategory("read"))
	_ = logger.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "ok"}))

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

	_ = logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "ok",
		"actor_id": "alice",
		"subject":  "test",
	}))

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

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "fail",
		"actor_id": "bob",
	}))
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

	// Fill the buffer.
	for i := 0; i < 100; i++ {
		_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "fail",
			"actor_id": "bob",
		}))
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
	_ = logger.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	// Missing required field path.
	_ = logger.AuditEvent(audit.NewEvent("schema_register", audit.Fields{"outcome": "ok"}))
	// Filtered event path.
	_ = logger.AuditEvent(audit.NewEvent("schema_read", audit.Fields{"outcome": "ok"}))
	// Normal path (will trigger serialization error in drain goroutine).
	_ = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "fail", "actor_id": "bob"}))

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

	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
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

	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
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

	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "bob",
	})))
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

			require.NoError(t, subLogger.AuditEvent(audit.NewEvent("auth_failure", tt.fields)))
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
	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "ok", "actor_id": "x"})))
	_ = out
}

// ---------------------------------------------------------------------------
// DestinationKeyer dedup tests
// ---------------------------------------------------------------------------

// destKeyOutput is a mock output that implements DestinationKeyer.
type destKeyOutput struct {
	name string
	key  string
}

func (d *destKeyOutput) Write(_ []byte) error { return nil }
func (d *destKeyOutput) Close() error         { return nil }
func (d *destKeyOutput) Name() string         { return d.name }
func (d *destKeyOutput) DestinationKey() string {
	return d.key
}

func TestWithOutputs_DuplicateDestination_ReturnsError(t *testing.T) {
	o1 := &destKeyOutput{name: "out1", key: "/var/log/audit.log"}
	o2 := &destKeyOutput{name: "out2", key: "/var/log/audit.log"}
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(o1, o2),
	)
	require.ErrorIs(t, err, audit.ErrDuplicateDestination)
	assert.Contains(t, err.Error(), "out1")
	assert.Contains(t, err.Error(), "out2")
}

func TestWithNamedOutput_DuplicateDestination_ReturnsError(t *testing.T) {
	o1 := &destKeyOutput{name: "out1", key: "localhost:514"}
	o2 := &destKeyOutput{name: "out2", key: "localhost:514"}
	_, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithNamedOutput(o1, nil, nil),
		audit.WithNamedOutput(o2, nil, nil),
	)
	require.ErrorIs(t, err, audit.ErrDuplicateDestination)
	assert.Contains(t, err.Error(), "out1")
	assert.Contains(t, err.Error(), "out2")
}

func TestWithOutputs_EmptyDestinationKey_NoCollision(t *testing.T) {
	// Outputs returning empty DestinationKey opt out of dedup.
	o1 := &destKeyOutput{name: "out1", key: ""}
	o2 := &destKeyOutput{name: "out2", key: ""}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(o1, o2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })
}

func TestWithOutputs_MixedTypes_NoFalsePositive(t *testing.T) {
	// destKeyOutput + MockOutput (no DestinationKeyer) should not collide.
	o1 := &destKeyOutput{name: "keyed", key: "/var/log/audit.log"}
	o2 := testhelper.NewMockOutput("unkeyed")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(o1, o2),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })
}

// ---------------------------------------------------------------------------
// formatCache tests
// ---------------------------------------------------------------------------

// cacheTestFmt is a minimal Formatter for testing the cache.
type cacheTestFmt struct{ id int }

func (f *cacheTestFmt) Format(_ time.Time, _ string, _ audit.Fields, _ *audit.EventDef, _ *audit.FormatOptions) ([]byte, error) {
	return []byte("data"), nil
}

func TestFormatCache_PutGet(t *testing.T) {
	tests := []struct {
		name       string
		formatters int
	}{
		{name: "single_formatter", formatters: 1},
		{name: "at_array_capacity", formatters: audit.FormatCacheSizeForTest},
		{name: "overflow_to_map", formatters: audit.FormatCacheSizeForTest + 1},
		{name: "well_beyond_capacity", formatters: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &audit.FormatCacheForTest{}
			fmts := make([]*cacheTestFmt, tt.formatters)
			for i := range fmts {
				fmts[i] = &cacheTestFmt{id: i}
				fc.Put(fmts[i], []byte{byte(i)})
			}

			for i, f := range fmts {
				data, ok := fc.Get(f)
				assert.True(t, ok, "formatter %d should be found", i)
				assert.Equal(t, []byte{byte(i)}, data)
			}

			unknown := &cacheTestFmt{id: 999}
			_, ok := fc.Get(unknown)
			assert.False(t, ok, "unknown formatter should not be found")
		})
	}
}

func TestFormatCache_NilData(t *testing.T) {
	fc := &audit.FormatCacheForTest{}
	f := &cacheTestFmt{id: 1}

	fc.Put(f, nil)

	data, ok := fc.Get(f)
	assert.True(t, ok, "nil-data entry should be found (cached failure)")
	assert.Nil(t, data, "data should be nil for cached failure")
}

// ---------------------------------------------------------------------------
// Field completeness tests
// ---------------------------------------------------------------------------

func TestLogger_Audit_FieldCompleteness_AllFieldsPresent(t *testing.T) {
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_check"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_check": {
				Required: []string{"outcome", "actor_id", "actor_type"},
				Optional: []string{"target_type", "target_id", "reason", "source_ip", "user_agent", "request_id"},
			},
		},
	}

	out := testhelper.NewMockOutput("field-test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	fields := audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"actor_type":  "user",
		"target_type": "schema",
		"target_id":   "my-topic-value",
		"reason":      "valid_credentials",
		"source_ip":   "192.168.1.100",
		"user_agent":  "test-client/1.0",
		"request_id":  "req-12345",
	}
	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_check", fields)))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)

	// Auto-populated fields.
	assert.Contains(t, record, "timestamp")
	assert.NotEmpty(t, record["timestamp"], "timestamp must not be empty")
	assert.Equal(t, "auth_check", record["event_type"])

	// All required fields present with correct values.
	for _, f := range tax.Events["auth_check"].Required {
		assert.Contains(t, record, f, "required field %q must be present", f)
	}

	// All optional fields we provided present with correct values.
	for _, f := range tax.Events["auth_check"].Optional {
		assert.Contains(t, record, f, "provided optional field %q must be present", f)
		assert.Equal(t, fields[f], record[f], "field %q value mismatch", f)
	}
}

func TestLogger_Audit_FieldCompleteness_OmittedOptionalFieldsAbsent(t *testing.T) {
	tax := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"auth_check"}},
		},
		Events: map[string]*audit.EventDef{
			"auth_check": {
				Required: []string{"outcome", "actor_id"},
				Optional: []string{"reason", "source_ip", "user_agent"},
			},
		},
	}

	out := testhelper.NewMockOutput("field-test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, OmitEmpty: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, logger.Close()) })

	// Send event with only required fields — optional fields omitted.
	require.NoError(t, logger.AuditEvent(audit.NewEvent("auth_check", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 2*time.Second))

	record := out.GetEvent(0)

	// Required fields must be present.
	assert.Equal(t, "success", record["outcome"])
	assert.Equal(t, "alice", record["actor_id"])

	// Optional fields not provided should be absent (OmitEmpty=true).
	for _, f := range tax.Events["auth_check"].Optional {
		assert.NotContains(t, record, f,
			"omitted optional field %q should not appear in output", f)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// silenceSlog suppresses slog output during benchmarks so that
// logger creation messages do not pollute benchmark output. The
// previous handler is restored via b.Cleanup.
func silenceSlog(b *testing.B) {
	b.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(prev) })
}

func BenchmarkAudit(b *testing.B) {
	silenceSlog(b)
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
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

func BenchmarkAuditDisabledCategory(b *testing.B) {
	silenceSlog(b)
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
		_ = logger.AuditEvent(audit.NewEvent("schema_read", fields))
	}
}

func BenchmarkAuditDisabledLogger(b *testing.B) {
	silenceSlog(b)
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
		_ = logger.AuditEvent(audit.NewEvent("auth_failure", fields))
	}
}

// ---------------------------------------------------------------------------
// Additional benchmarks — caller path
// ---------------------------------------------------------------------------

func BenchmarkAudit_RealisticFields(b *testing.B) {
	silenceSlog(b)
	taxonomy := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"api_request": {
				Required: []string{"outcome", "actor_id", "method", "path"},
				Optional: []string{"source_ip", "request_id", "user_agent", "subject", "schema_type", "version"},
			},
		},
	}
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(taxonomy),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = logger.Close() })

	fields := audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"method":      "POST",
		"path":        "/api/v1/schemas",
		"source_ip":   "10.0.0.1",
		"request_id":  "550e8400-e29b-41d4-a716-446655440000",
		"user_agent":  "go-audit-client/1.0",
		"subject":     "my-topic",
		"schema_type": "avro",
		"version":     1,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.AuditEvent(audit.NewEvent("api_request", fields))
	}
}

func BenchmarkAudit_Parallel(b *testing.B) {
	silenceSlog(b)
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

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
		}
	})
}

// BenchmarkAudit_PoolAmortised measures the Audit path under sustained
// load where the auditEntry pool is warm. Uses a large buffer and
// extended benchtime to demonstrate amortised pool benefit. The pool
// reduces GC pressure by reusing auditEntry structs rather than
// allocating and discarding them on every call.
func BenchmarkAudit_PoolAmortised(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
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

	// Warm the pool with a few iterations before measuring.
	for range 1000 {
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// ---------------------------------------------------------------------------
// Fan-out benchmarks — multi-output scenarios
// ---------------------------------------------------------------------------

// BenchmarkAudit_FanOut_SharedFormatter measures fan-out to 3 outputs
// sharing the same default formatter. The formatCache should serialise
// once and deliver the same []byte to all three outputs.
func BenchmarkAudit_FanOut_SharedFormatter(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	out3 := testhelper.NewMockOutput("out3")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out1, out2, out3),
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
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_MixedFormatters measures fan-out to 3 outputs
// with 2 different formatters (JSON + CEF + JSON). The formatCache
// should serialise once per unique formatter (2 serialisations, not 3).
func BenchmarkAudit_FanOut_MixedFormatters(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("json1")
	out2 := testhelper.NewMockOutput("cef")
	out3 := testhelper.NewMockOutput("json2")
	cefFmt := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithNamedOutput(out1, nil, nil),    // default JSON
		audit.WithNamedOutput(out2, nil, cefFmt), // CEF
		audit.WithNamedOutput(out3, nil, nil),    // default JSON (shared)
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
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_FilteredOutputs measures fan-out to 3 outputs
// where one output filters the event via an include-category route.
// This exercises the per-output route matching + filtered-output
// metrics path.
func BenchmarkAudit_FanOut_FilteredOutputs(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewMockOutput("all")
	out2 := testhelper.NewMockOutput("write-only")
	out3 := testhelper.NewMockOutput("security-only")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithNamedOutput(out1, nil, nil), // receives all events
		audit.WithNamedOutput(out2, &audit.EventRoute{
			IncludeCategories: []string{"write"},
		}, nil), // receives only write events
		audit.WithNamedOutput(out3, &audit.EventRoute{
			IncludeCategories: []string{"security"},
		}, nil), // receives only security events — filters schema_register
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
		// schema_register is "write" category — out1 and out2 receive it,
		// out3 filters it.
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

// BenchmarkAudit_FanOut_5Outputs measures fan-out to 5 outputs with
// the same formatter — tests scaling beyond the typical 1-3 output case.
func BenchmarkAudit_FanOut_5Outputs(b *testing.B) {
	silenceSlog(b)
	outputs := make([]audit.Output, 5)
	for i := range outputs {
		outputs[i] = testhelper.NewMockOutput("out" + string(rune('0'+i)))
	}
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(outputs...),
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
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
}

func BenchmarkCopyFields(b *testing.B) {
	fields := audit.Fields{
		"outcome":    "success",
		"actor_id":   "alice",
		"source_ip":  "10.0.0.1",
		"request_id": "550e8400-e29b-41d4-a716-446655440000",
		"method":     "POST",
		"path":       "/api/v1/schemas",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = audit.CopyFieldsForTest(fields)
	}
}

// BenchmarkAudit_EndToEnd measures the full Audit() path including
// enqueue with a large buffer. Events that overflow are silently
// dropped — the benchmark measures the amortised caller-side cost
// under sustained load. Drain-path (format + write) cost is measured
// separately by the formatter benchmarks.
func BenchmarkAudit_EndToEnd(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewMockOutput("bench")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, BufferSize: 100_000},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	if err != nil {
		b.Fatal(err)
	}

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = logger.AuditEvent(audit.NewEvent("schema_register", fields))
	}
	b.StopTimer()

	_ = logger.Close()
}

func BenchmarkFilterCheck(b *testing.B) {
	silenceSlog(b)
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

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = audit.IsEnabledForTest(logger, "schema_register")
	}
}

// BenchmarkFilterCheck_Parallel measures filter check throughput under
// heavy read contention. This is the scenario where sync.Map outperforms
// RWMutex — hundreds of concurrent readers avoid cache-line bouncing on
// the RWMutex reader counter.
func BenchmarkFilterCheck_Parallel(b *testing.B) {
	silenceSlog(b)
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

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = audit.IsEnabledForTest(logger, "schema_register")
		}
	})
}

// BenchmarkFilterCheck_ReadWriteContention measures filter check
// throughput while a writer goroutine continuously toggles a category.
// This simulates the production scenario of runtime filter changes
// during sustained audit traffic.
func BenchmarkFilterCheck_ReadWriteContention(b *testing.B) {
	silenceSlog(b)
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

	// Background writer toggling a category throughout the benchmark.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				_ = logger.DisableCategory("read")
				_ = logger.EnableCategory("read")
			}
		}
	}()
	b.Cleanup(func() { close(done) })

	b.SetParallelism(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = audit.IsEnabledForTest(logger, "schema_register")
		}
	})
}

// ---------------------------------------------------------------------------
// Event interface and NewEvent tests
// ---------------------------------------------------------------------------

func TestNewEvent_ImplementsInterface(t *testing.T) {
	t.Parallel()
	evt := audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})
	assert.Equal(t, "user_create", evt.EventType())
	assert.Equal(t, "success", evt.Fields()["outcome"])
	assert.Equal(t, "alice", evt.Fields()["actor_id"])
}

func TestAuditEvent_WithNewEvent(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	evt := audit.NewEvent("schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "test-schema",
	})
	require.NoError(t, logger.AuditEvent(evt))
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	assert.Equal(t, "success", out.GetEvent(0)["outcome"])
}

func TestAuditEvent_UnknownEventType(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	err = logger.AuditEvent(audit.NewEvent("nonexistent", audit.Fields{}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown event type")
}

func TestAuditEvent_NilEvent(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
	)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	err = logger.AuditEvent(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "event must not be nil")
}

// ---------------------------------------------------------------------------
// event_category (#227)
// ---------------------------------------------------------------------------

func TestAppendPostFields_JSON_SingleField(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "eventCategory", Value: "security"}}
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, fields)
	assert.Equal(t, `{"event_type":"test","outcome":"success","event_category":"security"}`+"\n", string(result))
}

func TestAppendPostFields_JSON_EmptyFields(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test"}` + "\n")
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, nil)
	assert.Equal(t, string(data), string(result), "empty fields should return unchanged data")
}

func TestAppendPostFields_CEF_SingleField(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	fields := []audit.PostField{{JSONKey: "event_category", CEFKey: "eventCategory", Value: "write"}}
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, fields)
	assert.Equal(t, "CEF:0|V|P|1|test|desc|5|outcome=success eventCategory=write\n", string(result))
}

func TestAppendPostFields_CEF_EmptyFields(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, nil)
	assert.Equal(t, string(data), string(result))
}

func TestAppendPostFields_JSON_MultipleFields(t *testing.T) {
	t.Parallel()
	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	fields := []audit.PostField{
		{JSONKey: "event_category", CEFKey: "eventCategory", Value: "security"},
		{JSONKey: "checksum", CEFKey: "checksum", Value: "abc123"},
	}
	result := audit.AppendPostFields(data, &audit.JSONFormatter{}, fields)
	assert.Contains(t, string(result), `"event_category":"security"`)
	assert.Contains(t, string(result), `"checksum":"abc123"`)
	assert.True(t, strings.HasSuffix(string(result), "}\n"))
}

func TestAppendPostFields_CEF_MultipleFields(t *testing.T) {
	t.Parallel()
	data := []byte("CEF:0|V|P|1|test|desc|5|outcome=success\n")
	fields := []audit.PostField{
		{JSONKey: "event_category", CEFKey: "eventCategory", Value: "write"},
		{JSONKey: "checksum", CEFKey: "checksum", Value: "abc123"},
	}
	result := audit.AppendPostFields(data, &audit.CEFFormatter{}, fields)
	assert.Contains(t, string(result), "eventCategory=write")
	assert.Contains(t, string(result), "checksum=abc123")
	assert.True(t, strings.HasSuffix(string(result), "\n"))
}

func TestAppendPostFields_UnknownFormatter(t *testing.T) {
	t.Parallel()
	data := []byte("some custom format\n")
	fields := []audit.PostField{{JSONKey: "k", CEFKey: "k", Value: "v"}}
	result := audit.AppendPostFields(data, nil, fields)
	assert.Equal(t, string(data), string(result), "unknown formatter should return unchanged")
}

func TestIsFrameworkField_EventCategory(t *testing.T) {
	t.Parallel()
	assert.True(t, audit.IsFrameworkField("event_category", nil))
}

func TestEventCategory_SingleCategory_JSON(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := audit.Taxonomy{
		Version:           1,
		EmitEventCategory: true,
		Categories:        map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, logger.Close())

	ev := out.GetEvent(0)
	assert.Equal(t, "security", ev["event_category"])
}

func TestEventCategory_MultiCategory_SeparateDeliveries(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := audit.Taxonomy{
		Version:           1,
		EmitEventCategory: true,
		Categories: map[string]*audit.CategoryDef{
			"security": {Events: []string{"admin_update"}},
			"write":    {Events: []string{"admin_update"}},
		},
		Events: map[string]*audit.EventDef{
			"admin_update": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("admin_update", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(2, 2*time.Second))
	require.NoError(t, logger.Close())

	cat0, ok0 := out.GetEvent(0)["event_category"].(string)
	require.True(t, ok0, "event_category should be a string")
	cat1, ok1 := out.GetEvent(1)["event_category"].(string)
	require.True(t, ok1, "event_category should be a string")
	categories := []string{cat0, cat1}
	assert.Contains(t, categories, "security")
	assert.Contains(t, categories, "write")
}

func TestEventCategory_Uncategorised_NoField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := audit.Taxonomy{
		Version:           1,
		EmitEventCategory: true,
		Categories:        map[string]*audit.CategoryDef{"write": {Events: []string{"ev1"}}},
		Events: map[string]*audit.EventDef{
			"ev1":         {Required: []string{"outcome"}},
			"uncat_event": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("uncat_event", audit.Fields{"outcome": "success"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, logger.Close())

	ev := out.GetEvent(0)
	_, hasCategory := ev["event_category"]
	assert.False(t, hasCategory, "uncategorised event should not have event_category")
}

func TestEventCategory_EmitFalse_NoField(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := audit.Taxonomy{
		Version:           1,
		EmitEventCategory: false,
		Categories:        map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{"outcome": "failure"}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, logger.Close())

	ev := out.GetEvent(0)
	_, hasCategory := ev["event_category"]
	assert.False(t, hasCategory, "emit_event_category:false should not add event_category")
}

func TestEventCategory_UserSupplied_Skipped(t *testing.T) {
	t.Parallel()

	out := testhelper.NewMockOutput("test")
	tax := audit.Taxonomy{
		Version:           1,
		EmitEventCategory: true,
		Categories:        map[string]*audit.CategoryDef{"security": {Events: []string{"auth_failure"}}},
		Events: map[string]*audit.EventDef{
			"auth_failure": {Required: []string{"outcome"}},
		},
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true, ValidationMode: "permissive"},
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)

	// User tries to set event_category — framework value should win.
	err = logger.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
		"outcome":        "failure",
		"event_category": "user_custom",
	}))
	require.NoError(t, err)
	require.True(t, out.WaitForEvents(1, 2*time.Second))
	require.NoError(t, logger.Close())

	ev := out.GetEvent(0)
	assert.Equal(t, "security", ev["event_category"], "framework category should override user-supplied")
}
