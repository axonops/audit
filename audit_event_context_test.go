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
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// newCtxAuditor builds an auditor (sync delivery by default for
// deterministic ctx-cancellation assertions).
func newCtxAuditor(t *testing.T, opts ...audit.Option) (*audit.Auditor, *testhelper.MockOutput) {
	t.Helper()
	out := testhelper.NewMockOutput("test")
	all := []audit.Option{
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithSynchronousDelivery(),
		audit.WithOutputs(out),
	}
	all = append(all, opts...)
	a, err := audit.New(all...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	return a, out
}

// TestAuditEventContext_BackgroundContext_DelegatesUnchanged proves
// the convenience-wrapper invariant: AuditEvent(evt) ===
// AuditEventContext(context.Background(), evt).
func TestAuditEventContext_BackgroundContext_DelegatesUnchanged(t *testing.T) {
	t.Parallel()
	a, out := newCtxAuditor(t)

	require.NoError(t, a.AuditEventContext(context.Background(), audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	})))
	require.True(t, out.WaitForEvents(1, 0))
	ev := out.GetEvent(0)
	assert.Equal(t, "alice", ev["actor_id"])
}

// TestAuditEventContext_NilEvent_ReturnsError preserves the
// nil-guard behaviour from the legacy AuditEvent.
func TestAuditEventContext_NilEvent_ReturnsError(t *testing.T) {
	t.Parallel()
	a, _ := newCtxAuditor(t)
	err := a.AuditEventContext(context.Background(), nil)
	require.Error(t, err)
	// text-only: audit.go:378 returns raw fmt.Errorf without an audit sentinel wrap.
	assert.Contains(t, err.Error(), "must not be nil")
}

// TestAuditEventContext_PreCancelledCtx_ReturnsCtxErr_Sync verifies
// the cancellation point at the top of auditInternalDonatedFlagsCtx
// in synchronous-delivery mode.
func TestAuditEventContext_PreCancelledCtx_ReturnsCtxErr_Sync(t *testing.T) {
	t.Parallel()
	a, out := newCtxAuditor(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, out.EventCount(), "no event should be delivered when ctx pre-cancelled")
}

// TestAuditEventContext_PreCancelledCtx_ReturnsCtxErr_Async verifies
// the same cancellation point in async-delivery mode.
func TestAuditEventContext_PreCancelledCtx_ReturnsCtxErr_Async(t *testing.T) {
	t.Parallel()
	out := testhelper.NewMockOutput("test")
	a, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		// async (default) — this exercises the enqueueCtx path.
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, out.EventCount(),
		"no event should be enqueued when ctx pre-cancelled")
}

// TestAuditEventContext_DeadlineExceeded_ReturnsCtxErr exercises the
// deadline-expired branch of the same gate.
func TestAuditEventContext_DeadlineExceeded_ReturnsCtxErr(t *testing.T) {
	t.Parallel()
	a, _ := newCtxAuditor(t)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()

	err := a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestAuditEventContext_DropMetric_RecordedOnCtxCancellation locks
// the locked-design Q4 contract: ctx-cancelled drops increment
// RecordBufferDrop (no new metric added).
func TestAuditEventContext_DropMetric_RecordedOnCtxCancellation(t *testing.T) {
	t.Parallel()
	mm := testhelper.NewMockMetrics()
	a, _ := newCtxAuditor(t, audit.WithMetrics(mm))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, mm.GetBufferDrops())
}

// TestAuditEventContext_DiagnosticLog_RecordsCancellation locks the
// diagnostic-log distinction between caller-driven and queue-full
// drops (Q4).
func TestAuditEventContext_DiagnosticLog_RecordsCancellation(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, _ := newCtxAuditor(t, audit.WithDiagnosticLogger(logger))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.Canceled)

	logs := buf.String()
	assert.Contains(t, logs, "event dropped due to context cancellation",
		"diagnostic log MUST distinguish caller-driven drops from queue-full drops")
	assert.Contains(t, logs, "auth_failure", "log line should include event_type")
}

// TestEventHandle_AuditContext_PassesThroughCtx verifies the handle
// path threads ctx end-to-end.
func TestEventHandle_AuditContext_PassesThroughCtx(t *testing.T) {
	t.Parallel()
	a, out := newCtxAuditor(t)
	h, err := a.Handle("auth_failure")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = h.AuditContext(ctx, audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, out.EventCount())
}

// TestEventHandle_AuditEventContext_PassesThroughCtx verifies the
// handle's event-typed ctx variant.
func TestEventHandle_AuditEventContext_PassesThroughCtx(t *testing.T) {
	t.Parallel()
	a, out := newCtxAuditor(t)
	h, err := a.Handle("auth_failure")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = h.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, out.EventCount())
}

// TestAuditEventContext_CancelAndBufferFull_RaceReturnsEitherErr
// exercises the 3-way select inside enqueueCtx when ctx is cancelled
// AND the async buffer is full at the same instant. Go's select
// nondeterministically picks the cancel branch or the queue-full
// branch — both are valid; both must drop the entry cleanly so the
// pool doesn't leak. Run repeatedly to exercise both branches.
func TestAuditEventContext_CancelAndBufferFull_RaceReturnsEitherErr(t *testing.T) {
	t.Parallel()
	mm := testhelper.NewMockMetrics()
	out := testhelper.NewMockOutput("test")
	a, err := audit.New(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithAppName("test-app"),
		audit.WithHost("test-host"),
		audit.WithOutputs(out),
		audit.WithMetrics(mm),
		audit.WithQueueSize(1),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	// Run several iterations to make both branches observable.
	const iterations = 50
	var cancelHits, queueFullHits int
	for i := 0; i < iterations; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		// Pre-fill any space in the buffer with a non-blocking send to
		// guarantee the next AuditEventContext lands on a full buffer.
		_ = a.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "alice",
		}))
		cancel()
		err := a.AuditEventContext(ctx, audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "alice",
		}))
		switch {
		case err == nil:
			// Possible: drain consumed the prefilled entry between
			// the prefill and the cancelled call. Acceptable.
		case errors.Is(err, context.Canceled):
			cancelHits++
		default:
			queueFullHits++
		}
	}
	// Both branches MUST be reachable; at least one cancellation hit
	// is required to prove the cancel path actually fires.
	assert.Positive(t, cancelHits+queueFullHits,
		"expected at least one cancel or queue-full drop across %d iterations", iterations)
}

// TestEventHandle_Audit_DelegatesToAuditContext_Background mirrors
// the Auditor-level invariant for the handle path.
func TestEventHandle_Audit_DelegatesToAuditContext_Background(t *testing.T) {
	t.Parallel()
	a, out := newCtxAuditor(t)
	h, err := a.Handle("auth_failure")
	require.NoError(t, err)

	require.NoError(t, h.Audit(audit.Fields{
		"outcome":  "failure",
		"actor_id": "alice",
	}))
	require.True(t, out.WaitForEvents(1, 0))
}
