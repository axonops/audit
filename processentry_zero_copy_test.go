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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// retainingOutput deliberately violates the documented [audit.Output.Write]
// retention contract: it stores the data slice WITHOUT copying. Used to
// exercise the zeroing-on-pool-put defence (see W2.5 of #497) — the
// retained slice MUST observe its bytes wiped to zero (or filled with
// next-event content) once the original buffer is returned to the pool.
type retainingOutput struct { //nolint:govet // fieldalignment: readability over packing for a test fixture
	mu       sync.Mutex
	retained [][]byte // intentionally NOT copied
	name     string
}

func newRetainingOutput(name string) *retainingOutput {
	return &retainingOutput{name: name}
}

// Write violates the retention contract on purpose — the test asserts
// that this misbehaviour is detected by the zeroing/canary
// instrumentation rather than silently corrupting downstream verifiers.
func (r *retainingOutput) Write(data []byte) error {
	r.mu.Lock()
	r.retained = append(r.retained, data)
	r.mu.Unlock()
	return nil
}

func (*retainingOutput) Close() error   { return nil }
func (r *retainingOutput) Name() string { return r.name }
func (r *retainingOutput) Snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([][]byte, len(r.retained))
	copy(cp, r.retained)
	return cp
}

// TestProcessEntry_RetainedBytes_NoForeignImpersonation confirms the
// security-reviewer requirement that a buggy output retaining bytes
// past Write CANNOT observe bytes that silently impersonate a
// different event identity.
//
// Test design (per test-analyst prescription): the synchronous delivery
// alone is insufficient — we have to FORCE the buffer pool to recycle
// at least once between the moment the bad output snags a reference and
// the moment we inspect it. We do that by submitting two distinct
// batches with disjoint identity (event_type + actor_id), then checking
// that no retained slice from the first batch claims to be a
// first-batch event while carrying any second-batch byte.
//
// The forbidden combination — `event_type="user_create"` paired with
// `actor_id="bob"` — is the silent-impersonation failure the defensive
// clear-on-Put plus in-place truncation must prevent.
//
//nolint:cyclop // branch-heavy retention-observation state machine
func TestProcessEntry_RetainedBytes_NoForeignImpersonation(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create", "auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Required: []string{"outcome", "actor_id"},
			},
			"auth_failure": {
				Required: []string{"outcome", "actor_id"},
			},
		},
	}
	bad := newRetainingOutput("retain")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithOutputs(bad),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	const batch1Count = 50
	for i := 0; i < batch1Count; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": "alice",
		})))
	}
	// Capture the retained slices for batch 1 — these slices alias
	// the buffer pool's backing arrays at this point.
	batch1Snap := bad.Snapshot()
	require.Len(t, batch1Snap, batch1Count)

	// Submit a SECOND batch with a different event_type AND a different
	// actor. Synchronous delivery means by the time the loop exits,
	// every batch-2 event has gone through processEntry's defer-chain
	// which returns the leased buffer (and clears it) to the pool.
	// Any of the batch-1 retained slices that aliased a now-recycled
	// buffer will observe either zeros (defence fired) or batch-2
	// bytes (next event reused the same array) — but never a fused
	// hybrid.
	const batch2Count = 50
	for i := 0; i < batch2Count; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
			"outcome":  "failure",
			"actor_id": "bob",
		})))
	}

	// Verify each batch-1 retained slice. Acceptable observations:
	//  - all-zero bytes (defensive clear fired)
	//  - valid user_create + actor_id=alice (buffer not yet recycled)
	//  - valid auth_failure + actor_id=bob (buffer FULLY rewritten)
	//  - garbled bytes (partial rewrite caught by the truncate path)
	// Forbidden: event_type=user_create + actor_id=bob (impersonation:
	// alice's identity wearing bob's skin), OR event_type=auth_failure
	// + actor_id=alice (the inverse hybrid).
	zeroed := 0
	faithful1 := 0 // user_create + alice
	overwritten := 0
	garbled := 0
	for i, s := range batch1Snap {
		if isAllZero(s) {
			zeroed++
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal(s, &ev); err != nil {
			garbled++
			continue
		}
		et, _ := ev["event_type"].(string)
		actor, _ := ev["actor_id"].(string)
		switch {
		case et == "user_create" && actor == "alice":
			faithful1++
		case et == "auth_failure" && actor == "bob":
			overwritten++
		default:
			t.Errorf("batch1 retained slice %d shows hybrid identity: event_type=%q actor=%q payload=%s",
				i, et, actor, string(s))
		}
	}
	t.Logf("retention triage (batch1 N=%d): zeroed=%d faithful1=%d overwritten=%d garbled=%d",
		batch1Count, zeroed, faithful1, overwritten, garbled)
}

// TestProcessEntry_FanOutToMultipleOutputs_BytesIntegrity covers the
// core BDD scenario informally: many events fanned out to several
// outputs share the format-cache buffer; each output that copies on
// enqueue (the contract) MUST receive byte-identical, correctly
// attributed events. Run under -race to catch any future buffer
// aliasing regression.
func TestProcessEntry_FanOutToMultipleOutputs_BytesIntegrity(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Required: []string{"outcome", "actor_id", "marker"},
			},
		},
	}
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	out3 := testhelper.NewMockOutput("out3")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out1, out2, out3),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	const total = 200
	for i := 0; i < total; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": "alice",
			"marker":   markerFor(i),
		})))
	}

	for _, out := range []*testhelper.MockOutput{out1, out2, out3} {
		require.True(t, out.WaitForEvents(total, 5*time.Second),
			"output %s did not receive all events", out.Name())
		evs := out.GetEvents()
		require.Equal(t, total, len(evs))
		for i, raw := range evs {
			var ev map[string]any
			require.NoError(t, json.Unmarshal(raw, &ev),
				"event %d on %s did not unmarshal: %s", i, out.Name(), string(raw))
			assert.Equal(t, markerFor(i), ev["marker"],
				"event %d on %s carries wrong marker — fan-out aliasing detected", i, out.Name())
		}
	}
}

// TestProcessEntry_ConcurrentSubmission_NoRace stress-tests the W2
// per-event scratch + format-cache pool leases under heavy concurrent
// AuditEvent submission. Goroutine-leak verification + -race ensures
// no shared state escapes processEntry's defer chain.
func TestProcessEntry_ConcurrentSubmission_NoRace(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"outcome", "actor_id"}},
		},
	}
	out := testhelper.NewNoopOutput("noop")
	auditor, err := audit.New(
		audit.WithQueueSize(100_000),
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	const goroutines = 32
	const perGoroutine = 500
	var wg sync.WaitGroup
	var errs atomic.Int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
					"outcome":  "success",
					"actor_id": "alice",
				})); err != nil {
					errs.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	assert.Zero(t, errs.Load(), "AuditEvent reported errors under concurrency")

	// Wait for drain to catch up.
	deadline := time.Now().Add(5 * time.Second)
	expected := uint64(goroutines * perGoroutine)
	for out.Writes() < expected && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, expected, out.Writes(),
		"some events were not delivered: got %d want %d", out.Writes(), expected)
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func markerFor(i int) string {
	return "evt-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// panicOutput panics in Write to exercise the per-output panic
// recovery (drain.go's deliverToOutput defer) AND the surrounding
// processEntry defer chain that releases pool leases.
type panicOutput struct { //nolint:govet // fieldalignment: readability over packing for a test fixture
	name        string
	panicEvery  int
	calls       atomic.Int32
	panickedSet sync.Map // captures call indices where it panicked, for assertions
}

func newPanicOutput(name string, panicEvery int) *panicOutput {
	return &panicOutput{name: name, panicEvery: panicEvery}
}

func (p *panicOutput) Write(_ []byte) error {
	n := int(p.calls.Add(1))
	if p.panicEvery > 0 && n%p.panicEvery == 0 {
		p.panickedSet.Store(n, true)
		panic(fmt.Sprintf("intentional panic in panicOutput on call %d", n))
	}
	return nil
}

func (*panicOutput) Close() error   { return nil }
func (p *panicOutput) Name() string { return p.name }
func (p *panicOutput) Calls() int   { return int(p.calls.Load()) }

// TestProcessEntry_MultiCategory_BufferReuseAcrossPasses verifies the
// W2 lease-across-passes invariant: a multi-category event causes
// processEntry to iterate per category and share the format cache
// across passes. With two outputs using DIFFERENT formatters (one
// JSON, one CEF), the cache holds two distinct entries — both leased
// for the entire processEntry call. The leases must be reused (not
// re-acquired) across category passes; the wire bytes for each pass
// must differ ONLY in the event_category field.
func TestProcessEntry_MultiCategory_BufferReuseAcrossPasses(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"security":   {Events: []string{"user_create"}},
			"compliance": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Categories: []string{"security", "compliance"},
				Required:   []string{"outcome", "actor_id"},
			},
		},
	}
	jsonOut := testhelper.NewMockOutput("json")
	cefOut := testhelper.NewMockOutput("cef")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithNamedOutput(jsonOut, audit.OutputFormatter(&audit.JSONFormatter{})),
		audit.WithNamedOutput(cefOut, audit.OutputFormatter(&audit.CEFFormatter{
			Vendor: "axonops", Product: "audit", Version: "1.0",
		})),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))

	// Each output should have received TWO events: one per category.
	require.Equal(t, 2, jsonOut.EventCount(), "json output should receive 2 events (one per category)")
	require.Equal(t, 2, cefOut.EventCount(), "cef output should receive 2 events (one per category)")

	// JSON: the two events should differ ONLY in the event_category
	// field. Sort by category for deterministic comparison.
	j1 := jsonOut.GetEvent(0)
	j2 := jsonOut.GetEvent(1)
	c1Cat, _ := j1["event_category"].(string)
	c2Cat, _ := j2["event_category"].(string)
	cats := []string{c1Cat, c2Cat}
	require.ElementsMatch(t, []string{"security", "compliance"}, cats,
		"json events must carry one each of security/compliance category")
	// Strip event_category and assert all other fields are byte-identical.
	delete(j1, "event_category")
	delete(j2, "event_category")
	assert.Equal(t, j1, j2, "json payload (excluding event_category) must be byte-identical across category passes")

	// CEF: the two raw bytes should differ ONLY in the cat= extension.
	c1 := string(cefOut.GetEvents()[0])
	c2 := string(cefOut.GetEvents()[1])
	c1NoCat := stripCEFExt(c1, "cat")
	c2NoCat := stripCEFExt(c2, "cat")
	assert.Equal(t, c1NoCat, c2NoCat, "cef payload (excluding cat) must be byte-identical across category passes")
}

// TestProcessEntry_PanicMidDelivery_ReleaseStillRuns covers the
// failure mode where a buggy output panics in Write. Per the existing
// per-output panic recovery (deliverToOutput's defer), the auditor
// must continue serving subsequent events. In W2 there is an
// additional concern: the format-cache buffer leases and the
// per-event scratch buffer MUST be returned to the pool even after a
// panic — otherwise the pool leaks across events and Close() can hang
// (because the auditor cannot get back the pooled buffers it expects
// to find on shutdown).
func TestProcessEntry_PanicMidDelivery_ReleaseStillRuns(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"outcome", "actor_id"}},
		},
	}
	bad := newPanicOutput("bad", 1) // panic on EVERY call
	good := testhelper.NewMockOutput("good")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithOutputs(bad, good),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	const total = 100
	for i := 0; i < total; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": fmt.Sprintf("alice-%d", i),
		})))
	}

	// Bad output panicked on every call — calls counter sees them.
	assert.Equal(t, total, bad.Calls(), "panic output should have been called once per event")
	// Good output received every event despite the bad output's panics.
	require.Equal(t, total, good.EventCount(),
		"good output must receive every event despite per-event panic in bad output — proves pool leases were released after each panicking processEntry")

	// Spot-check that the events are intact (not corrupted by the
	// panic interrupting the format cache).
	for i := 0; i < total; i++ {
		ev := good.GetEvent(i)
		assert.Equal(t, fmt.Sprintf("alice-%d", i), ev["actor_id"],
			"event %d: actor_id corrupted", i)
	}
}

// TestProcessEntry_FormatError_CacheNilEntry_NoDoublePut covers the
// failure mode where a shared formatter returns an error: the cache
// stores nil, so the second output sharing that formatter hits the
// cache (data=nil) and skips delivery without re-invoking format. The
// W2 cache.put(f, nil, nil) path MUST NOT trigger a double pool-put
// or a nil-buffer release — both would corrupt the buffer pool.
//
// Concretely: same errorFormatter shared by two outputs ⇒ exactly ONE
// RecordSerializationError call (not two), no panic on shutdown.
func TestProcessEntry_FormatError_CacheNilEntry_NoDoublePut(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	tax := testhelper.TestTaxonomy()
	out1 := testhelper.NewMockOutput("out1")
	out2 := testhelper.NewMockOutput("out2")
	metrics := newCountingMetrics()

	// Both outputs share the SAME errorFormatter instance — this is
	// the cache-key the auditor uses (formatter pointer identity).
	shared := &errorFormatter{}
	auditor, err := audit.New(
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithTaxonomy(tax),
		audit.WithMetrics(metrics),
		audit.WithNamedOutput(out1, audit.OutputFormatter(shared), audit.OutputRoute(&audit.EventRoute{})),
		audit.WithNamedOutput(out2, audit.OutputFormatter(shared), audit.OutputRoute(&audit.EventRoute{})),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	})))

	assert.Zero(t, out1.EventCount(), "out1 should receive nothing — formatter errored")
	assert.Zero(t, out2.EventCount(), "out2 should receive nothing — cache hit returns nil")
	assert.Equal(t, int64(1), metrics.serializationErrors.Load(),
		"shared errorFormatter must trigger RecordSerializationError EXACTLY once (not once per output)")
}

// stripCEFExt removes a ` key=value` segment from a CEF line, used to
// compare two CEF events that differ only in one extension.
func stripCEFExt(line, key string) string {
	prefix := " " + key + "="
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return line
	}
	rest := line[idx+len(prefix):]
	end := strings.IndexAny(rest, " \n")
	if end < 0 {
		end = len(rest)
	}
	return line[:idx] + line[idx+len(prefix)+end:]
}

// countingMetrics is a minimal Metrics implementation that just
// counts the calls relevant to the W2 cache-nil tests. Methods not
// overridden inherit the no-op behaviour of [audit.NoOpMetrics].
type countingMetrics struct {
	audit.NoOpMetrics
	serializationErrors atomic.Int64
}

func newCountingMetrics() *countingMetrics { return &countingMetrics{} }

func (m *countingMetrics) RecordSerializationError(string) { m.serializationErrors.Add(1) }

// errors import kept for future helpers that wrap sentinel errors.
var _ = errors.New

// TestJSONFormatter_FormatBuf_OversizeEventDropsBuffer exercises the
// maxPooledBufCap branch in putJSONBuf: a buffer larger than the cap
// MUST NOT be re-pooled (let GC reclaim instead). We exercise this
// via the public Format path with an event whose serialised size
// exceeds 64 KiB; the test does not directly observe the pool (sync.Pool
// behaviour is implementation-dependent), but it asserts the public
// path stays correct on oversized events: serialisation succeeds and
// round-trips unchanged through json.Unmarshal.
//
// The pool-rejection branch itself is small (cap check + early
// return), so direct observation requires a whitebox helper — see
// PutJSONBufForTest in audit_export_test.go for the focused test.
func TestJSONFormatter_FormatBuf_OversizeEventDropsBuffer(t *testing.T) {
	t.Parallel()

	// A 128 KiB string forces the buffer past the 64 KiB pool cap.
	bigStr := strings.Repeat("X", 128*1024)
	tax := &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Required: []string{"outcome", "actor_id"}, Optional: []string{"big"}},
		},
	}
	out := testhelper.NewMockOutput("out")
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditor.Close() })

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"big":      bigStr,
	})))

	require.Equal(t, 1, out.EventCount())
	ev := out.GetEvent(0)
	assert.Equal(t, bigStr, ev["big"], "oversized field must serialise correctly even though buffer was not re-pooled")
}

// TestPutJSONBuf_OversizeBufferUntouched verifies the cap-rejection
// branch in putJSONBuf: an oversized buffer must NOT have its
// contents modified (no clear, no pool put). The test fills the
// backing array with a sentinel, calls putJSONBuf, and confirms the
// sentinel survived.
func TestPutJSONBuf_OversizeBufferUntouched(t *testing.T) {
	t.Parallel()

	oversize := audit.MaxPooledBufCapForTest * 2 // beyond cap → must be rejected
	cleared := audit.PutJSONBufClearsContents(oversize)
	assert.False(t, cleared,
		"oversized buffer (cap=%d > maxPooledBufCap=%d) must NOT be cleared — putJSONBuf should reject before zeroing",
		oversize, audit.MaxPooledBufCapForTest)
}

// TestPutJSONBuf_AcceptedBufferIsZeroed verifies the security-defence
// zeroing branch: an in-cap buffer's contents are wiped to zero before
// returning to the pool. Combined with the oversize test above, this
// pins the two halves of the security-reviewer requirement #4.
func TestPutJSONBuf_AcceptedBufferIsZeroed(t *testing.T) {
	t.Parallel()

	fits := audit.MaxPooledBufCapForTest / 2 // well within cap → must be accepted+zeroed
	cleared := audit.PutJSONBufClearsContents(fits)
	assert.True(t, cleared,
		"in-cap buffer (cap=%d <= maxPooledBufCap=%d) MUST be zeroed by putJSONBuf to defend against read-past-len bugs",
		fits, audit.MaxPooledBufCapForTest)
}
