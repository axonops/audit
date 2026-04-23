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

// Side-by-side benchmarks that compare this library's Audit path
// against [log/slog] with a JSON handler (#512). Developers
// evaluating the library will naturally ask "why not just use
// slog?" — these benchmarks provide the honest numeric answer, and
// BENCHMARKS.md explains what the delta buys (taxonomy validation,
// framework fields, fan-out, HMAC, sensitivity stripping,
// config-driven outputs).
//
// Fair-comparison rules (reviewer prescription, #512 post-code
// review):
//
//   - **Synchronous delivery on both sides.** slog's
//     slog.Logger.Info is synchronous: it serialises + writes
//     inline. The audit library defaults to async delivery (drain
//     goroutine), which means the default BenchmarkAudit charges
//     only caller-side enqueue cost and hides serialisation on a
//     different goroutine. For an apples-to-apples comparison, the
//     audit sub-benchmarks use [audit.WithSynchronousDelivery] so
//     the full serialise → fan-out → post-field → HMAC → Write
//     path is on the benchmark's critical path, exactly like slog.
//
//   - **Zero drops.** The async default silently drops events when
//     the queue fills — which happens in any benchmark that calls
//     AuditEvent tighter than the drain can process. Synchronous
//     delivery eliminates this by construction, and every audit
//     sub-benchmark asserts that every output's write count equals
//     b.N at b.StopTimer so a future change cannot regress the
//     benchmark back into silent-drop territory.
//
//   - **Matched sinks.** slog writes to [io.Discard]; the audit
//     library writes to [testhelper.NoopOutput] — both are true
//     zero-cost sinks. NoopOutput atomic-increments a counter and
//     does not copy or inspect bytes; io.Discard discards every
//     write with no allocation. The output backend is excluded
//     on both sides; the benchmark measures the library's pipeline.
//
//   - **Matched payloads.** 3-field and 10-field variants mirror
//     the BenchmarkAudit / BenchmarkAudit_RealisticFields payloads
//     so ns/op is interpretable against the rest of BENCHMARKS.md.
//     Only the audit dynamic slow path ([audit.NewEvent]) is
//     represented. The cmd/audit-gen-generated fast path
//     ([audit.FieldsDonor]-satisfying typed builders) is
//     intentionally NOT benchmarked here — a pure-test shim would
//     allocate a wrapper per iteration and misrepresent the
//     stack-allocated generated builder. Fast-path numbers live
//     in the BenchmarkAudit_FastPath_* family (audit_test.go).
//
//   - **slog's fast path is included.** slog.Logger.Info with
//     positional args forces Attr pairing via variadic; slog.LogAttrs
//     with a pre-constructed []slog.Attr is the documented fast
//     path. Both are benchmarked so the reader sees slog's best
//     number, not a strawman.

package audit_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/require"
)

// benchComparisonTaxonomy defines the two event shapes used
// across every sub-benchmark: a 3-field "schema_register" and a
// 10-field "api_request". Mirrors BenchmarkAudit and
// BenchmarkAudit_RealisticFields.
func benchComparisonTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"schema_register", "api_request"}},
		},
		Events: map[string]*audit.EventDef{
			"schema_register": {
				Required: []string{"outcome", "actor_id", "subject"},
			},
			"api_request": {
				Required: []string{"outcome", "actor_id", "method", "path"},
				// source_ip, request_id, user_agent are reserved standard
				// fields — always available without being listed here.
				Optional: []string{"subject", "schema_type", "version"},
			},
		},
	}
}

// benchComparison10Fields returns the canonical 10-field payload
// used by every 10-field comparison sub-benchmark. Kept in one
// place so edits to the payload shape cannot drift between
// benchmarks.
func benchComparison10Fields() audit.Fields {
	return audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"method":      "POST",
		"path":        "/api/v1/schemas",
		"source_ip":   "10.0.0.1",
		"request_id":  "550e8400-e29b-41d4-a716-446655440000",
		"user_agent":  "audit-client/1.0",
		"subject":     "my-topic",
		"schema_type": "avro",
		"version":     1,
	}
}

// BenchmarkSlog_JSONHandler_BaselineComparison runs slog and the
// audit library side-by-side under matched conditions. Report the
// sub-benchmarks as a group in BENCHMARKS.md so readers see both
// numbers in one place. All audit sub-benchmarks use
// [audit.WithSynchronousDelivery] so the full pipeline is on the
// benchmark's critical path.
//
// Note on audit fast path: consumers using cmd/audit-gen-generated
// typed builders get a stack-allocated event whose Fields map
// population avoids the `audit.Fields{...}` literal allocation
// measured here. Representing that in a benchmark requires
// generated code — a pure-test shim (NewFieldsDonorForTest)
// cannot, because the shim itself allocates. Benchmarks for
// audit-gen output live in the example / capstone test suites.
// The numbers in this file are the dynamic slow path; the
// fast-path win is an additional reduction on top.
func BenchmarkSlog_JSONHandler_BaselineComparison(b *testing.B) {
	b.Run("slog/3fields", benchSlog3Fields)
	b.Run("audit/3fields_sync", benchAudit3FieldsSync)
	b.Run("slog/10fields", benchSlog10Fields)
	b.Run("slog/10fields_LogAttrs", benchSlog10FieldsLogAttrs)
	b.Run("audit/10fields_sync", benchAudit10FieldsSync)
	b.Run("audit/10fields_sync_WithHMAC", benchAudit10FieldsSyncWithHMAC)
	b.Run("audit/10fields_sync_FanOut4", benchAudit10FieldsSyncFanOut4)
}

// benchSlog3Fields: slog with a JSON handler, discard sink,
// 3 fields. Uses the positional-arg form (logger.Info), matching
// the ergonomic default most consumers reach for first.
func benchSlog3Fields(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	b.ReportAllocs()
	for b.Loop() {
		logger.Info("schema_register",
			"outcome", "success",
			"actor_id", "alice",
			"subject", "my-topic",
		)
	}
}

// benchAudit3FieldsSync: same 3-field payload through the audit
// library with WithSynchronousDelivery so the pipeline runs on
// the caller goroutine — fair vs slog's synchronous handler.
// Asserts all events were written (no silent drops) at b.StopTimer.
func benchAudit3FieldsSync(b *testing.B) {
	// silenceSlog muffles slog.Default used by the library's
	// construction-time diagnostics; the locally-constructed
	// slog.Logger in the slog benchmarks is unaffected.
	silenceSlog(b)
	out := testhelper.NewNoopOutput("bench-cmp")
	auditor, err := audit.New(
		audit.WithTaxonomy(benchComparisonTaxonomy()),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditor.Close() })

	fields := audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}

	var n uint64
	b.ReportAllocs()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("schema_register", fields))
		n++
	}
	b.StopTimer()
	require.Equal(b, n, out.Writes(), "audit dropped events; benchmark ns/op is invalid")
}

// benchSlog10Fields: slog with a 10-field payload via the
// positional-arg form (logger.Info). 10 attrs exceeds slog's
// inline Attr array (nAttrsInline = 5) and forces a heap spill
// — see BENCHMARKS.md for the 208 B/op explanation.
func benchSlog10Fields(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	b.ReportAllocs()
	for b.Loop() {
		logger.Info("api_request",
			"outcome", "success",
			"actor_id", "alice",
			"method", "POST",
			"path", "/api/v1/schemas",
			"source_ip", "10.0.0.1",
			"request_id", "550e8400-e29b-41d4-a716-446655440000",
			"user_agent", "audit-client/1.0",
			"subject", "my-topic",
			"schema_type", "avro",
			"version", 1,
		)
	}
}

// benchSlog10FieldsLogAttrs: slog's documented fast path — the
// caller pre-constructs a []slog.Attr so the handler avoids the
// variadic Attr-pairing cost. Published alongside benchSlog10Fields
// so the comparison includes slog's best number, not only its
// ergonomic default.
func benchSlog10FieldsLogAttrs(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx := b.Context()

	attrs := []slog.Attr{
		slog.String("outcome", "success"),
		slog.String("actor_id", "alice"),
		slog.String("method", "POST"),
		slog.String("path", "/api/v1/schemas"),
		slog.String("source_ip", "10.0.0.1"),
		slog.String("request_id", "550e8400-e29b-41d4-a716-446655440000"),
		slog.String("user_agent", "audit-client/1.0"),
		slog.String("subject", "my-topic"),
		slog.String("schema_type", "avro"),
		slog.Int("version", 1),
	}

	b.ReportAllocs()
	for b.Loop() {
		logger.LogAttrs(ctx, slog.LevelInfo, "api_request", attrs...)
	}
}

// benchAudit10FieldsSync: 10-field payload through the audit
// library slow path (audit.NewEvent). Synchronous delivery so
// the caller pays the full serialise + validate + Write cost
// inline, matching slog's dispatch model. Asserts every event
// was written at b.StopTimer.
func benchAudit10FieldsSync(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewNoopOutput("bench-cmp")
	auditor, err := audit.New(
		audit.WithTaxonomy(benchComparisonTaxonomy()),
		audit.WithOutputs(out),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditor.Close() })

	fields := benchComparison10Fields()

	var n uint64
	b.ReportAllocs()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("api_request", fields))
		n++
	}
	b.StopTimer()
	require.Equal(b, n, out.Writes(), "audit dropped events; benchmark ns/op is invalid")
}

// benchAudit10FieldsSyncWithHMAC: 10-field payload with HMAC
// tamper-evidence enabled. slog has no equivalent; this
// sub-benchmark quantifies the marginal cost of tamper-evident
// logging, not a direct slog comparison. Synchronous so HMAC
// compute runs on the caller goroutine.
func benchAudit10FieldsSyncWithHMAC(b *testing.B) {
	silenceSlog(b)
	out := testhelper.NewNoopOutput("bench-cmp-hmac")
	hmacCfg := &audit.HMACConfig{
		Enabled: true,
		Salt: audit.HMACSalt{
			Version: "v1",
			Value:   []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		},
		Algorithm: "HMAC-SHA-256",
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(benchComparisonTaxonomy()),
		audit.WithNamedOutput(out, audit.WithHMAC(hmacCfg)),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditor.Close() })

	fields := benchComparison10Fields()

	var n uint64
	b.ReportAllocs()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("api_request", fields))
		n++
	}
	b.StopTimer()
	require.Equal(b, n, out.Writes(), "audit dropped events; benchmark ns/op is invalid")
}

// benchAudit10FieldsSyncFanOut4: 10-field payload fanned out to
// four NoopOutputs sharing one formatter. slog has no native
// fan-out; the marginal per-output cost is what this measures.
// Synchronous delivery so fan-out runs on the caller goroutine.
// Asserts every output received every event.
func benchAudit10FieldsSyncFanOut4(b *testing.B) {
	silenceSlog(b)
	out1 := testhelper.NewNoopOutput("cmp-1")
	out2 := testhelper.NewNoopOutput("cmp-2")
	out3 := testhelper.NewNoopOutput("cmp-3")
	out4 := testhelper.NewNoopOutput("cmp-4")
	auditor, err := audit.New(
		audit.WithTaxonomy(benchComparisonTaxonomy()),
		audit.WithOutputs(out1, out2, out3, out4),
		audit.WithSynchronousDelivery(),
	)
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditor.Close() })

	fields := benchComparison10Fields()

	var n uint64
	b.ReportAllocs()
	for b.Loop() {
		_ = auditor.AuditEvent(audit.NewEvent("api_request", fields))
		n++
	}
	b.StopTimer()
	for _, out := range []*testhelper.NoopOutput{out1, out2, out3, out4} {
		require.Equal(b, n, out.Writes(),
			"audit fan-out dropped events on %q; benchmark ns/op is invalid", out.Name())
	}
}
