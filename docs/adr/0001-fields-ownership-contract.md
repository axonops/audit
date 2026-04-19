# ADR 0001: Fields Ownership Contract for Generated Builders

- **Status:** Accepted (2026-04-19)
- **Issue:** [#497](https://github.com/axonops/audit/issues/497)
- **Reviewers:** api-ergonomics-reviewer (APPROVED), performance-reviewer (APPROVED)
- **Supersedes:** —

## Context

The defensive `copyFieldsWithDefaults` helper in `audit.go` allocates a
fresh `Fields` map per `AuditEvent` call — necessary because the
caller's `map[string]any` may be mutated after the call returns and
the audit pipeline must see a stable snapshot. Each `any` value is
boxed to the heap. `BenchmarkAudit_RealisticFields` (10 fields)
landed at ~840 ns/op and 2 allocs/op on the bench-baseline refresh
under #493.

For Logger-style hot paths (10k events/s steady-state at 10 fields per
event = 100k heap boxings/s), the defensive copy is the dominant
per-event allocation cost. Generated builders from `cmd/audit-gen` do
not mutate or retain their `Fields` map after `AuditEvent` returns —
they construct a fresh map per call from typed setters and discard
their handle on return. The pipeline could safely take ownership of
that map and skip the copy, but only if there is a contract the
pipeline can detect at runtime that the value is donor-style.

This ADR records the contract shape chosen at v1.0 lock-in.

## Decision

Add an opt-in extension interface, `FieldsDonor`, that an `Event`
implementation MAY also satisfy. Detection is via runtime type
assertion. The interface uses an **unexported sentinel method**
(`donateFields()`) so that only the audit-gen toolchain can produce
implementations — third-party authors cannot opportunistically opt
into the fast path without going through the generator that
guarantees the no-mutate / no-retain contract.

```go
// FieldsDonor is an optional extension interface that the audit
// pipeline checks via type assertion in [Auditor.AuditEvent]. When an
// [Event] also implements FieldsDonor, the auditor takes ownership
// of the [Fields] map returned by Event.Fields() — no defensive copy.
//
// Implementers MUST NOT mutate or retain the returned Fields after
// Event.Fields() is called by the auditor; the auditor merges
// standard-field defaults INTO the returned map and the formatters
// then read from it across multiple outputs. Re-using the same Event
// instance for a second AuditEvent call is undefined behaviour.
//
// The unexported donateFields() sentinel prevents third-party
// implementation outside the audit-gen toolchain. Generated builders
// emit the sentinel; consumer-defined Event types and NewEvent both
// stay on the defensive-copy slow path.
type FieldsDonor interface {
    Event
    donateFields()
}
```

`NewEvent` and `NewEventKV` deliberately do NOT implement
`FieldsDonor`. Their callers commonly hand a literal `audit.Fields{...}`
constructed inline, sometimes a long-lived map; the safe default is
the existing copy-on-call behaviour.

## Alternatives Considered

### (a) `Event.OwnedFields() (Fields, bool)`

Add a method to the core `Event` interface returning the fields and a
bool signalling "may take ownership."

- ✗ Pollutes the core `Event` interface with a niche performance
  concern — every implementer must consider it.
- ✗ Unclear semantic when bool=false: does the caller mutate the
  returned map? (Forces a `Fields()` + `OwnedFields()` split.)
- ✗ Two-tuple return forces an extra allocation on the slow path.

### (b) Extension interface with sentinel — **CHOSEN**

See above. Matches `encoding/json.Marshaler`, `io.WriterTo`,
`http.Hijacker`, `slog.LogValuer`, `zap.ObjectMarshaler` — the
canonical Go pattern for "framework opportunistically takes a faster
path if the value implements X."

### (c) `Auditor.AuditOwnedEvent(OwnedEvent)`

Separate API method.

- ✗ Forks the public API surface — every consumer must know which to
  call. Bad TTHW; breaks progressive disclosure.
- ✗ Generated builders would need to emit code that knows to call the
  donor variant — leaking pipeline internals into the generator.
- ✗ No precedent in zap/zerolog/slog/encoding — all keep a single
  entry point.

## Consequences

### Positive

- Generated builders take a zero-extra-alloc fast path. Target:
  `BenchmarkAudit_GeneratedBuilder_FastPath` at ≤ 1 alloc/op (the
  pooled `auditEntry`) and ≤ 400 ns/op for a 10-field event.
- Public API surface unchanged for consumers — `AuditEvent(evt Event)`
  remains the entry point.
- Forward-compatible: additional opt-in extension interfaces (e.g.
  `OwnedTransport`, `OwnedAttachments`) can be added later using the
  same sentinel pattern with no API break.

### Negative

- One extra runtime type assertion per `AuditEvent` call. Cost is ~1
  ns; itab is cached. Measured by `BenchmarkAudit_Mixed_50_50` to
  catch any branch-predictor surprise under contention.
- Generated builders are now single-use by contract. Re-using a
  generated builder instance after `AuditEvent` will deliver stale
  defaults from the previous call (`mergeDefaultsInPlace` writes back
  into the donor's map). Documented loudly on `FieldsDonor` and
  enforced in `cmd/audit-gen/template.go` by nilling the builder's
  fields field after `AuditEvent` returns.
- `cmd/audit-gen` template adds the unexported sentinel method to
  every generated builder struct. Generated code is slightly larger.

### Neutral

- Behaviour for `NewEvent`, `NewEventKV`, and consumer-defined `Event`
  types is unchanged — they continue through `copyFieldsWithDefaults`.
  No migration required.
- Fan-out semantics unchanged. The donated map is shared across all
  output formatters (which read-only iterate it) — same as the
  defensive copy was previously.

## References

- Issue [#497](https://github.com/axonops/audit/issues/497) — full
  acceptance criteria + benchmark targets.
- Issue [#494](https://github.com/axonops/audit/issues/494) — same
  zero-alloc design pattern previously applied to the Loki batch-build
  hot path.
- `BENCHMARKS.md` — bench-baseline numbers used as the regression
  reference.
- Go standard library precedents: `encoding/json.Marshaler`,
  `io.WriterTo`, `net/http.Hijacker`, `slog.LogValuer`.

## Addendum (2026-04-19) — W2 zero-copy drain pipeline

The original ADR scope addressed only the defensive-copy bypass via
`FieldsDonor`. Performance review of the implementation surfaced three
additional drain-side allocations that were unrelated to the donor
mechanism but contributed equally to per-event GC pressure:

1. The formatter copy-out: `Format()` allocated a fresh `[]byte` to
   return because the format-cache entry had to outlive the leased
   buffer.
2. The post-field append: `event_category`, `_hmac_v`, `_hmac` each
   allocated a fresh `[]byte` because they had to mutate the cache
   value without aliasing it.
3. The sorted-keys slice in the formatter when `omitEmpty` or extra
   fields were present.

Three architecture-aware agent reviews (api-ergonomics, code-reviewer,
security-reviewer) ran in parallel and converged on the same shape:
extend the format cache to track buffer leases; share the leased
buffer across all outputs and category passes; introduce an unexported
`bufferedFormatter` extension interface so `*JSONFormatter` and
`*CEFFormatter` can return their leased buffer without leaking the
type into the public API; add an in-place `appendPostFieldJSONInto` /
`appendPostFieldCEFInto` that mutates a per-event scratch buffer;
pool the sorted-keys slice; release every lease in `processEntry`'s
defer chain after every output `Write` has returned.

Security review added five blocking requirements that landed in the
same change:

- Explicit `Output.Write` retention contract godoc: "The library MAY
  reuse data's underlying array after Write returns. Implementations
  MUST NOT retain data past the call." All first-party outputs already
  copy on enqueue, so the contract is observably honoured.
- Defensive `clear()` on every pool Put zeros the entire backing array.
- 64 KiB cap on pool Put — outlier buffers are dropped (let GC
  reclaim) to bound pool memory.
- HMAC ordering invariant comment in `drain.go` above the HMAC block,
  documenting that the buffer holding `data` MUST NOT be returned to
  any pool until `output.Write(data)` has returned.
- `formatWithExclusion` (per-output sensitivity-label stripping) stays
  on the public `Format` defensive-copy path. Folding per-output
  label-stripped output into a shared buffer would create an aliasing
  hazard.

The api-ergonomics-reviewer rejected an alternative typed-builder
buffer-accumulation design (zerolog-style pre-encoded JSON bytes)
because it would break format-neutrality (CEF cannot share a JSON
buffer), validation (`validateFields` needs the map), and per-output
sensitivity stripping. That work was scoped out into
[#660](https://github.com/axonops/audit/issues/660) for v1.1 with a
different shape — `BuiltEvent` extension interface returning typed
`[]Field` slices, matching the zap/slog pattern.

### Measured outcome

`BenchmarkAudit_FastPath_PipelineOnly` (donor outside loop, NoopOutput):
**0 allocs/op @ ~440 ns/op**.

`BenchmarkAudit_FastPath_FanOut4_NoopOutputs` (4 outputs sharing a
formatter): **0 allocs/op**.

`BenchmarkAudit_FastPath_WithHMAC_Noop` (single output, HMAC enabled):
**0 allocs/op**.

`BenchmarkAudit_RealisticFields` (slow path via NewEvent, 10 fields,
MockOutput): 2 → 1 alloc/op, 670 → 320 B/op.

`BenchmarkAudit_WithHMAC` (slow path, HMAC enabled, MockOutput):
2 → 1 alloc/op, 330 → 165 B/op.

The remaining alloc on the slow path is the documented
`copyFieldsWithDefaults` map clone — the contract `NewEvent` cannot
escape without becoming a footgun.

### Test coverage added

Per the test-analyst prescription on this expansion:

- `TestProcessEntry_RetainedBytes_NoForeignImpersonation` — proves a
  third-party output that violates the no-retention contract observes
  zeroed or fully-overwritten bytes, never silently-impersonated
  foreign-event hybrids.
- `TestProcessEntry_FanOutToMultipleOutputs_BytesIntegrity` — every
  event delivered to every output with the correct marker under
  `-race`.
- `TestProcessEntry_ConcurrentSubmission_NoRace` — 32 goroutines × 500
  events, NoopOutput, goleak-clean.
- `TestProcessEntry_MultiCategory_BufferReuseAcrossPasses` — JSON +
  CEF outputs receive byte-identical payloads across category passes
  except for the `event_category` / `cat` field.
- `TestProcessEntry_PanicMidDelivery_ReleaseStillRuns` — 100 events
  with a panicking output; the parallel good output receives all 100
  intact, proving the lease-release defer fires on every panic.
- `TestProcessEntry_FormatError_CacheNilEntry_NoDoublePut` — shared
  errorFormatter triggers `RecordSerializationError` exactly once
  across two outputs.
- `TestPutJSONBuf_OversizeBufferUntouched` /
  `TestPutJSONBuf_AcceptedBufferIsZeroed` — the 64 KiB cap branch and
  the defensive zero-on-Put branch.
- `TestAppendPostFieldJSONInto_PropertyEqualsAppendPostFields` /
  `TestAppendPostFieldCEFInto_…` — rapid property tests proving the
  in-place post-field path produces byte-identical output to the
  copy-out path across hundreds of randomly-generated inputs (JSON +
  CEF).

The existing BDD suite (`hmac_integrity.feature`,
`multi_output_fanout.feature`, `multi_category_events.feature`,
`loki_hmac.feature`, `sensitivity_labels.feature`) provides the
external contract that pins the wire-byte equivalence pre-/post-W2 —
no new BDD scenarios were added because the W2 change is a pure
internal optimisation with no consumer-visible behaviour change.

### Follow-up

[#660](https://github.com/axonops/audit/issues/660) — v1.1
`BuiltEvent` typed-field interface to eliminate the remaining
caller-side allocations (`Fields{}` literal + `any`-boxing).
