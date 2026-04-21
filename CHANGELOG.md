# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking Changes

- `New` signature changed from `New(Config, ...Option)` to `New(...Option)` — Config fields expressed as Options (#388)
- `Config.Version` unexported, `Config.Enabled` removed — use `WithDisabled()` (#388)
- `Fields` changed from type alias to defined type `type Fields map[string]any` with `Has()`, `String()`, `Int()` methods (#388)
- `EmitEventCategory` renamed to `SuppressEventCategory` (inverted semantics) (#388)
- `ParseTaxonomyYAML` returns `*Taxonomy` instead of `Taxonomy` (#389)
- `WithTaxonomy` accepts `*Taxonomy` with deep copy and mutation protection (#389)
- `outputconfig.Load` signature changed — `coreMetrics` moved to `WithCoreMetrics` LoadOption (#390)
- `WithStandardFieldDefaults` guard relaxed from error-on-second-call to last-wins (#390)
- `WithNamedOutput` replaced positional params with `...OutputOption` (#391)
- `WithOutputHMAC` removed — use `OutputHMAC` within `WithNamedOutput` (#391)
- `EventType` renamed to `EventHandle`, `Name()` renamed to `EventType()` (#402)
- Module renamed from `github.com/axonops/go-audit` to `github.com/axonops/audit` (#398)
- `audit-gen` generates typed parameters (string/int) instead of `any` for standard field setters and constructors (#394)
- HMAC wire-format: `_hmac_v` now appears BEFORE `_hmac` on the wire and is inside the HMAC-authenticated bytes. External verifiers must strip only the `_hmac` field from the received line (keeping `_hmac_v` in place) to recompute the HMAC. See [`docs/hmac-integrity.md`](docs/hmac-integrity.md#canonicalisation-rule-for-verifiers) for the full canonicalisation contract (#473)
- HMAC `SaltVersion` character set restricted to `[A-Za-z0-9._:-]` (length 1–64) at config-time validation — values containing spaces, control characters, CEF/JSON metacharacters, or other ambiguous bytes are rejected (#473)
- `OutputFactory` signature grew a `*slog.Logger` parameter: `func(name string, rawConfig []byte, coreMetrics Metrics, logger *slog.Logger) (Output, error)`. Custom factories must add the parameter (nil is valid; treated as `slog.Default`). The logger is plumbed from `outputconfig.WithDiagnosticLogger` / `audit.WithDiagnosticLogger` so construction-time warnings reach the consumer's handler (#490)
- Root-level `tls_policy:` removed from `outputconfig` YAML schema. TLS policy is now configured per-output (under `syslog:`, `webhook:`, `loki:`) and per-provider (under `vault:`, `openbao:`). Consumers with `tls_policy:` at the root get an explicit "unknown top-level key" error at startup and must move the block into each affected output/provider. Rationale: the previous inheritance model created a privilege-escalation surface where a permissive policy set for a legacy syslog target would silently downgrade the TLS posture of secret-provider connections that carry bootstrap credentials. See [`examples/15-tls-policy/outputs.yaml`](examples/15-tls-policy/outputs.yaml) and [`docs/output-configuration.md` — Per-Output TLS Policy](docs/output-configuration.md#-per-output-tls-policy) for the new form (#476, #632)

### Performance

- Batched syslog writes — `syslog.Config` adds `BatchSize` (default 100), `FlushInterval` (default 5 s), and `MaxBatchBytes` (default 1 MiB) fields, matching the conventions already established by `loki.Config` and `webhook.Config`. The `writeLoop` accumulates events and flushes on count threshold, byte threshold, timer timeout, or Close — instead of writing one event per srslog call. RFC 5425 octet-counting framing is preserved per message (each event remains an independently framed syslog message within a batch). Oversized single events flush alone — never dropped. YAML keys: `batch_size`, `flush_interval`, `max_batch_bytes`. **Behaviour change for existing consumers**: events may now wait up to `FlushInterval` (5 s default) before reaching the syslog server. Consumers needing synchronous per-event delivery should set `BatchSize: 1` or a small `FlushInterval` (e.g. `10ms`). Close still drains any pending batch before returning, bounded by the existing 10 s shutdown timeout. Follow-up issues filed: #687 (webhook `MaxBatchBytes` for cross-output consistency), #688 (per-event `MaxEventBytes` bound to defend against consumer-controlled memory pressure). (#599)
- Eliminate per-field allocations in the CEF formatter (#496). Primitive field values (`string`, `bool`, all int/uint widths, `float64`, `float32`, `time.Time`, `time.Duration`) now format directly into the pool-leased buffer via `strconv.Append*` into a 32-byte stack scratch, bypassing the `strconv.Format* → string → cefEscapeExtValue → string → WriteString` double-copy pattern. String values route through a new in-place `writeEscapedExtValueString` that performs CEF escaping while writing, without allocating an intermediate escaped string. Non-primitive fallback (the `default` branch for slices/maps/structs via `fmt.Sprintf("%v", val)`) is preserved unchanged — byte-for-byte output compatibility. `buf.Grow(768)` preflight added to `CEFFormatter.formatBuf` to amortise cold-pool growth across a realistic 20-field event. Result: `BenchmarkCEFFormatter_Format_LargeEvent` drops from 3 → 1 allocs/op (1196 → 1170 ns/op, 584 → 577 B/op); `BenchmarkCEFFormatter_Format` unchanged at 1 alloc/op. New benchmarks `BenchmarkCEFFormatter_Format_LargeEvent_Escaping` (metacharacter-heavy), `_Numeric` (10 numeric fields), and `_Parallel` (GOMAXPROCS) added for regression coverage. Byte-equivalence with the legacy path proven by rapid property tests (`TestWriteEscapedExtValueString_PropertyEqualsCEFEscape` — raw byte strings including invalid UTF-8 + adversarial seeds; `TestAppendFormatFieldValue_ByteEquivalentToLegacy` — table-driven across every supported primitive type).
- Eliminate per-event allocations in the drain pipeline via two coordinated changes shipped together (#497):
  - **`FieldsDonor` extension interface** — generated builders from `cmd/audit-gen` opt into a defensive-copy bypass via the unexported `donateFields()` sentinel method. The auditor takes ownership of the donor's `Fields` map (no per-event map clone), eliminating the dominant allocation on the slow path. `NewEvent` and consumer-defined `Event` types stay on the original defensive-copy path. Contract documented in [`docs/adr/0001-fields-ownership-contract.md`](docs/adr/0001-fields-ownership-contract.md).
  - **W2 zero-copy drain** — the formatter buffer leased from `jsonBufPool` / `cefBufPool` is now retained for the lifetime of `processEntry` (one event) and shared across every output and category pass. Per-output post-field assembly (`event_category`, `_hmac_v`, `_hmac`) writes into a pooled scratch buffer in place of the previous `make([]byte, n)` per-field copy. Sorted field-key slices are pooled. `Output.Write` godoc tightened: implementations MUST NOT retain `data` past the call (all first-party outputs already copy on enqueue). Pool returns enforce a 64 KiB capacity cap to bound memory under outlier events, and `clear()` the backing array as defence-in-depth against future read-past-len bugs.
  - Result: `BenchmarkAudit_RealisticFields` (10 fields, slow path) drops from 2 → 1 allocs/op and 670 → 320 B/op. `BenchmarkAudit_WithHMAC` drops from 2 → 1 allocs/op and 330 → 165 B/op (50 % reduction). Fan-out byte allocations halved across every variant. The donor fast path hits 0 allocs/op on the drain side end-to-end; the remaining caller-side allocations (builder `Fields{}` literal, `any`-boxing) are addressed by the v1.1 follow-on in #660. See [`BENCHMARKS.md`](BENCHMARKS.md) and [`docs/performance.md`](docs/performance.md) for the full table and the fast-path / slow-path ownership model.
- Eliminate per-event allocations in the Loki batch-build hot path. `BenchmarkLokiOutput_BatchBuild` for 100 events across 5 streams drops from **390 → 35 allocs/op** (91% reduction; ~0.35 allocs/event vs ~4 previously). Measured wall-clock falls 56% (78 µs → 35 µs); per-batch heap usage falls 95% (266 KiB → 12 KiB). New `BenchmarkLokiOutput_BatchBuild_HighCardinality` benchmarks the worst-case 100-distinct-streams pattern at 5 allocs/stream — the unavoidable floor without slab pooling. Optimisations: `streamKey` rewritten as `writeStreamKey` so the per-event lookup uses the Go compiler's `m[string(b)]` zero-alloc pattern; `sortedStreams` and `writeLabelsJSON` reuse pooled scratch slices on the Output struct; `frameworkFields.pidStr` pre-computed at `SetFrameworkFields` time; `strconv.AppendInt` writes into a fixed `[20]byte` scratch instead of `buf.AvailableBuffer()`. Behaviour unchanged — verified by existing BDD and three new unit tests (negative-pid, delimiter-collision, baseline-pid-zero). Closes #494
- New public `audit.WriteJSONBytes(buf, []byte)` mirrors `audit.WriteJSONString` for byte-slice input. Used by the Loki output to embed the pre-serialised event line as a JSON string value without the `string(b)` copy that was the single largest per-event allocation in the loki drain path. Verified byte-identical to `WriteJSONString` (and to `encoding/json.Marshal`) across 10k random inputs by quick-check. Closes #495

### Documentation

- Document the window-boundary counting semantics of `dropLimiter.record`. The lock-free two-atomic design (lastWarn + count) allows a drop's `count.Add(1)` that races with a winning goroutine's `count.Swap(0)` to be reported in the NEXT window rather than the one whose boundary just closed. Total drops across all windows are conserved; per-window counts are slightly smeared under concurrent bursts. Callers needing a monotonic SLA-grade drop total should use `OutputMetrics.RecordDrop` (pure `atomic.Add`, no windowing). Adds `TestDropLimiter_TotalConservedAcrossWindows` which proves conservation under 64 goroutines × 2000 records (#492)
- Document the required placement of `audit.Middleware` relative to panic-recovery middleware. `Middleware` MUST be placed OUTSIDE any panic-recovery middleware; reversing the order silently breaks the re-raise contract. `Middleware` godoc gained a new `# Placement` section with correct / wrong examples, `docs/http-middleware.md` gained a `Placement: Audit Must Wrap Panic Recovery` section with framework-specific examples (chi, Gin), and two BDD scenarios in `tests/bdd/features/http_middleware.feature` document the observable behaviour of both placements (#491)
- Add output-specific benchmark coverage for file rotation and outputconfig startup (#504, master tracker C-18 + C-19). Three components: (1) `BenchmarkWriter_Write_WithRotation` in `file/internal/rotate` sets `MaxSize: 4 KiB` + `MaxBackups: 2` + `Compress: false` so rotation fires every ~25 writes and the per-rotation cost is isolable from the write path (delta vs `BenchmarkWriter_Write_SyncOnWriteFalse` captures rename + new file + prune — ≈960 ns/write amortised, ≈24 µs per rotation event); a companion `BenchmarkFileOutput_Write_WithRotation` in the public `file` package uses `MaxSizeMB: 1` (the public API minimum) so rotation is dilute — catches regressions in the `file.Output → rotate.Writer → flush` chain that only surface after a rotate. Both include a post-loop `filepath.Glob` assertion that rotation actually fired, so a silent break in the rotation trigger fails the benchmark instead of reading as a free perf win. (2) `BenchmarkOutputConfigLoad` in a new `outputconfig/bench_test.go` baselines the full parse + envsubst + validate + factory dispatch path against a 4-output fixture (stdout + 3 file variants with routing, HMAC, envsubst, standard-field defaults) at ~485 µs/op, 1.23 MiB/op, ~8,171 allocs/op — a startup-only cost but a useful regression target for consumers reloading config dynamically. Outputs are closed outside the timer; a post-loop assertion verifies Load actually constructed all 4 outputs. (3) `BenchmarkLokiOutput_BatchBuild_HighCardinality` for the Loki 100-distinct-streams worst case already existed from #494 and is now cross-referenced in BENCHMARKS.md as fulfilling the Loki portion of #504's AC.
- Publish a side-by-side benchmark against `log/slog` + `slog.NewJSONHandler` to answer the adoption-critical "why not just use `slog`?" question with measured numbers. New `BenchmarkSlog_JSONHandler_BaselineComparison` in `bench_comparison_test.go` exercises 3-field and 10-field payloads on both sides, plus audit-only `WithHMAC` and `FanOut4` variants where `slog` has no equivalent. Both sides run synchronously (`audit.WithSynchronousDelivery` on the audit side; `slog.Logger.Info` is synchronous by construction), and each audit sub-benchmark asserts `NoopOutput.Writes() == b.N` at `b.StopTimer` so a silent drop cannot make the ns/op a lie. slog's fast path (`slog.LogAttrs` with pre-constructed `[]slog.Attr`) is represented alongside the ergonomic variadic form so the comparison uses slog's best number. Results published in [`BENCHMARKS.md` § Comparison against log/slog](BENCHMARKS.md#comparison-against-logslog) with prose covering taxonomy validation, framework fields, fan-out, HMAC, and sensitivity-label features that `slog` does not provide. Synchronous-call overhead is ~1.7–1.8 × slog at matched payload sizes — the price of the audit-library guarantees. Benchmarks committed to `bench-baseline.txt` (count=10) so `make bench-compare` tracks regressions; Go stdlib upgrades that change slog numbers are expected to require a rebaseline (#512)

### Fixed

- Syslog reconnect path no longer silently discards the `Close` error on the previous writer. The call previously read `_ = s.writer.Close()` with no comment and no log — a `Close` failure from a mid-handshake TLS teardown, TCP half-close, or unreachable remote produced no diagnostic signal, and operators had no way to link a persistent reconnect loop back to the underlying teardown error. The error is now logged at `slog.LevelDebug` with `address` and `error` attributes; the reconnect itself still proceeds (a fresh transport is about to be established by the subsequent `connect()`, so there is no recoverable action to take beyond observing the failure) (#489)
- Panic loudly at init if any hardcoded SSRF CIDR or IP literal fails to parse. Previously `cgnatBlock` / `deprecatedSiteLocalBlock` / `awsIPv6MetadataIP` init used `_, n, _ := net.ParseCIDR(...)` (or `net.ParseIP(...)` with no check); a source-level corruption or stdlib regression would have silently produced `nil`, and every subsequent SSRF check would have nil-deref panicked inside `Contains` / `Equal`. A new `mustParseCIDR` / `mustParseIP` wrapper panics with a clear `audit: SSRF init: failed to parse hardcoded CIDR ...` message at package load instead (#488)
- Data race on the diagnostic logger field in `webhook`, `file`, `syslog`, `loki` outputs. `SetDiagnosticLogger` performed a plain field assignment while background goroutines concurrently read the same field. Race detector now passes `-count=100` across all four outputs. The field is `atomic.Pointer[slog.Logger]`; writers use `Store`, readers use `Load`. No API-shape change; no functional behaviour change (#474)

### Security

- Drop `github.com/rgooding/go-syncmap` third-party dependency from the filter hot path. The 15-line generic wrapper over `sync.Map` is now inlined as `syncMapBool` in `filter.go`. Rationale: CLAUDE.md mandates minimal dependencies; a single-purpose type on the `isEnabled` path shouldn't carry supply-chain surface. No behavioural change; `BenchmarkAudit` and `BenchmarkAudit_Parallel` unchanged (~370 ns/op and ~62 ns/op, 1 alloc/op) (#588)
- HMAC now authenticates the `_hmac_v` salt version identifier. Previously `_hmac_v` was appended AFTER HMAC computation, leaving it outside the authenticated region. An in-transit attacker could flip the version from `v1` to `v2` to redirect a verifier's salt lookup without detection. `_hmac_v` is now inside the authenticated bytes; any modification invalidates the HMAC tag. Pre-v1.0 consumers using external verifiers that strip both `_hmac` and `_hmac_v` must update the verifier to strip only `_hmac` (#473)
- Document memory retention windows for credential-carrying fields. `HMACConfig.SaltValue`, `loki.Config.BearerToken`, `loki.BasicAuth.Password`, `webhook.Config.Headers`, and `loki.Config.TenantID` retain resolved plaintext for the auditor's lifetime; Go strings cannot be zeroed. The library best-effort zeroes provider `[]byte` token storage in `Provider.Close()` and drops HTTP header map entries after each request, but these are narrowings of the retention window, not zeroing guarantees. `outputconfig.Load()` now explicitly clears the short-lived resolver caches before return as defence-in-depth. Full model + operator rotation strategy: [`SECURITY.md` §Secrets and Memory Retention](SECURITY.md#secrets-and-memory-retention) and [`docs/secrets.md` §Memory Retention and Rotation Strategy](docs/secrets.md#memory-retention-and-rotation-strategy) (#479)
- Extend SSRF block list to cover AWS IMDSv2 over IPv6 (`fd00:ec2::254`) and deprecated IPv6 site-local range (`fec0::/10`, RFC 3879 — not classified by Go's `net.IP.IsPrivate`). IPv4-mapped IPv6 forms (`::ffff:a.b.c.d`) are now normalised to IPv4 before classification — a consumer cannot bypass the private-range or metadata block by bracketing an IPv4 address as an IPv6 literal. SSRF rejections now return the typed `*SSRFBlockedError` wrapping the new `ErrSSRFBlocked` sentinel, exposing a stable `Reason` string (`cloud_metadata`, `cgnat`, `link_local`, `multicast`, `loopback`, `private`, `deprecated_site_local`, `unspecified`) suitable for use as a Prometheus metric label. Azure IPv6 IMDS endpoint research tracked in #643 (#480)
- Add Go fuzz targets for the four untrusted-input parsers: `ParseTaxonomyYAML`, `outputconfig.Load`, `outputconfig.expandEnvString`, and `secrets.ParseRef`. Each target runs committed seed corpus on every PR (via standard `go test`) and is fuzzed for 5 minutes per target as a blocking release-gate step. Two real defects surfaced during the initial fuzz run and were fixed in the same PR: (a) `secrets.validatePath` now rejects C0/C1 control bytes and DEL (classic null-byte path-truncation vector), and (b) taxonomy + output-config parser error messages now sanitise control bytes out of embedded input echo (log-injection defence when a downstream logger prints the error). See [`CONTRIBUTING.md` — Fuzz Testing](CONTRIBUTING.md#fuzz-testing-481) (#481)
- `VerifyHMAC` now validates structural properties of the supplied HMAC value (non-empty, correct length for the algorithm's hash size, lowercase hex only) BEFORE reaching `hmac.Equal`. Malformed inputs return the new `ErrHMACMalformed` sentinel joined with `ErrValidation` so consumers can discriminate format errors from genuine verification failures. Uppercase hex is rejected deliberately — `ComputeHMAC` always emits lowercase, and accepting both would invite a "two valid encodings for one MAC" ambiguity. The constant-time compare happy path is unchanged; structural rejects are not timing-sensitive and are intentionally early returns (#483)
- Preserve string semantics through environment-variable substitution in `outputconfig`. Every YAML-marshaling re-serialisation in the output-config pipeline (`invokeFactory`, `buildRoute`, `buildHMACConfig`, `buildFormatter`, `unmarshalProviderConfig`) now routes through a new `safeMarshal` helper that wraps every string leaf in a YAML `DoubleQuoted` scalar. Without this, a post-expansion string value like `.inf`, `.NaN`, or (on older YAML 1.1 parsers) `on`/`off`/`yes`/`no` was re-emitted unquoted and the downstream factory read it as the wrong Go type — silently turning a string config value into a `float64(+Inf)` or `bool(true)` and breaking field-level contracts. Numbers, booleans, and nulls continue to round-trip at their parsed types; only string leaves are wrapped. Behaviour change is observable only in configs where env-expanded values would otherwise have coerced — existing configs using plain string values are unaffected (#487)
- Redact user-controlled substrings from every `secrets.ParseRef` and `secrets.Ref.Valid` error message. Previously the `invalid scheme %q` error echoed the caller-supplied scheme verbatim — a malformed reference such as `ref+LEAK-SCHEME://...` would surface `LEAK-SCHEME` in any log line that printed the error. A single user-controlled substring in a diagnostic log is a leakage vector (scheme, path, and key portions of a ref are all potentially sensitive in real deployments). The error message is now category-level only (`invalid scheme (redacted, must match [a-z][a-z0-9-]*)`); sentinel `ErrMalformedRef` still wraps the error, preserving `errors.Is` discrimination (#486)
- Enforce a 1-second minimum floor on the derived `http.Transport.ResponseHeaderTimeout` in the `webhook` and `loki` outputs. Previously the value was `Config.Timeout / 2`, which could become a sub-second figure (or even `0` for a misconfigured nanosecond-scale Timeout) unable to complete a real TLS handshake + server response. The overall `http.Client.Timeout` still enforces the caller-configured deadline unchanged; only the per-stage detection of a slow-to-respond server is now prevented from dropping below 1 second (#485)
- Cap the response-body drain to **4 KiB on any 3xx response** in the `webhook` and `loki` outputs. `net/http.Client.CheckRedirect` rejects standard redirects (301/302/303/307/308 with a `Location` header), but a non-redirect 3xx (for example `300 Multiple Choices`, `304 Not Modified`, or a redirect code without a `Location` header) still reaches our `defer`-based drain. Without this cap an attacker-controlled endpoint could force up to `maxResponseDrain` (1 MiB for webhook, 64 KiB for loki) of traffic per *request* — and with the maximum permitted `max_retries` of 20 that becomes 20 × per event. Non-redirect 3xx is treated as a non-retryable client error, so in practice only one drain occurs per event; the cap is still necessary because configuration or policy can change retry semantics, and retries do occur on 5xx where the larger body budget continues to apply. The previous 1 MiB / 64 KiB caps continue to apply to 2xx / 4xx / 5xx responses where the body may carry useful diagnostic information (#484)

### Added

- `ErrValidation`, `ErrUnknownEventType`, `ErrMissingRequiredField`, `ErrUnknownField`, `ErrReservedFieldName` sentinels with `ValidationError` struct (#400, #473)
- `outputconfig.New()` facade for single-call logger creation (#392)
- `github.com/axonops/audit/outputs` convenience package — single blank import registers all output factories (#393)
- `Stdout()` convenience constructor, `NewEventKV()` slog-style event creation, `DevTaxonomy()` permissive development taxonomy (#395)
- `WithSynchronousDelivery()` for inline event processing — no drain goroutine, no Close-before-assert in tests (#403)
- `WithDiagnosticLogger(*slog.Logger)` for configurable library diagnostics (#397)
- `DiagnosticLoggerReceiver` interface — sub-module outputs receive the library's diagnostic logger (#397)
- `RecordedEvent.StringField()`, `IntField()`, `FloatField()` accessors with JSON float64 coercion (#397)
- `NoOpMetrics` base struct for composable Metrics implementations (#401)
- `WithFactory` LoadOption for per-call factory overrides (#399)
- `webhook.WithDiagnosticLogger`, `syslog.WithDiagnosticLogger`, `loki.WithDiagnosticLogger`, `file.WithDiagnosticLogger` functional options on each output module's `New()` — route construction-time TLS and permission warnings to a caller-supplied logger rather than `slog.Default` (#490)
- `outputconfig.WithDiagnosticLogger` LoadOption — threads the auditor's diagnostic logger through every output constructed by `outputconfig.Load`. Pair with `audit.WithDiagnosticLogger` on the `Auditor` for consistent routing of both construction-time and runtime warnings (#490)
- Runtime introspection methods: `BufferLen()`, `BufferCap()`, `OutputNames()`, `IsCategoryEnabled()`, `IsEventEnabled()`, `IsDisabled()`, `IsSynchronous()` (#404)
- `docs/writing-custom-outputs.md` — interface hierarchy and decision tree (#397)
- `docs/migrating-from-application-logging.md` — side-by-side coexistence guide (#397)

### Changed

- All 18 examples rewritten to use simplified API — net deletion of 285 lines (#396)
- Unknown output type error message now suggests both specific import and convenience package (#393)
- `audittest.NewLoggerQuick` defaults to synchronous delivery (#403)

- `default_formatter` YAML key removed — set `formatter:` on each output individually. Outputs without a `formatter:` block default to JSON. If you previously used `default_formatter: { type: json, timestamp: unix_ms }` or `default_formatter: { omit_empty: true }`, move those settings to each output's `formatter:` block or use `logger: { omit_empty: true }` for the `omit_empty` case (#305)
- Progressive examples renumbered: outputs grouped together, 04-12 → 05-17 with gaps for new examples (#278)
- Progressive examples renumbered: new 03-standard-fields inserted, 03-11 → 04-12 (#237)
- Bare optional declaration of reserved standard fields now rejected by `ValidateTaxonomy` — use `required: true` or add labels (#237)
- CEF `event_category` extension key changed from `eventCategory` to `cat` (ArcSight `deviceEventCategory`) (#237)
- `Logger.Audit(eventType, fields)` replaced by `Logger.AuditEvent(Event)` (#205)
- Taxonomy YAML `required:` and `optional:` replaced by unified `fields:` map (#195)
- `Taxonomy.Categories` type changed from `map[string][]string` to `map[string]*CategoryDef` (#188)
- `EventDef.Category` (string) replaced by `EventDef.Categories` ([]string) — derived from categories map (#188)
- `category:` field removed from YAML event definitions (#188)
- `MatchesRoute` signature now requires a `severity int` parameter (#187)
- `Taxonomy.DefaultEnabled` field removed — all categories are enabled by default (#12)
- `InjectLifecycleEvents`, `EmitStartup`, and automatic shutdown event removed (#12)

### Changed

- Buffer-full slog.Warn rate-limited to at most once per 10 seconds across core, webhook, and loki outputs. Drop count included in warning message. (#251)
- JSON post-serialisation append reduced from 6 to 1 allocs/op (#229)
- HMAC drain-loop: hash reuse via Reset() + pre-allocated buffers, 8 → 1 extra alloc per event (#230)
- SSRF dial control extracted from webhook/internal/ssrf to core audit package (#256)

### Added

- **Secret provider integration** (`go-audit/secrets`, `go-audit/secrets/openbao`, `go-audit/secrets/vault`) — resolve sensitive config values from external secret stores using `ref+SCHEME://PATH#KEY` syntax in YAML (#353)
  - `Provider` interface with optional `BatchProvider` for path-level caching
  - OpenBao and Vault KV v2 providers: thin HTTP clients, HTTPS-only, SSRF protection, redirect blocking, token zeroing
  - Resolution pipeline: env vars → ref resolution → safety-net scan for unresolved refs
  - HMAC disabled bypass: `enabled` resolved first, remaining refs skipped when false
  - `WithSecretProvider` and `WithSecretTimeout` LoadOptions on `outputconfig.Load()`
  - **Breaking**: `outputconfig.Load()` signature adds `context.Context` and `...LoadOption`
  - 22 BDD scenarios + 6 real-container integration scenarios (OpenBao + Vault with dev-tLS)
  - Docker Compose for OpenBao and Vault dev-tls containers
  - Comprehensive documentation: authentication guide, troubleshooting, error reference
- **Grafana Loki output** (`go-audit/loki`) — stream labels, gzip compression, multi-tenancy, batched delivery with retry (#251)
  - Config: URL, BasicAuth/BearerToken, TenantID, static + dynamic labels, batching, compression
  - Stream labels: app_name, host, pid, event_type, event_category, severity (individually toggleable)
  - HTTP delivery: exponential backoff retry on 429/5xx, Retry-After support, SSRF protection
  - `FrameworkFieldReceiver` interface for outputs to receive app_name, host, pid
  - 11 integration tests against real Loki, 480+ BDD scenarios, 95% unit test coverage
  - HMAC integrity: end-to-end verification through Loki pipeline (7 BDD scenarios)
  - Multi-output fan-out with Loki: file+Loki, routing, HMAC consistency, failure isolation (7 BDD scenarios)
  - Docker TLS infrastructure: loki-tls (port 3101) and loki-mtls (port 3102) containers
- Syslog output severity mapped dynamically from audit event severity: audit 10→LOG_CRIT, 8-9→LOG_ERR, 6-7→LOG_WARNING, 4-5→LOG_NOTICE, 1-3→LOG_INFO, 0→LOG_DEBUG. Syslog output now implements `MetadataWriter` (#285)
- `MetadataWriter` optional interface for outputs that need structured per-event context (#250)
- `EventMetadata` value type: event type, severity, category, timestamp — zero-allocation, passed by value (#250)

- `WithAppName`, `WithHost`, `WithTimezone` options for logger-wide framework fields (#237)
- `FrameworkFieldSetter` interface for formatters to receive app_name, host, timezone, pid (#237)
- `pid` framework field auto-captured via `os.Getpid()` at construction (#237)
- JSON output: `app_name`, `host`, `timezone`, `pid` after `duration_ms`, before user fields (#237)
- CEF output: `deviceProcessName`, `dvchost`, `dtz`, `dvcpid` framework extensions (#237)
- `app_name`, `host`, `timezone` top-level keys in outputs YAML with env var support (#237)
- `standard_fields` YAML section for deployment-wide reserved field defaults (#237)
- Syslog `hostname` auto-injected from top-level `host` when not set per-output (#237)
- Code generation: setter methods and field constants for all 31 reserved standard fields on every builder (#237)
- `WithStandardFieldDefaults` option for deployment-wide reserved field defaults (#237)
- Syslog `hostname` config field overrides `os.Hostname()` in RFC 5424 header (#237)
- 31 reserved standard fields always accepted without taxonomy declaration (#237)
- Expanded default CEF field mapping from 7 to 28 ArcSight extension keys (#237)
- Per-output HMAC integrity verification with 6 NIST-approved algorithms (#216)
- `HMACConfig`, `ComputeHMAC`, `VerifyHMAC` for tamper detection and verification (#216)
- `_hmac` and `_hmac_v` reserved framework fields (#216)
- `event_category` framework field appended to serialised output (JSON and CEF) showing the delivery-specific category (#227)
- `emit_event_category` taxonomy config (under `categories:`) controls category emission; defaults to `true` (#227)
- `PostField` and `AppendPostFields` extensible post-serialisation append mechanism (#227)
- Reserved field name validation: `timestamp`, `event_type`, `severity`, `event_category` rejected as user-defined fields (#227)
- `audittest` package: in-memory `Recorder` and `MetricsRecorder`, `New`, `NewQuick`, `QuickTaxonomy`, `WithConfig`, `WithValidationMode` for consumer testing (#184)
- `Event` interface, `LabelInfo`, `FieldInfo`, `CategoryInfo` core types (#205)
- `NewEvent()` for dynamic event construction without code generation (#205)
- Per-event typed builders with required-field constructors and optional-field setters (#205)
- `audit-gen` generates typed event builders alongside existing constants (#205)
- Per-event `{Name}Fields` descriptor structs with `FieldInfo()` metadata accessor (#205)
- `Categories()` method on builders returning `[]audit.CategoryInfo` (#205)

- `SensitivityConfig` and `SensitivityLabel` for field-level sensitivity labels (#195)
- Three labeling mechanisms: explicit per-field annotation, global field name mapping, regex patterns (#195)
- Per-output `exclude_labels` strips labeled fields before delivery (#195)
- `WithNamedOutput` accepts variadic `excludeLabels` for output-level field stripping (#195)
- `audit-gen` generates `Label` constants when taxonomy has sensitivity labels (#195)
- Framework fields (timestamp, event_type, severity, duration_ms) protected from labeling (#195)

- `CategoryDef` struct with `Severity *int` for per-category CEF severity (#186)
- `EventDef.Severity *int` for per-event severity override; `EventDef.ResolvedSeverity()` returns resolved value (#186)
- `severity` framework field in JSON output, emitted after `event_type` (#186)
- CEF formatter uses taxonomy `Description` and `ResolvedSeverity()` when `DescriptionFunc`/`SeverityFunc` are nil (#186)
- Events can belong to multiple categories (#188)
- Uncategorised events (not in any category) are valid and always globally enabled (#188)
- `EventRoute.MinSeverity` and `EventRoute.MaxSeverity` for severity-based event routing (#187)
- `ValidateEventRoute` validates severity range (0-10) and min ≤ max (#187)
- Webhook `allow_insecure_http` and `allow_private_ranges` configurable via YAML (#181)
- Stdout factory rejects non-empty config blocks (#182)
- Eight progressive example applications in `examples/` (#163)
- YAML-based output configuration with registry pattern (`outputconfig` module) (#172)
- Output factory registry in core `audit` package: `OutputFactory`, `RegisterOutputFactory`, `LookupOutputFactory`, `RegisteredOutputTypes` (#172)
- Factory registration for file, syslog, and webhook outputs via `init()` and `NewFactory(metrics)` (#172)
- Environment variable substitution (`${VAR}`, `${VAR:-default}`) with post-parse expansion for YAML injection safety (#172)
- Per-output routing, formatter overrides, and `enabled` toggle in YAML config (#172)
- `audit-gen` CLI for generating type-safe audit event helpers from taxonomy YAML (#26)
- Taxonomy description field support (#161)
