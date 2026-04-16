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

### Added

- `ErrValidation`, `ErrUnknownEventType`, `ErrMissingRequiredField`, `ErrUnknownField` sentinels with `ValidationError` struct (#400)
- `outputconfig.New()` facade for single-call logger creation (#392)
- `github.com/axonops/audit/outputs` convenience package — single blank import registers all output factories (#393)
- `Stdout()` convenience constructor, `NewEventKV()` slog-style event creation, `DevTaxonomy()` permissive development taxonomy (#395)
- `WithSynchronousDelivery()` for inline event processing — no drain goroutine, no Close-before-assert in tests (#403)
- `WithDiagnosticLogger(*slog.Logger)` for configurable library diagnostics (#397)
- `DiagnosticLoggerReceiver` interface — sub-module outputs receive the library's diagnostic logger (#397)
- `RecordedEvent.StringField()`, `IntField()`, `FloatField()` accessors with JSON float64 coercion (#397)
- `NoOpMetrics` base struct for composable Metrics implementations (#401)
- `WithFactory` LoadOption for per-call factory overrides (#399)
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
