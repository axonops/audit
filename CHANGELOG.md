# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking Changes

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

- JSON post-serialisation append reduced from 6 to 1 allocs/op (#229)
- HMAC drain-loop: hash reuse via Reset() + pre-allocated buffers, 8 → 1 extra alloc per event (#230)
- SSRF dial control extracted from webhook/internal/ssrf to core audit package (#256)

### Added

- **Grafana Loki output** (`go-audit/loki`) — stream labels, gzip compression, multi-tenancy, batched delivery with retry (#251)
  - Config: URL, BasicAuth/BearerToken, TenantID, static + dynamic labels, batching, compression
  - Stream labels: app_name, host, pid, event_type, event_category, severity (individually toggleable)
  - HTTP delivery: exponential backoff retry on 429/5xx, Retry-After support, SSRF protection
  - `FrameworkFieldReceiver` interface for outputs to receive app_name, host, pid
  - 11 integration tests against real Loki, 461 BDD scenarios, 95% unit test coverage
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
- `audittest` package: in-memory `Recorder` and `MetricsRecorder`, `NewLogger`, `NewLoggerQuick`, `QuickTaxonomy`, `WithConfig`, `WithValidationMode` for consumer testing (#184)
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
