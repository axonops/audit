# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking Changes

- `Logger.Audit(eventType, fields)` replaced by `Logger.AuditEvent(Event)` (#205)
- Taxonomy YAML `required:` and `optional:` replaced by unified `fields:` map (#195)
- `Taxonomy.Categories` type changed from `map[string][]string` to `map[string]*CategoryDef` (#188)
- `EventDef.Category` (string) replaced by `EventDef.Categories` ([]string) — derived from categories map (#188)
- `category:` field removed from YAML event definitions (#188)
- `MatchesRoute` signature now requires a `severity int` parameter (#187)
- `Taxonomy.DefaultEnabled` field removed — all categories are enabled by default (#12)
- `InjectLifecycleEvents`, `EmitStartup`, and automatic shutdown event removed (#12)

### Added

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
