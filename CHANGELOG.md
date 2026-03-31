# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking Changes

- `Taxonomy.Categories` type changed from `map[string][]string` to `map[string]*CategoryDef` (#188)
- `EventDef.Category` (string) replaced by `EventDef.Categories` ([]string) — derived from categories map (#188)
- `category:` field removed from YAML event definitions (#188)
- `MatchesRoute` signature now requires a `severity int` parameter (#187)

### Added

- `CategoryDef` struct with `Severity *int` for per-category CEF severity (#186)
- `EventDef.Severity *int` for per-event severity override; `EventDef.ResolvedSeverity()` returns resolved value (#186)
- `severity` framework field in JSON output, emitted after `event_type` (#186)
- CEF formatter uses taxonomy `Description` and `ResolvedSeverity()` when `DescriptionFunc`/`SeverityFunc` are nil (#186)
- Lifecycle events have explicit severity: startup=6, shutdown=7
- Events can belong to multiple categories (#188)
- Uncategorised events (not in any category) are valid and always globally enabled (#188)
- `EventRoute.MinSeverity` and `EventRoute.MaxSeverity` for severity-based event routing (#187)
- `ValidateEventRoute` validates severity range (0-10) and min ≤ max (#187)
- Webhook `allow_insecure_http` and `allow_private_ranges` configurable via YAML (#181)
- Stdout factory rejects non-empty config blocks (#182)
- Eight progressive example applications in `examples/` (#163)
- YAML-based output configuration with registry pattern (`outputconfig` module) (#172)
- Output factory registry in core `audit` package: `OutputFactory`, `RegisterOutputFactory`, `LookupOutputFactory`, `RegisteredOutputTypes`
- Factory registration for file, syslog, and webhook outputs via `init()` and `NewFactory(metrics)`
- Environment variable substitution (`${VAR}`, `${VAR:-default}`) with post-parse expansion for YAML injection safety
- Per-output routing, formatter overrides, and `enabled` toggle in YAML config
- `audit-gen` CLI for generating type-safe audit event helpers from taxonomy YAML (#26)
- Taxonomy description field support (#161)
