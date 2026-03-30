# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- YAML-based output configuration with registry pattern (`outputconfig` module) (#172)
- Output factory registry in core `audit` package: `OutputFactory`, `RegisterOutputFactory`, `LookupOutputFactory`, `RegisteredOutputTypes`
- Factory registration for file, syslog, and webhook outputs via `init()` and `NewFactory(metrics)`
- Environment variable substitution (`${VAR}`, `${VAR:-default}`) with post-parse expansion for YAML injection safety
- Per-output routing, formatter overrides, and `enabled` toggle in YAML config
- `audit-gen` CLI for generating type-safe audit event helpers from taxonomy YAML (#26)
- Taxonomy description field support (#161)
