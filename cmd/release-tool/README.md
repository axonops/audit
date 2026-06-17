# release-tool — typed automation for the audit release flow

[![Go Reference][godoc-badge]][godoc]

`release-tool` is the audit project's internal CLI that drives the
release workflow. It replaces the bash + jq + gh-CLI helpers that
produced 7 cascading bugs during v0.2.1 (#900–#916). PR-6 (#929)
deleted those bash scripts; this Go binary is the canonical
App-signed commit + tag path. #967 added a third subcommand
(`preflight-tidy-check`) that validates `make tidy` output against
6 safety gates before the release dispatch absorbs the diff.

> **Module path**: `github.com/axonops/audit/cmd/release-tool`
> **Status**: pre-release (v0.x) — internal binary, NOT published to consumers
> **Tracking issue**: [#918](https://github.com/axonops/audit/issues/918)

## Why

Every bug in the v0.2.1 release was a bash + jq + gh-CLI impedance
mismatch:

- `$()` strips NUL bytes (#907)
- `gh api --jq` silently bypassed on 4xx, leaking error JSON as a SHA (#911)
- `jq` exits 5 on non-JSON, propagated silently under `set -e` (#914)
- `--raw-field` sends JSON objects as strings (#916)

These are not bash bugs — they are bash-vs-typed-data impedance
mismatches that a small Go binary does not have. `release-tool`
constructs typed structs, marshals via `encoding/json`, and surfaces
every API failure with the full response body and a per-call request
ID.

## I/O contract

- **Stderr is for humans.** Every log line, error, and diagnostic goes
  there. The slog handler MUST write to stderr.
- **Stdout is for machines.** When a subcommand produces a result the
  release workflow needs to capture (e.g. the new commit SHA), it is
  written to stdout with no decoration so it can be captured into a
  shell variable.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Operational failure (API error, network, I/O) |
| 2 | Usage error (flag parse, unknown subcommand) |
| 3 | Validation error (allowlist rejected, invalid SHA) |
| 4 | Idempotent no-op (target already in desired state) |

## Build

```bash
make build-release-tool   # builds ./bin/release-tool (~2.6 MB)
```

The binary lives in its own `cmd/release-tool/go.mod` module so its
`net/http`+`slog`+`uuid` dependencies do not enter the published
library graph.

## Usage

```bash
release-tool [persistent flags] <subcommand> [subcommand flags]
```

### Persistent flags

| Flag | Default | Description |
|------|---------|-------------|
| `--help` | — | Show help and exit. |
| `--version` | — | Print version (includes the build commit SHA in dev builds) and exit. |
| `--dry-run` | `false` | Print every state-mutating API payload to stdout and exit 0 without performing the mutation. |
| `--timeout` | `30s` | Per-request timeout for GitHub API calls. |

### Environment

- `GH_TOKEN` (required) — the GitHub App's Installation Token. Never logged.

### Subcommands

#### `commit-pinned-deps`

Opens an App-signed commit on a branch using the GitHub GraphQL
`createCommitOnBranch` mutation. Reads the staged `go.mod` /
`go.sum` files from the workdir, screens every path against the
allowlist (rejects symlinks, refuses anything outside go.mod / go.sum
at 0-2 levels deep), and submits them in a single mutation.

| Flag | Required | Description |
|------|----------|-------------|
| `--owner` | yes | GitHub repository owner |
| `--repo` | yes | GitHub repository name |
| `--branch` | yes | Target branch (e.g. `release/v0.2.2`) |
| `--message` | yes | Commit message headline |
| `--auto-create-branch` | no | Create the branch from `main` if missing |
| `--workdir` | no | Path to the git working directory (default: `.`) |

On success the new commit OID is written to stdout. With `--dry-run`,
the proposed payload (path + size, never raw file contents) is
written to stdout instead and no API mutation occurs.

Regressions locked:
- #906 / #910 — paths outside go.mod/go.sum, and any symlinked target, are refused
- #907 — `git status -z` is consumed as an `io.Reader`, never round-tripped through `$()`
- #911 — only 40-hex commit SHAs reach the API
- #915 / #916 — GraphQL `variables` is a structured object, never a JSON-string-of-an-object

#### `create-tag`

Creates an annotated tag at a commit SHA. Strictly idempotent: if the
tag already exists at the same SHA, exit 4 (no-op); at a different
SHA, exit 1 (refusing to overwrite) with the operator pointed at
the contaminating commit.

| Flag | Required | Description |
|------|----------|-------------|
| `--owner` | yes | GitHub repository owner |
| `--repo` | yes | GitHub repository name |
| `--tag` | yes | Tag name, e.g. `v0.2.2` |
| `--sha` | yes | Commit SHA to point the tag at (40 lowercase hex) |
| `--message` | yes | Tag annotation message |

On success the tag OBJECT SHA is written to stdout. With `--dry-run`,
the two proposed payloads (`POST /git/tags` and `POST /git/refs`)
are written to stdout instead and no API mutation occurs.

#### `preflight-tidy-check`

Validates the working tree's uncommitted diff (presumed to be the
output of a fresh `make tidy`) against six NON-NEGOTIABLE safety
gates before the release.yml `preflight-tidy` job (#967) commits
it. Each gate failure exits with an exact operator-facing error
string declared in #967 AC #4 (see `docs/releasing.md` § "Preflight
tidy (#967)" for the failure-mode table).

| Flag | Required | Description |
|------|----------|-------------|
| `--last-released-version` | yes | The last released `vX.Y.Z` — gates 3 + 4 root their checks here |
| `--published-modules` | yes | Comma-separated list of published module paths (derived from `make print-publish-modules`) |
| `--workdir` | no | Path to the git working directory (default: `.`) |
| `--max-diff-bytes` | no | Hard cap on diff size (default: `8192`) |
| `--sumdb-endpoint` | no | Override the sum.golang.org endpoint (test-only) |
| `--sumdb-timeout` | no | Per-module sumdb lookup timeout (default: `30s`) |
| `--skip-sumdb-cross-check` | no | DANGER — skip gate 4 (test-only) |

Exit codes (additions to the project-wide table above):
- `0` — every gate passed; stdout lists `<module> <version>` per validated pair.
- `3` — a safety gate aborted; stdout + stderr carry the AC #4 string.
- `4` — no diff (idempotent no-op).

The subcommand performs the sum.golang.org transparency-log lookup
directly via HTTPS — `GOPROXY` is not consulted on the verification
path. See `internal/sumdb/` for the signed-note threat model.

## Internal packages

| Package | Purpose |
|---------|---------|
| `internal/sha` | Strict 40-hex-char SHA validation (regression for #911). |
| `internal/gitstatus` | NUL-safe `git status -z` parser (regression for #907). |
| `internal/allowlist` | go.mod / go.sum allowlist enforcement (rejects vendor/, .github/, symlinks). |
| `internal/ghclient` | Typed wrapper around 3 GitHub REST endpoints with slog instrumentation. |
| `internal/sumdb` | Direct sum.golang.org transparency-log lookup for `preflight-tidy-check` gate 4 (#967). |

Each package is unit-tested against `httptest.Server` fixtures and is
covered ≥ 85 %.

## See also

- [Umbrella tracking issue #918](https://github.com/axonops/audit/issues/918)
- [PR-2 scope issue #921](https://github.com/axonops/audit/issues/921) — foundation + helpers
- [PR-3 scope issue #923](https://github.com/axonops/audit/issues/923) — subcommands (this revision)
- [`scripts/release/`](../../scripts/release/) — the surviving shell helpers; the v0.2.1 App-signed bash helpers were deleted in PR-6 (#929)
- [`docs/releasing.md`](../../docs/releasing.md) — operator-facing release playbook

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/release-tool.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/release-tool
