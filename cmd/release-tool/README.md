# release-tool — typed automation for the audit release flow

[![Go Reference][godoc-badge]][godoc]

`release-tool` is the audit project's internal CLI that drives the
release workflow. It replaces the two failing bash scripts
(`scripts/release/gh-graphql-commit.sh` and `gh-graphql-tag.sh`)
that produced 7 cascading bugs during v0.2.1 (#900–#916).

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

## Internal packages

| Package | Purpose |
|---------|---------|
| `internal/sha` | Strict 40-hex-char SHA validation (regression for #911). |
| `internal/gitstatus` | NUL-safe `git status -z` parser (regression for #907). |
| `internal/allowlist` | go.mod / go.sum allowlist enforcement (rejects vendor/, .github/, symlinks). |
| `internal/ghclient` | Typed wrapper around 3 GitHub REST endpoints with slog instrumentation. |

Each package is unit-tested against `httptest.Server` fixtures and is
covered ≥ 85 %.

## See also

- [Umbrella tracking issue #918](https://github.com/axonops/audit/issues/918)
- [PR-2 scope issue #921](https://github.com/axonops/audit/issues/921) — foundation + helpers
- [PR-3 scope issue #923](https://github.com/axonops/audit/issues/923) — subcommands (this revision)
- [`scripts/release/`](../../scripts/release/) — the shell scripts being replaced (deletion in PR-6)
- [`docs/releasing.md`](../../docs/releasing.md) — operator-facing release playbook (updated in PR-6)

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/release-tool.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/release-tool
