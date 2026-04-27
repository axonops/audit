# Contributing to audit

Thank you for your interest in contributing to audit. This document
covers the development setup, coding standards, and pull request process.

## Development Setup

```bash
git clone https://github.com/axonops/audit.git
cd audit
make install-tools   # golangci-lint v2.1.6, govulncheck v1.1.4, goimports, goreleaser
make workspace       # creates go.work for IDE tooling (gitignored)
make check           # runs the full quality gate locally
```

Requires **Go 1.26+**.

## Running Tests

```bash
make test              # unit tests for all modules
make test-integration  # integration tests (requires Docker)
make test-bdd          # BDD tests (requires Docker)
make check             # full quality gate (same checks as CI)
make sbom              # generate CycloneDX + SPDX SBOMs (requires syft)
make sbom-validate     # validate generated SBOMs
```

Individual modules can be tested separately: `make test-core`,
`make test-file`, `make test-syslog`, `make test-webhook`,
`make test-outputconfig`, `make test-audit-gen`.

This project does not use pre-commit hooks. Run `make check` before
committing to execute the full quality gate locally.

### BDD Strict mode — non-negotiable

Every `godog.Options{}` block in every test file MUST include
`Strict: true`. Without it, scenarios whose step definitions are
missing pass silently — the BDD suite reports them as "undefined"
but the test still exits zero, and CI misses the regression.

This caused a months-long silent-failure window in `outputconfig`
BDD (issues #622 and #476). To prevent recurrence:

- `make check-bdd-strict` runs as part of `make check` and as a
  dedicated **Hygiene** step in CI, executed BEFORE the test
  matrix so a regression fails loudly and early.
- The check rejects three patterns: (1) any `godog.Options{}`
  block missing `Strict: true`; (2) any `Strict: false` anywhere
  in Go source; (3) any `--godog.strict=false` flag in a Makefile,
  shell script, or CI config.

**Under no circumstances may a PR be merged that disables Strict
mode, weakens the `check-bdd-strict` target, or removes the CI
step.** Attempts to bypass the check with `//nolint` comments,
build tags, or conditional shell expressions are a review-rejection
criterion independent of the underlying change's merits.

If you hit an undefined step, the fix is to define the step — not
to disable Strict. If you need to stage a scenario before its steps
exist, do not commit the scenario yet.

### Fuzz Testing (#481)

Four untrusted-input parsers have Go fuzz targets:

| Target | Fuzz function | Location |
|---|---|---|
| `audit.ParseTaxonomyYAML` | `FuzzParseTaxonomyYAML` | `taxonomy_yaml_fuzz_test.go` |
| `outputconfig.Load` | `FuzzOutputConfigLoad` | `outputconfig/outputconfig_fuzz_test.go` |
| `outputconfig.expandEnvString` | `FuzzExpandEnvString` | `outputconfig/envsubst_fuzz_test.go` |
| `secrets.ParseRef` | `FuzzParseRef` | `secrets/secrets_fuzz_test.go` |

**Regular PR CI** runs each fuzz function against its committed
seed corpus via `go test` — no `-fuzz` flag, just seeds as regular
sub-tests. Committed crashers live under `testdata/fuzz/FuzzXxx/`
and protect against regressions.

**Release workflow** runs `make fuzz-long` (default 5 minutes per
target) as a blocking gate — any crasher fails the release. Crash
inputs are uploaded as a workflow artifact for triage.

**Local fuzzing** — reproduce a seeded run quickly:
```bash
make fuzz-short                       # seeds only, < 1s
make fuzz-long                        # 60s per target
make fuzz-long FUZZ_TIME=10m          # 10 minutes per target
go test -fuzz=FuzzParseRef -fuzztime=30s ./secrets  # single target
```

If the fuzzer finds a crasher, it writes the reproducer to
`testdata/fuzz/FuzzXxx/<hash>`. Commit that file alongside the
fix — it becomes a permanent regression seed.

### Benchmarks and regression detection (#493)

The repo ships a committed baseline in `bench-baseline.txt` and a
human-readable summary in `BENCHMARKS.md`. The release workflow runs
`make bench-compare` as an advisory step (GitHub Actions runners are
too noisy for a hard threshold) and uploads the delta report as a
`bench-delta` artifact plus a summary in the GitHub Actions summary.

**Running benchmarks locally:**
```bash
make bench                      # run all modules → bench.txt (count=5)
make bench BENCH_COUNT=3        # faster, less statistical power
make bench-compare              # bench + benchstat vs bench-baseline.txt
make bench-save                 # bench and copy output to bench-baseline.txt
```

**Reading `make bench-compare` output.** benchstat produces a
two-column delta report (baseline vs current). A `+5.00%` under
`sec/op` means 5% slower; a `-2.00%` means 2% faster. The `p=...`
column reports statistical confidence (`p < 0.05` is the usual
threshold for a real delta). A blank column or `~` means the
confidence interval spans zero — run with a higher `BENCH_COUNT` to
get a clearer signal.

**When to refresh `bench-baseline.txt`:**

- A benchmark is renamed. `make bench-baseline-check` (part of
  `make check`) rejects a PR that introduces a stale name.
- A hot-path change lands that moves numbers meaningfully — say
  after a #494–#508 style performance issue.
- Before any milestone release (`docs/releasing.md` Pre-Release
  Checklist calls this out explicitly).

Refresh with `make bench-save` on consistent local hardware, update
`BENCHMARKS.md` with the new headline numbers, and commit both files
together in a `chore: refresh bench-baseline ...` commit.

## Code Standards

The [Google Go Style Guide](https://google.github.io/styleguide/go/)
is the baseline. Key points:

- **External test packages** — use `package audit_test`, not `package audit`
- **Error wrapping** — `fmt.Errorf("audit: context: %w", err)` with `%w` as the final verb
- **Naming** — no stutter (`audit.Auditor` not `audit.AuditAuditor`), no `Get` prefix, acronyms in caps (`ID`, `URL`)
- **Godoc** — all exported symbols have comments starting with the symbol name
- **Coverage** — target 90%+; `goleak.VerifyNone(t)` on tests that start goroutines
- **No panics** — this is a library; no `log.Fatal`, `os.Exit`, or `panic` that escapes the package boundary

## Commit Conventions

Conventional commits are required:

```
feat: add webhook retry backoff (#42)
fix: prevent buffer overflow on slow outputs (#43)
test: add CEF formatter edge cases (#44)
docs: update syslog configuration reference (#45)
```

- **One logical change per commit**
- **Reference the issue number** in every commit message
- **Imperative mood** — "add feature" not "added feature"

## Pull Request Process

1. **File an issue first** for significant work — this avoids duplicated effort
2. **Branch from `main`** as `feature/<short-name>` or `fix/<short-name>`
3. **Write tests with the code** — if it is not tested, it is not done
4. **Run `make check`** — this runs the same checks as CI
5. **Open a PR** — keep the title under 70 characters; use the description for details
6. **CI must pass** — the `CI Pass` summary job gates all merges

Never commit directly to `main`.

## Branch and Commit Rules

The `main` branch has protection rules enforced by GitHub:

- **Signed commits required** — all commits must be GPG or SSH
  signed. See [GitHub's signing docs](https://docs.github.com/en/authentication/managing-commit-signature-verification)
  for setup instructions.
- **Linear history** — only squash or rebase merges are allowed.
  No merge commits.
- **No force pushes** — `git push --force` to `main` is blocked.
- **No branch deletion** — `main` cannot be deleted.
- **Status checks** — the `CI Pass` job must be green before merge.
  This aggregates all per-module build, lint, test, and security jobs.
- **Up-to-date branches** — your branch must be rebased on the
  latest `main` before merging.

Version tags (`v*`, `file/v*`, `syslog/v*`, `webhook/v*`,
`outputconfig/v*`) are protected — they cannot be deleted or
force-updated once created.

## Dependencies

Dependencies are kept minimal. The core library depends on
`github.com/goccy/go-yaml` (taxonomy parsing) and `go-syncmap` (lock-free
category lookups). Output modules carry their own dependencies
(e.g., `github.com/axonops/srslog` for syslog).

Before adding a new dependency, file an issue to discuss it. Forbidden
in core: Prometheus, OpenTelemetry, any logging framework, any config
file parser beyond what already exists.

## Multi-Module Development

The repository contains multiple Go modules (core, file, syslog,
webhook, outputconfig). Each has its own `go.mod`.

- `make workspace` creates a `go.work` file for IDE cross-module navigation
- `make tidy` runs `go mod tidy` on all modules
- `make tidy-check` verifies tidy produces no diff (CI enforces this)

## Project Layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the pipeline design, module
boundaries, and key source files.

## Release Process

Releases are cut by maintainers. Contributors do not create release tags.

The full release procedure — pre-release checklist, tagging commands for all
7 modules, proxy verification, and retraction policy — is documented in
[docs/releasing.md](docs/releasing.md).

Key points for contributors:

- Do not create tags matching `v*`, `file/v*`, `syslog/v*`, `webhook/v*`,
  `loki/v*`, `outputconfig/v*`, or `cmd/audit-gen/v*`.
- Do not add `replace` directives to `go.mod` on any branch intended for
  merge — `make check-replace` enforces this in CI.
- Use `make workspace` to create a `go.work` file for local cross-module
  development. It is gitignored and does not affect published modules.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Questions?

Open a [GitHub issue](https://github.com/axonops/audit/issues) —
there are no mailing lists or chat channels.
