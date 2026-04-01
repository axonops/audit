# Contributing to go-audit

Thank you for your interest in contributing to go-audit. This document
covers the development setup, coding standards, and pull request process.

## Development Setup

```bash
git clone https://github.com/axonops/go-audit.git
cd go-audit
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
```

Individual modules can be tested separately: `make test-core`,
`make test-file`, `make test-syslog`, `make test-webhook`,
`make test-outputconfig`, `make test-audit-gen`.

This project does not use pre-commit hooks. Run `make check` before
committing to execute the full quality gate locally.

## Code Standards

The [Google Go Style Guide](https://google.github.io/styleguide/go/)
is the baseline. Key points:

- **External test packages** — use `package audit_test`, not `package audit`
- **Error wrapping** — `fmt.Errorf("audit: context: %w", err)` with `%w` as the final verb
- **Naming** — no stutter (`audit.Logger` not `audit.AuditLogger`), no `Get` prefix, acronyms in caps (`ID`, `URL`)
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

## Dependencies

Dependencies are kept minimal. The core library depends on
`gopkg.in/yaml.v3` (taxonomy parsing) and `go-syncmap` (lock-free
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

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Questions?

Open a [GitHub issue](https://github.com/axonops/go-audit/issues) —
there are no mailing lists or chat channels.
