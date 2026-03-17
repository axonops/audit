# go-audit — CLAUDE.md

## Project

Standalone Go audit logging library — multi-output, async, with taxonomy-driven event validation.

- **Repository:** `github.com/axonops/go-audit`
- **Module:** `github.com/axonops/go-audit`
- **Package:** `audit`
- **License:** Apache 2.0
- **Go:** 1.26+
- **Status:** Pre-release (`v0.x`)

The full specification is GitHub issue [axonops/axonops-schema-registry#371](https://github.com/axonops/axonops-schema-registry/issues/371). That issue is the authoritative source for requirements. If this file conflicts with the spec, the spec wins.

## Workflow — Agent Gates

These agents are mandatory gates, not optional tools. Do not skip them.

### Before creating any GitHub issue:
Run the **issue-writer** agent. Every issue must have: summary, detailed requirements, numbered acceptance criteria, specific testing requirements (named tests, not "add tests"), documentation requirements, dependencies, and labels. If any section is missing or vague, rewrite it before creating.

### After completing any feature:
1. **code-reviewer** — on all changed files
2. **security-reviewer** — on any code touching TLS, HTTP, credentials, or external input
3. **go-quality** — as a final gate before commit

### After creating or modifying CI/CD configuration:
4. **devops** — on any workflow, GoReleaser, Dependabot, or Makefile changes

### When writing tests:
5. **test-writer** — use for creating unit, integration, and BDD tests

### Issue quality is non-negotiable:
Do not create issues with `gh issue create` without running the issue-writer agent first. A vague issue with bullet points and no acceptance criteria is not an issue — it is a TODO comment that escaped into the tracker. Every issue is a contract: it must contain enough detail that a developer can implement it without asking clarifying questions.

## Reference Implementation

The existing audit code lives in a sibling checkout at:
```
/development/auditworkspace/axonops-schema-registry/internal/auth/audit*.go
```
This is **read-only reference material**. Do not modify files in the schema registry. Use it to understand existing patterns, but the library API must follow the spec in issue #371, not replicate the existing code.

## GitHub Issues Are the Source of Truth

Every piece of work must be tracked. GitHub issues are how we coordinate — not conversations, not comments in code, not TODO markers.

- Check `gh issue list` before starting any work — there may already be an issue for it
- Create issues with `gh issue create` for: bugs found during development, design questions, gaps in the spec, sub-tasks of larger features
- Use labels: `bug`, `enhancement`, `testing`, `documentation`, `security`
- Reference issue numbers in every commit: `feat: add file output (#12)`
- When a bug is found by the code-reviewer or security-reviewer agents, they file issues automatically — do not duplicate
- Every `TODO`, `FIXME`, `HACK`, or `BUG` comment must reference a GitHub issue (`// TODO(#42): handle reconnection`). Orphaned TODOs are not acceptable.

## Branching & Commits

- **Main branch:** `main` — always buildable, always passes CI
- **Feature work:** `feature/<short-name>` branched from `main`
- **Bug fixes:** `fix/<short-name>` branched from `main`
- Never commit directly to `main`
- Conventional commits required: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`
- Commits are atomic — one logical change per commit
- Always include the issue reference: `feat: add webhook output (#5)`

## Code Standards

This is a published open-source Go library. It is held to stdlib-grade quality. The Google Go Style Guide (https://google.github.io/styleguide/go/) is the baseline.

### Errors
- All error returns handled — no `_` discards without a comment
- Wrap with context: `fmt.Errorf("audit: output %q: %w", name, err)` — `%w` as the final verb
- Error strings: lowercase, no punctuation
- Sentinel errors: `var ErrBufferFull = errors.New("audit: buffer full")` — exported, at package level
- Discrimination: `errors.Is` / `errors.As` only — never string matching

### Naming
- No stutter: `audit.Logger` not `audit.AuditLogger`
- No `Get` prefix: `Count()` not `GetCount()`
- Acronyms: `URL`, `HTTP`, `ID` — never `Url`, `Http`, `Id`
- Receivers: 1–2 chars from the type name — never `this` or `self`
- Constants: `MaxBufferSize` not `MAX_BUFFER_SIZE`

### Concurrency
- No global mutable state — everything hangs off the `Logger` struct
- Every goroutine has a documented shutdown path
- Shared state protected by `sync.Mutex`, `sync.RWMutex`, or `atomic`
- `sync.WaitGroup.Add()` called before the goroutine, never inside it
- Channel direction types on function signatures: `<-chan T`, `chan<- T`

### API Design
- All exported symbols have godoc comments starting with the symbol name
- Functional options for optional configuration: `audit.WithTaxonomy(t)`, `audit.WithBufferSize(n)`
- Functions that can fail return `error` as the last return value
- No `log.Fatal`, `os.Exit`, or `panic` that escapes the package boundary — this is a library
- No `init()` functions with non-trivial work
- Zero value usability where practical

### Complexity
- Functions over ~40 lines: split them
- Nesting deeper than 2 levels: use guard clauses and early returns
- Cyclomatic complexity > 10: refactor before merge

### Dependencies
- Minimal. Every new dependency must be justified.
- Approved: `lumberjack.v2` (file rotation), `srslog` (RFC 5424 syslog), `yaml.v3` (yamlconfig sub-package only)
- Test only: `testify`, `godog`, `testcontainers-go`, `goleak`
- Forbidden in core: Prometheus, OpenTelemetry, any config file parser, any logging framework
- If you think you need a new dependency, file an issue to discuss it first

### Files
- Every `.go` file has the Apache 2.0 license header
- File size: split at ~300 lines by concern
- Import groups: stdlib first, then third-party — use `goimports`
- No `import .`; blank imports only in `main` or tests

## Testing — Non-Negotiable

If it is not tested, it is not done. No exceptions. No "I'll add tests later." Write the test with the code.

### Unit Tests
- File placement: `writer_test.go` beside `writer.go`
- Package: `package audit_test` (external/black-box) — never `package audit`
- Table-driven tests with `t.Run` for multi-case logic
- `testify/require` for preconditions, `testify/assert` for assertions
- `assert.ErrorIs` / `assert.ErrorAs` — not string matching
- `t.Helper()` on all helpers; `t.Cleanup()` for teardown
- No `time.Sleep` as synchronisation — use channels, `sync.WaitGroup`, or `sync.Cond`
- `goleak.VerifyNone(t)` on any test that starts goroutines
- Coverage target: 90%+

### Integration Tests
- Tagged `//go:build integration`
- Live in `tests/integration/`
- Run against real infrastructure via Docker Compose / testcontainers-go
- Every output (syslog, webhook, file) tested against real containers
- TLS tests use a committed test CA — never `InsecureSkipVerify`
- Black-box: test packages use `_test` suffix and only touch the public API

### BDD Tests (Godog)
- Feature files in `tests/bdd/features/`
- Step definitions in `tests/bdd/steps/`
- Written in consumer language, not implementation language
- One feature file = one user-facing capability
- `Scenario Outline` with `Examples` for data-driven cases
- Thin step definitions — translate Gherkin to API calls, no business logic

### Running Tests
```bash
# Unit
go test -race -v -count=1 ./...

# Integration
go test -race -v -count=1 -tags integration ./tests/integration/...

# BDD
go test -race -v -count=1 -tags integration ./tests/bdd/...

# Coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | grep total
```

## Quality Gates

Before any code is considered complete, it must pass:

1. `gofmt` and `goimports` produce no diff
2. `go vet ./...` clean
3. `golangci-lint run ./...` clean
4. `go test -race -count=1 ./...` all pass
5. Coverage ≥ 90%
6. `go mod tidy` produces no diff
7. `govulncheck ./...` no HIGH/CRITICAL
8. Cross-platform build: `linux/amd64`, `darwin/arm64`, `windows/amd64`

Use the subagents in `.claude/agents/` — they enforce these standards:
- **code-reviewer**: correctness, API design, naming, concurrency, tests, complexity
- **security-reviewer**: TLS, credentials, SSRF, input validation, DoS
- **test-writer**: unit, integration, BDD test creation and quality
- **go-quality**: automated toolchain checks, anti-pattern detection, documentation, module hygiene

Run `code-reviewer` and `security-reviewer` before marking any feature branch ready. Run `go-quality` as a final gate before merge.

## What NOT to Do

- Do not modify anything in the `axonops-schema-registry` checkout
- Do not hardcode event types, categories, or field names — the taxonomy is consumer-defined
- Do not accept file paths for taxonomy loading — `[]byte` only
- Do not add Prometheus or any concrete metrics implementation to the core library
- Do not skip tests to "come back later"
- Do not use `http.DefaultClient` or `http.DefaultTransport`
- Do not use `math/rand` for anything — `crypto/rand` if randomness is needed
- Do not leave `fmt.Println` or `log.Printf` debug statements in library code
- Do not create massive PRs — break work into focused, reviewable branches
- Do not use `time.Sleep` as synchronisation in tests
- Do not commit `go.work` files
- Do not use `replace` directives in `go.mod` on any branch intended for release

## Repository Structure

```
go-audit/
├── .claude/
│   └── agents/              # Claude Code subagents
├── .github/
│   └── workflows/           # CI/CD
├── internal/                # Private implementation details
├── yamlconfig/              # Sub-package: audit/yamlconfig (isolates yaml.v3 dep)
├── examples/
│   ├── basic/
│   ├── multi-output/
│   ├── event-routing/
│   └── middleware/
├── tests/
│   ├── integration/         # Docker Compose integration tests
│   ├── bdd/
│   │   ├── features/        # Godog feature files
│   │   ├── steps/           # Step definitions
│   │   └── docker-compose.*.yml
│   └── testdata/            # Fixtures, test certs
├── audit.go                 # Core Logger, NewLogger, Close, Audit()
├── taxonomy.go              # Taxonomy, EventDef, Fields, validation
├── event.go                 # EventType handle, lifecycle events
├── output.go                # Output interface
├── filter.go                # EventRoute, per-output routing
├── file.go                  # FileOutput
├── syslog.go                # SyslogOutput
├── webhook.go               # WebhookOutput
├── stdout.go                # StdoutOutput
├── fanout.go                # Multi-output fan-out
├── format.go                # JSON + CEF formatters
├── config.go                # Config structs
├── migrate.go               # Config version migration
├── metrics.go               # Metrics interface
├── middleware.go             # HTTP middleware + hints
├── doc.go                   # Package documentation
├── CLAUDE.md                # This file
├── Makefile
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
├── .golangci.yml
├── .goreleaser.yml
└── .gitignore
```

## Makefile Targets

```bash
make test              # go test -race -v ./...
make test-integration  # integration tests (Docker)
make test-bdd          # BDD tests (Docker)
make lint              # golangci-lint
make vet               # go vet
make fmt               # gofmt + goimports
make build             # go build
make check             # fmt + vet + lint + test-race (full local gate)
make bench             # benchmarks with benchmem
make coverage          # coverage report with HTML output
make clean             # clear test cache
```
