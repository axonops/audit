# junit-report — JUnit XML to HTML/Markdown renderer

[![Go Reference][godoc-badge]][godoc]

An internal CI tool for the [`github.com/axonops/audit`][parent]
repository. Reads a JUnit XML report (as emitted by
[`gotestsum --junitfile`][gotestsum]) and writes a standalone HTML
or GitHub-flavoured Markdown report to stdout. Sibling to
[`bdd-report`](../bdd-report/) — same renderer, JUnit XML input
instead of cucumber JSON.

> **Module path**: `github.com/axonops/audit/cmd/junit-report`
> **Status**: pre-release (v0.x) · internal CI use
> **Sibling tool**: [`bdd-report`](../bdd-report/) (same renderer, cucumber JSON input)

## Why

`go test -json` and `gotestsum --junitfile` produce machine-
readable output. Humans still want to see, at a glance, which
package failed, which test failed inside it, and what the failure
or panic body looked like — without manually grepping the JUnit
XML or scrolling through raw test logs.

`junit-report` is a small dedicated renderer for that one job.
The HTML output is single-file, embedded CSS, no JavaScript, no
external assets. The Markdown output targets
[GitHub-flavoured Markdown][gfm]: inline `<details>`/`<summary>`
blocks render natively on `github.com` and inside the Actions
step summary panel.

It distinguishes JUnit's two failure flavours: `<failure>`
(assertion mismatch) and `<error>` (panic or test-setup failure).
Both surface separately in the report so reviewers can spot
panics without trawling through assertion fails.

It is mostly used inside this repository's CI; nothing prevents
external use, but it has no public Go API (it's `package main`)
and no stability commitment beyond what this repo needs.

## Install

```bash
# Pinned binary (rare — typically used via `go run` from the repo):
go install github.com/axonops/audit/cmd/junit-report@latest

# Or via go run:
go run github.com/axonops/audit/cmd/junit-report@latest [flags]
```

Requires Go 1.26+. No runtime dependencies.

## Usage

```bash
junit-report -suite <name> -input <junit.xml> [-format html|markdown] [-only-failures]
```

| Flag | Default | Effect |
|------|---------|--------|
| `-suite` | _(required)_ | Suite or module name shown in the report header (e.g. `core`, `webhook`). |
| `-input` | stdin | Path to the JUnit XML file. Omit (or pass `-`) to read from stdin. |
| `-format` | `html` | Output format: `html` or `markdown` (alias `md`). |
| `-only-failures` | `false` | Markdown only: emit only failed and errored tests. Suitable for the `$GITHUB_STEP_SUMMARY` 1 MiB cap. |
| `-version` | — | Print version and exit. |

Output is always written to stdout. Redirect to a file:

```bash
junit-report -suite core -input report.xml -format html > report.html
```

Non-zero exit when the input is missing, empty, or malformed.
Both `<testsuites>`-rooted (gotestsum, modern Surefire) and bare
`<testsuite>`-rooted (older runners) JUnit documents are accepted.

## Quick start

Run a Go test suite through gotestsum to capture JUnit XML, then
render:

```bash
gotestsum \
    --junitfile=/tmp/r.xml \
    --format=pkgname \
    -- -race ./...

junit-report -suite core -input /tmp/r.xml -format html > report.html
junit-report -suite core -input /tmp/r.xml -format markdown > report.md
```

Open `report.html` in a browser. Each test suite (Go package)
collapses to a header with per-suite pass/fail/error/skip counts.
Failed and errored tests auto-expand, showing the JUnit
`<failure>` / `<error>` body or the captured `<system-err>` (the
panic stack trace lands there when gotestsum can't extract a
structured failure record).

## CI integration

This repo wires `junit-report` into the unit-test job for every
module via the shared composite action at
[`.github/actions/upload-test-report`][upload-action]. The
caller-side step looks like this:

```yaml
- name: Run module tests
  run: make test-${{ matrix.flag }}
  # The shared go_test_with_junit Makefile helper writes
  # ./<module>/<module>-junit.xml as a side-effect.

- name: Generate + upload test report
  if: always()
  uses: ./.github/actions/upload-test-report
  with:
    format: junit-xml
    suite: ${{ matrix.flag }}
    input-path: ${{ matrix.module }}/${{ matrix.flag }}-junit.xml
    artifact-prefix: test-report
```

The composite action invokes `junit-report` twice — once for the
full HTML/Markdown artefacts, once with `-only-failures` for the
step summary panel — and uploads both as workflow artefacts named
`test-report-<suite>` (HTML) and `test-report-<suite>-md`
(Markdown).

### Truncation under the step-summary cap

`$GITHUB_STEP_SUMMARY` has a hard 1 MiB limit. In `-only-failures`
mode, `junit-report` tracks the running output size and emits a
truncation footer once the budget is exceeded — pointing
reviewers at the full Markdown artefact for the rest. A single
suite whose serialised form alone exceeds the cap will overshoot
once; GitHub silently truncates the tail in that case and
reviewers download the artefact for the full report.

## Parity with bdd-report

The escape helpers, Markdown writer, and step-summary truncation
logic in `render.go` / `writer.go` are byte-identical between
`junit-report` and `bdd-report`. `make check-report-parity`
enforces this in CI so a fix to one renderer applies to both.

## See also

- Sibling: [`bdd-report`](../bdd-report/) — same renderer,
  cucumber JSON input
- Composite CI action: [`.github/actions/upload-test-report`][upload-action]
- [gotestsum][gotestsum] — the Go test runner that produces the
  JUnit XML this tool consumes
- [Source](https://github.com/axonops/audit/tree/main/cmd/junit-report)

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/junit-report.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/junit-report
[parent]: https://github.com/axonops/audit
[gotestsum]: https://github.com/gotestyourself/gotestsum
[gfm]: https://github.github.com/gfm/
[upload-action]: https://github.com/axonops/audit/blob/main/.github/actions/upload-test-report/action.yml
