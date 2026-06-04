# bdd-report — cucumber JSON to HTML/Markdown renderer

[![Go Reference][godoc-badge]][godoc]

An internal CI tool for the [`github.com/axonops/audit`][parent]
repository. Reads a cucumber JSON report (as emitted by
[godog][godog]'s `cucumber:<file>` formatter) and writes a
standalone HTML or GitHub-flavoured Markdown report to stdout.

> **Module path**: `github.com/axonops/audit/cmd/bdd-report`
> **Status**: pre-release (v0.x) · internal CI use
> **Sibling tool**: [`junit-report`](../junit-report/) (same renderer, JUnit XML input)

## Why

godog produces a structured cucumber JSON report. Humans don't
read JSON. CI reviewers want to see at a glance which scenarios
passed, which failed, which steps inside each scenario failed,
and what the failure message was — preferably without leaving the
GitHub Actions tab.

`bdd-report` is a small dedicated renderer for that one job. The
HTML output is single-file, embedded CSS, no JavaScript, no
external assets — drop it into a workflow artefact and reviewers
can open it locally. The Markdown output targets
[GitHub-flavoured Markdown][gfm]: inline
`<details>`/`<summary>` collapsible blocks render natively on
`github.com` and inside the Actions step summary panel.

It is mostly used inside this repository's CI; nothing prevents
external use, but it has no public Go API (it's `package main`)
and no stability commitment beyond what this repo needs.

## Install

```bash
# Pinned binary (rare — typically used via `go run` from the repo):
go install github.com/axonops/audit/cmd/bdd-report@latest

# Or via go run:
go run github.com/axonops/audit/cmd/bdd-report@latest [flags]
```

Requires Go 1.26+. No runtime dependencies.

## Usage

```bash
bdd-report -suite <name> -input <cucumber.json> [-format html|markdown] [-only-failures]
```

| Flag | Default | Effect |
|------|---------|--------|
| `-suite` | _(required)_ | Suite name shown in the report header (e.g. `core`, `webhook`). |
| `-input` | stdin | Path to the cucumber JSON file. Omit (or pass `-`) to read from stdin. |
| `-format` | `html` | Output format: `html` or `markdown` (alias `md`). |
| `-only-failures` | `false` | Markdown only: emit only failed scenarios. Suitable for the `$GITHUB_STEP_SUMMARY` 1 MiB cap. |
| `-version` | — | Print version and exit. |

Output is always written to stdout. Redirect to a file:

```bash
bdd-report -suite core -input report.json -format html > report.html
```

Non-zero exit when the input is missing, empty, or malformed.

## Quick start

Run a BDD suite with godog's cucumber formatter and convert the
report:

```bash
go test -tags integration -v \
    ./tests/bdd -run TestFeatures -godog.format=cucumber:/tmp/r.json

bdd-report -suite core -input /tmp/r.json -format html > report.html
bdd-report -suite core -input /tmp/r.json -format markdown > report.md
```

Open `report.html` in a browser. The page is single-file with
embedded CSS — no JavaScript, no network requests. Each feature
collapses to a header that shows pass/fail counts; failed
scenarios auto-expand and show the failed step's error body.

The Markdown form renders directly when pasted into a GitHub
issue or PR comment:

```markdown
# BDD report — core

**42 scenarios** · **41 passed** · **1 failed**

<details open>
<summary><strong>Feature: HTTP middleware</strong> — 5✓ · 1✗</summary>
...
</details>
```

## CI integration

This repo wires `bdd-report` into every BDD matrix leg via the
shared composite action at
[`.github/actions/upload-test-report`][upload-action]. The
caller-side step looks like this:

```yaml
- name: Run BDD tests
  env:
    BDD_REPORT_FILE: ${{ runner.temp }}/bdd-report-${{ matrix.suite }}.json
  run: make ${{ matrix.target }}

- name: Generate + upload BDD report
  if: always()
  uses: ./.github/actions/upload-test-report
  with:
    format: cucumber-json
    suite: ${{ matrix.suite }}
    input-path: ${{ runner.temp }}/bdd-report-${{ matrix.suite }}.json
    artifact-prefix: bdd-report
```

The composite action invokes `bdd-report` twice — once for the
full HTML/Markdown artefacts, once with `-only-failures` for the
step summary panel — and uploads both as workflow artefacts named
`bdd-report-<suite>` (HTML) and `bdd-report-<suite>-md`
(Markdown).

### Truncation under the step-summary cap

`$GITHUB_STEP_SUMMARY` has a hard 1 MiB limit. In `-only-failures`
mode, `bdd-report` tracks the running output size and emits a
truncation footer once the budget is exceeded — pointing
reviewers at the full Markdown artefact for the rest. A single
feature whose serialised form alone exceeds the cap will
overshoot once; GitHub silently truncates the tail in that case
and reviewers download the artefact for the full report.

## See also

- Sibling: [`junit-report`](../junit-report/) — same renderer,
  JUnit XML input
- Composite CI action: [`.github/actions/upload-test-report`][upload-action]
- Cucumber JSON schema: <https://github.com/cucumber/cucumber-json-schema>
- [Source](https://github.com/axonops/audit/tree/main/cmd/bdd-report)

[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/cmd/bdd-report.svg
[godoc]: https://pkg.go.dev/github.com/axonops/audit/cmd/bdd-report
[parent]: https://github.com/axonops/audit
[godog]: https://github.com/cucumber/godog
[gfm]: https://github.github.com/gfm/
[upload-action]: https://github.com/axonops/audit/blob/main/.github/actions/upload-test-report/action.yml
