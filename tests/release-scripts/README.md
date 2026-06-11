# tests/release-scripts

bats-core harness for the five shell scripts under `scripts/release/`
that survived the v0.2.2 PR-3 typed-Go rewrite (#925).

## Why this exists

The two App-signed commit + tag helpers were the bash + jq + `gh` CLI
chokepoints that produced eight cascading bugs in v0.2.1
(#900-#916). PR-3 replaced them with `cmd/release-tool`; PR-6 (#929)
deleted them. These five surviving scripts stay shell because their
work — string-mangling `go.mod`, parsing `make print-publish-modules`,
`git tag` plumbing — is shell-native and porting to Go would not buy
enough type safety to justify the churn. Each one was edited at
least once during the v0.2.1 cascade, though, so they need test
scaffolding.

## What is covered

| Script | LoC | Tests |
|---|---:|---:|
| `check-tag-conflicts.sh` | 7 | 7 |
| `tag-all.sh` | 18 | 18 |
| `update-deps.sh` | 7 | 7 |
| `regen-docs.sh` | 6 | 6 |
| `bump-example-deps.sh` | 6 | 6 |
| **Total** | — | **44** |

Plus three meta-tests for the fixture stub binaries
(`fixtures/bin/{go,git,make}`), 24 grep-based regression tests for
`.github/workflows/release.yml` + the composite action at
`.github/actions/build-release-tool/`, and 4 behavioural CLI flag
validity tests (`cli-flag-validity.bats`, #960) that invoke the
real gh / goreleaser / cosign tools. **Total: 87 tests.**

## What is **not** covered

- The deleted bash commit + tag helpers — their behaviour is locked
  by the typed Go tests in
  `cmd/release-tool/internal/{ghclient,allowlist,sha,gitstatus}`
  and the named-regression suite in
  `cmd/release-tool/regression_named_test.go`.
- `release.yml` text — covered by the dedicated grep-based suite at
  `tests/release-scripts/release-yml-grep.bats`.
- CLI flag validity (gh / goreleaser / cosign) — covered by
  `tests/release-scripts/cli-flag-validity.bats` (#960). PR-5 shipped
  a fake fix because the regression test only grep'd release.yml for
  the literal string `--json url --jq '.url'`; gh CLI silently
  rejected the flag at v0.2.2 dispatch. The new file invokes the
  actual CLIs and validates every flag in release.yml /
  .goreleaser.yml against the tool's `--help` output. CI's
  `Test - Release Scripts` job installs goreleaser + cosign at the
  same SHA-pinned versions goreleaser.yml uses, so the harness
  exercises the real surface.

## Running locally

```bash
# Install bats-core (one-time):
#   npm install -g bats
#     — or —
#   git clone https://github.com/bats-core/bats-core
#   cd bats-core && ./install.sh ~/.local

make test-release-scripts
```

CI installs bats fresh per run from the SHA-pinned commit; see
`.github/workflows/ci.yml` → `release-scripts` job.

## How the harness is structured

| Path | Purpose |
|---|---|
| `test_helper.bash` | shared helpers: temp git repo init, fake `make print-publish-modules`, PATH-stub setup, argv assertion file helpers |
| `fixtures/bin/{go,git,make}` | stub binaries that record every invocation's argv to `$ASSERTION_DIR/<name>.args`; tests grep that file to assert "did the script call X with Y" |
| `fixtures.bats` | meta-tests for the stub binaries themselves (canary for stub regressions) |
| `<script>.bats` | one file per script under test |

Each test:

1. Runs `stub_path` in `setup()` — prepends `fixtures/bin/` to PATH and
   points `ASSERTION_DIR` at a per-test temp dir under `BATS_TEST_TMPDIR`.
2. Stages whatever filesystem fixtures the script needs (temp git
   repo, fake `Makefile`, fake `go.mod`, etc.).
3. `run "$SCRIPT" <args>` to exercise the script under test.
4. Asserts exit code, stdout/stderr content, and (where applicable)
   the recorded argv of the fixture binaries.

Every test is hermetic: `BATS_TEST_TMPDIR` is fresh per test and the
stubs only touch files under that root.

## Adding a new test

1. Add a `@test "test_<script>_<scenario>"` block to the existing
   `<script>.bats` file, or — if covering a new script — create
   a new `<script>.bats` and copy the `load 'test_helper.bash'`
   + `setup()` boilerplate from a sibling.
2. Name the test by the AC convention (`test_<script>_<scenario>`)
   so the test name traces back to a numbered AC item or a
   referenced GitHub issue.
3. Run `make test-release-scripts` locally; CI gates on the same
   target.

## Adding a new fixture stub

If a script under test starts shelling out to a new binary
(e.g. `gh`, `curl`), add a stub at `fixtures/bin/<name>` and a
meta-test in `fixtures.bats` to canary it.

The stub MUST:

- Record every invocation's argv to `"$ASSERTION_DIR/<name>.args"`
  (one line per call, NUL-free).
- Honour environment-variable knobs for controlled failure modes
  (e.g. `FAKE_GO_FAIL`).
- Exit 0 by default so the upstream script reaches its happy path.

## See also

- [Umbrella tracking issue #918](https://github.com/axonops/audit/issues/918)
- [PR-4 scope issue #925](https://github.com/axonops/audit/issues/925)
- [`cmd/release-tool`](../../cmd/release-tool) — the typed Go binary
  that replaces the bash scripts being deleted in PR-6
- [`scripts/release/`](../../scripts/release) — the scripts under test
- [`docs/releasing.md`](../../docs/releasing.md) — operator-facing
  release playbook
