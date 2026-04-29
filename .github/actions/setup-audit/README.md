# `setup-audit` — repo-local composite action

Single source of truth for the "set up Go workspace" ceremony every CI job
in this repo runs after `actions/checkout`. Replaces ~10 lines of duplicated
setup steps in each consuming job.

## Usage

```yaml
- name: Checkout
  uses: actions/checkout@<sha> # vN.N.N

- name: Set up audit workspace
  uses: ./.github/actions/setup-audit
  with:
    install-tools: 'true'              # default 'false'
    install-make-on-windows: 'false'   # default 'false'
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `install-tools` | `'false'` | If `'true'`, cache `~/go/bin` and run `make install-tools`. Cache key is `go-tools-${{ runner.os }}-${{ hashFiles('scripts/tool-versions.txt') }}` so version bumps auto-invalidate the cache without touching `Makefile`. |
| `install-make-on-windows` | `'false'` | If `'true'` AND `runner.os == 'Windows'`, run `choco install make -y` first. GitHub-hosted Windows runners ship Git Bash but not GNU make; required only by the Windows shard of `test-cross-platform`. |

Inputs are stringly-typed (`'true'` / `'false'`) per the GitHub Actions
composite-action convention.

## What it does

1. *(conditional, Windows only)* `choco install make -y`.
2. `actions/setup-go@<sha>` with `go-version-file: go.mod` and
   built-in module cache.
3. `make workspace` — initialises `go.work` for the multi-module repo.
4. *(conditional)* `actions/cache@<sha>` keyed on `scripts/tool-versions.txt`.
5. *(conditional)* `make install-tools` — installs every pinned tool.

Steps 4 and 5 only run when `install-tools` is `'true'`. Jobs that don't
need golangci-lint / govulncheck / goreleaser (e.g. unit-test runners)
should leave `install-tools` at default `'false'` to skip the install
hop entirely.

## Why it exists

Before this composite action, the same ~10-line setup block appeared in
10 jobs across `.github/workflows/ci.yml`. The blocks drifted — some
jobs cached `~/go/bin`, others didn't; the cache key hashed the entire
`Makefile`. Centralising fixes both:

- **Cache key drift** — every job that installs tools now uses the
  same key, hashed from `scripts/tool-versions.txt`. Editing the
  Makefile no longer busts the cache.
- **Setup ceremony bloat** — net ~110 LOC removed from `ci.yml`.

See [docs/releasing.md "For Maintainers: CI Health"](../../../docs/releasing.md)
for the broader CI architecture.

## Pin freshness

The two third-party actions invoked here (`actions/setup-go`,
`actions/cache`) are pinned to full SHAs with version-tag comments per
repo policy. Dependabot's `github-actions` ecosystem entry rotates them
automatically.
