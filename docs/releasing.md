[&larr; Back to README](../README.md)

# Releasing go-audit

- [How Go Module Publishing Works](#how-go-module-publishing-works)
- [For Maintainers: Cutting a Release](#for-maintainers-cutting-a-release)
- [For Maintainers: Verification Tools](#for-maintainers-verification-tools)
- [For Contributors](#for-contributors)
- [For Consumers](#for-consumers)

---

## How Go Module Publishing Works

### The Go Module Proxy

When a consumer runs `go get github.com/axonops/go-audit@v0.1.1`, the Go
toolchain contacts [proxy.golang.org](https://proxy.golang.org). The proxy
fetches and permanently caches the module source from GitHub at the exact
commit pointed to by that tag. The checksum is recorded in
[sum.golang.org](https://sum.golang.org) — a transparency log.

Two consequences follow directly from this:

- **A published tag is permanent.** Once a version is fetched through the
  proxy, it exists in the checksum database forever. Deleting or force-pushing
  a tag does not remove it from the proxy or the checksum log. Consumers who
  already fetched that version will get a checksum mismatch error if the tag
  is later changed. A tag that has been pushed MUST NOT be modified.

- **Publication is automatic.** There is no `go publish` command. Pushing a
  tag triggers indexing the next time any consumer (or the
  `publish-verify` workflow) requests that version. The proxy fetches from
  GitHub on demand.

[pkg.go.dev](https://pkg.go.dev) pulls its documentation from the same proxy.
It indexes asynchronously — expect up to 30 minutes after the first `go get`
before the documentation page appears.

### Multi-Module Tagging Scheme

This repository contains 10 Go modules. Each module has its own `go.mod` and
its own independent version history. The Go toolchain identifies module
versions by tag, using a path prefix for sub-modules:

| Module | Directory | Tag format | Tier |
|--------|-----------|------------|------|
| `github.com/axonops/go-audit` | `.` (root) | `vX.Y.Z` | 0 |
| `github.com/axonops/go-audit/secrets` | `secrets/` | `secrets/vX.Y.Z` | 0 |
| `github.com/axonops/go-audit/file` | `file/` | `file/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/syslog` | `syslog/` | `syslog/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/webhook` | `webhook/` | `webhook/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/loki` | `loki/` | `loki/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/cmd/audit-gen` | `cmd/audit-gen/` | `cmd/audit-gen/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/secrets/openbao` | `secrets/openbao/` | `secrets/openbao/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/secrets/vault` | `secrets/vault/` | `secrets/vault/vX.Y.Z` | 1 |
| `github.com/axonops/go-audit/outputconfig` | `outputconfig/` | `outputconfig/vX.Y.Z` | 2 |

### Three-Tier Tagging

Tags are created in three phases based on the inter-module dependency graph:

- **Tier 0** (core + secrets): no internal dependencies. Tagged at the
  CI-tested commit.
- **Tier 1** (file, syslog, webhook, loki, cmd/audit-gen, secrets/openbao,
  secrets/vault): depend on Tier 0 modules. Their `go.mod` files are updated
  to reference the Tier 0 release version, committed to `main`, then tagged
  at the new commit.
- **Tier 2** (outputconfig): depends on Tier 0 + Tier 1 modules. Its `go.mod`
  is updated after Tier 1 is indexed on the proxy, committed, then tagged.

This means Tier 0, Tier 1, and Tier 2 tags point at **three different commits**
on `main`. This is the standard Go multi-module release pattern — it ensures
external consumers who `go get` any sub-module receive `go.mod` files that
reference the correct release version of their dependencies.

### v0.x Stability Contract

This library is pre-release (`v0.x`). The Go module system treats v0 the same
as v1 for import paths — no `/v2` suffix is needed. However, v0.x releases
carry no API stability guarantee. Breaking changes MAY occur between minor
versions (`v0.1.x` → `v0.2.x`). Consumers MUST pin to a specific version:

```bash
go get github.com/axonops/go-audit@v0.1.1
```

The library will increment to v1.0.0 when the API is considered stable. At
that point the stability guarantees described in the
[Go module compatibility rules](https://go.dev/blog/module-compatibility) will
apply: no breaking changes within a major version.

### The "Never Modify a Published Tag" Rule

Once any of the 7 tags has been fetched through `proxy.golang.org` or recorded
in `sum.golang.org`, it is sealed. The constraint is absolute:

- Force-pushing a tag causes `go mod verify` to fail for every consumer who
  already fetched that version.
- Deleting a tag does not remove it from the proxy cache.
- Moving a tag to a different commit changes the source code the tag resolves
  to, which breaks the checksum verification for anyone who downloaded it.

If a release contains a serious bug, the correct response is:
1. Publish a new patch version with the fix.
2. Add a `retract` directive (see [Retracting a Bad Release](#retracting-a-bad-release)).

---

## For Maintainers: Cutting a Release

### Release Workflow Overview

Two GitHub Actions workflows handle the release pipeline:

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **Release** | `release.yml` | Manual (workflow_dispatch) | Runs full CI, creates tags, verifies proxy indexing, runs smoke test |
| **GoReleaser** | `goreleaser.yml` | Automatic (on `v*` tag push) | Builds binaries, SBOMs, creates GitHub Release |

**You only trigger `Release`.** It runs the entire pipeline end-to-end: CI → tags → proxy verification → smoke test. GoReleaser triggers automatically when the tags are pushed.

### Pre-Release Checklist

Complete every item before creating any tags. A partial or incorrect release
cannot be undone.

- [ ] CI is green on `main` — check the
      [CI workflow](https://github.com/axonops/go-audit/actions/workflows/ci.yml)
- [ ] `make check` passes locally with no errors or diffs
- [ ] No `replace` directives in any `go.mod` — `make check-replace` confirms this
- [ ] All inter-module dependencies reference the correct version. Each
      sub-module's `go.mod` MUST require `github.com/axonops/go-audit` at the
      version being released (or the most recent stable version if releasing
      only a subset of modules). Verify with:

      ```bash
      grep "axonops/go-audit" file/go.mod syslog/go.mod webhook/go.mod \
          loki/go.mod outputconfig/go.mod cmd/audit-gen/go.mod
      ```

- [ ] `CHANGELOG.md` updated — the `## [Unreleased]` section converted to
      `## [0.1.1] - 2026-01-01` (or the actual date)
- [ ] The version string is consistent across `CHANGELOG.md` and all tags you
      are about to create
- [ ] `go.sum` files are committed and up to date — `make tidy-check` passes

### Creating a Release

> **Warning:** Once tags are pushed, they are permanent. Complete the
> pre-release checklist before triggering the workflow.

Releases are created via the
[Release workflow](https://github.com/axonops/go-audit/actions/workflows/release.yml).
**Do not create tags manually** — the workflow runs the full CI pipeline
(unit tests, BDD, integration, lint, security) and only creates tags
after everything passes.

1. Go to **Actions → Release → Run workflow**
2. Enter the version string (e.g. `v0.1.1`)
3. Click **Run workflow**

The workflow will:
1. Run the entire CI pipeline (same as a PR check — all tests, all modules)
2. Validate the version format and confirm HEAD is on `main`
3. Verify no tags already exist for this version
4. Create annotated tags for all 7 modules at HEAD
5. Push all tags — the `v*` root tag triggers `release.yml` (GoReleaser) automatically

If you need to test the workflow without burning a real version number,
use a pre-release tag like `v0.1.1-alpha.1` or `v0.1.1-rc.1`.

### After the Release

The `release.yml` workflow handles everything end-to-end: after creating
tags, it automatically verifies proxy indexing, checksums, and runs a
smoke test. Monitor the workflow run for the final status.

`goreleaser.yml` runs in parallel (triggered by the `v*` tag push) and
creates the GitHub Release with binaries, checksums, and SBOMs. Monitor at:
[Actions → GoReleaser](https://github.com/axonops/go-audit/actions/workflows/goreleaser.yml)

Optionally verify locally:

```bash
make publish-verify VERSION=v0.1.1
make publish-smoke  VERSION=v0.1.1
```

### First Release: v0.1.1

The first release for this repository is `v0.1.1`. Version `v0.1.0` was
skipped because `loki/v0.1.0` was already sealed in the Go checksum database
before the loki module was ready to publish. Using `v0.1.1` as the first
coordinated release across all modules avoids a version mismatch where `loki`
appears to have a `v0.1.0` that predates the rest of the library.

No `retract` directive is required for `loki/v0.1.0` in the loki module's
`go.mod` because that version was never published with importable code — it
was sealed at a commit that did not contain the `loki` directory's current
code. If consumers report resolution issues with `loki/v0.1.0`, add:

```go
// loki/go.mod
retract v0.1.0 // sealed in sum DB before module was complete; use v0.1.1
```

### Retracting a Bad Release

If a published release contains a serious bug or security vulnerability,
publish a fix as a new version and add a `retract` directive. The retraction
MUST be in the module's `go.mod`, and the retraction itself MUST be released
as a new version for the Go toolchain to surface the warning to consumers.

Example — retracting `v0.1.1` from the core module after publishing `v0.1.2`:

```go
// go.mod
module github.com/axonops/go-audit

go 1.26.2

retract v0.1.1 // contains data loss bug in drain loop; use v0.1.2
```

The retraction comment is displayed by `go get` and `go list` when a consumer
has the retracted version. It MUST explain why the version was retracted and
what version to use instead.

Each affected module MUST have its own `retract` directive — retraction is
per-module, not repository-wide.

---

## For Maintainers: Verification Tools

### The Release Workflow

The [Release workflow](../.github/workflows/release.yml) handles the
entire release pipeline end-to-end. It is triggered manually via
`workflow_dispatch` with a single `version` input.

**What it does, in order:**

1. Runs the full CI pipeline (every test, lint, security check)
2. Validates version format and confirms HEAD is on `main`
3. Creates annotated tags for all 7 modules and pushes them
4. Triggers `proxy.golang.org` indexing for all modules
5. Verifies proxy serves `.info` for each module
6. Verifies checksums via `go mod download`
7. Runs a smoke test (`go get` + compile + install audit-gen)

If any step fails, the workflow stops. Tags that were already pushed
cannot be undone — see [Retracting a Bad Release](#retracting-a-bad-release).

### Makefile Targets

These targets run locally for manual verification:

```bash
# Trigger proxy.golang.org indexing for a version
make publish-trigger VERSION=v0.1.1

# Verify proxy.golang.org and pkg.go.dev for a version
make publish-verify VERSION=v0.1.1

# Smoke test: go get + compile all modules for a version
make publish-smoke VERSION=v0.1.1
```

`publish-trigger` calls `go list -m` against `GOPROXY=https://proxy.golang.org`
for each module. This is the same operation that a consumer's first `go get`
performs — it forces the proxy to fetch and cache the module from GitHub.

`publish-verify` checks the `.info` endpoint on `proxy.golang.org` and the
HTTP status of `pkg.go.dev` for each module. It does not fail on a non-200
from `pkg.go.dev` — use it as a quick sanity check, not a gate.

`publish-smoke` creates a temporary module in `$(mktemp -d)`, installs all
7 modules at the specified version, compiles a program that imports all of
them, and installs `audit-gen`. This is the closest local equivalent to
"does this release actually work for a consumer."

---

## For Contributors

Contributors do not cut releases. This section explains how Go module
publishing works so that contributor actions (tags, `go.mod` changes) do not
accidentally interfere with the release process.

### How a Consumer Gets Your Code

When a consumer runs `go get github.com/axonops/go-audit@v0.1.1`:

1. The Go toolchain asks `proxy.golang.org` for the module at that version.
2. The proxy fetches the source from GitHub at the commit pointed to by the
   `v0.1.1` tag, if it has not already cached it.
3. The proxy records the module hash in `sum.golang.org`.
4. The source is extracted into the consumer's module cache.
5. The consumer's `go.sum` is updated with the verified hash.

The proxy caches the module permanently. If the tag is later deleted or moved,
consumers who already fetched it are unaffected — they get the same bytes
from the proxy cache. New consumers would get an error (tag not found on
GitHub), but the proxy cache would still serve the old bytes for existing
`go.sum` entries.

### What Contributors MUST NOT Do

- **Do not create release tags.** Tags matching `v*`, `file/v*`, `syslog/v*`,
  `webhook/v*`, `loki/v*`, `outputconfig/v*`, or `cmd/audit-gen/v*` are
  protected on `main` and can only be created by maintainers.
- **Do not add `replace` directives to `go.mod` on any branch intended for
  merge.** `replace` directives in published modules break consumer builds.
  `make check-replace` enforces this in CI.
- **Do not modify `go.mod` to point inter-module dependencies at local paths.**
  Use `make workspace` to create a `go.work` file for local development — it is
  gitignored and does not affect the published modules.

### Inter-Module Dependencies

Each sub-module depends on `github.com/axonops/go-audit` (the core module).
During development, `go.work` resolves these to your local checkout. In
published modules, the `go.mod` MUST reference a released version of the
core module — there is no `replace` directive in the committed `go.mod`.

Before a release, maintainers update each sub-module's `go.mod` to reference
the correct core version. Contributors do not need to manage this — just
ensure `make check` passes on your branch.

---

## For Consumers

### Installing Modules

Requires **Go 1.26.2+**.

Install only the modules you need. The core module provides the logger,
taxonomy validation, formatters, stdout output, HTTP middleware, and the
`audittest` testing package. Output modules are separate to keep the core
dependency footprint minimal.

```bash
# Core (always required)
go get github.com/axonops/go-audit@v0.1.1

# Output modules — install only what you use
go get github.com/axonops/go-audit/file@v0.1.1         # file output with rotation
go get github.com/axonops/go-audit/syslog@v0.1.1       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/go-audit/webhook@v0.1.1      # batched HTTP webhook
go get github.com/axonops/go-audit/loki@v0.1.1         # Grafana Loki
go get github.com/axonops/go-audit/outputconfig@v0.1.1 # YAML-based output configuration

# Code generator (dev/build tooling, not a runtime dependency)
go get github.com/axonops/go-audit/cmd/audit-gen@v0.1.1
```

Each module is versioned independently. You MUST use the same version across
all modules you install — mixing versions (e.g. core at `v0.1.1` and syslog
at `v0.2.0`) is unsupported and may cause compile errors or unexpected
behaviour.

### Version Pinning

This library is pre-release (v0.x). The API MAY change between minor
versions. Pin to an exact version in your `go.mod`:

```bash
go get github.com/axonops/go-audit@v0.1.1
```

Do not use `@latest` in production `go.mod` files — a new minor release may
introduce breaking changes.

### Verifying Your Install

After installation, verify the checksums against the transparency log:

```bash
go mod verify
```

This confirms that the module source in your local cache has not been tampered
with. It checks against the hashes recorded in your `go.sum`, which were
verified against `sum.golang.org` when the module was first downloaded.

### Verifying Release Artifacts

Every release binary and SBOM has a GitHub
[build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
that cryptographically proves it was built by the go-audit CI pipeline.
Verify any downloaded artifact with:

```bash
gh attestation verify audit-gen_linux_amd64.tar.gz --repo axonops/go-audit
```

This confirms the artifact was built by GitHub Actions from the axonops/go-audit
repository at the tagged commit. No keys or additional tools are needed — the
`gh` CLI handles everything via GitHub's Sigstore-based transparency log.

### SBOM

Every GitHub Release includes SBOMs in both CycloneDX and SPDX formats,
generated by GoReleaser using [syft](https://github.com/anchore/syft). They
are attached to the release as assets named `sbom.cdx.json` and
`sbom.spdx.json`.

Download them from the
[Releases page](https://github.com/axonops/go-audit/releases) or via the
GitHub CLI:

```bash
gh release download v0.1.1 --pattern "sbom.*" --repo axonops/go-audit
```

The SBOMs cover the compiled binaries produced by GoReleaser (including
`audit-gen`). For the full transitive dependency graph of a specific module,
use `go mod graph` or generate your own SBOM with syft against your built
binary.
