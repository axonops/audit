[&larr; Back to README](../README.md)

# Releasing audit

- [How Go Module Publishing Works](#how-go-module-publishing-works)
- [For Maintainers: Cutting a Release](#for-maintainers-cutting-a-release)
- [For Maintainers: Verification Tools](#for-maintainers-verification-tools)
- [For Maintainers: CI Health](#for-maintainers-ci-health)
- [For Contributors](#for-contributors)
- [For Consumers](#for-consumers)

---

## How Go Module Publishing Works

### The Go Module Proxy

When a consumer runs `go get github.com/axonops/audit@v0.1.1`, the Go
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
| `github.com/axonops/audit` | `.` (root) | `vX.Y.Z` | 0 |
| `github.com/axonops/audit/secrets` | `secrets/` | `secrets/vX.Y.Z` | 0 |
| `github.com/axonops/audit/file` | `file/` | `file/vX.Y.Z` | 1 |
| `github.com/axonops/audit/syslog` | `syslog/` | `syslog/vX.Y.Z` | 1 |
| `github.com/axonops/audit/webhook` | `webhook/` | `webhook/vX.Y.Z` | 1 |
| `github.com/axonops/audit/loki` | `loki/` | `loki/vX.Y.Z` | 1 |
| `github.com/axonops/audit/cmd/audit-gen` | `cmd/audit-gen/` | `cmd/audit-gen/vX.Y.Z` | 1 |
| `github.com/axonops/audit/secrets/openbao` | `secrets/openbao/` | `secrets/openbao/vX.Y.Z` | 1 |
| `github.com/axonops/audit/secrets/vault` | `secrets/vault/` | `secrets/vault/vX.Y.Z` | 1 |
| `github.com/axonops/audit/outputconfig` | `outputconfig/` | `outputconfig/vX.Y.Z` | 2 |

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
go get github.com/axonops/audit@v0.1.1
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

## For Maintainers: Repository Protection Configuration

The repository's release contract depends on three layers of GitHub
configuration. Two of them — branch protection and tag protection —
are GitHub UI settings, not committed files. Maintainers MUST verify
these are configured before the v1.0.0 release, and on every
subsequent maintainer onboarding.

### CODEOWNERS (committed)

`.github/CODEOWNERS` declares review-required ownership for every
security-sensitive surface — `.github/workflows/`, `.goreleaser.yml`,
every `go.mod` / `go.sum`, `Makefile`, `SECURITY.md`,
`docs/threat-model.md`, `docs/releasing.md`, `docs/deployment.md`,
and the cryptographic primitives (`hmac.go`, `ssrf*.go`,
`tls_policy.go`, `secrets/`). The catch-all `*` rule assigns the
maintainer team as default reviewer for every other path so no PR
merges without a maintainer's approval.

### Branch protection on `main`

Configure in **Settings → Branches → Add rule** (or **Edit** an
existing rule for `main`). Required settings:

| Setting | Value | Why |
|---|---|---|
| Branch name pattern | `main` | Protects the release branch. |
| Require a pull request before merging | ✓ | No direct commits. |
| Require approvals | ✓ — at least **1** approving review | Two-eyes review on every change. |
| Dismiss stale pull request approvals when new commits are pushed | ✓ | Reset reviews on rebase / amend. |
| Require review from Code Owners | ✓ | Enforces `.github/CODEOWNERS`. |
| Require status checks to pass before merging | ✓ | Block on CI. |
| Require branches to be up to date before merging | ✓ | Re-run CI on the merge target. |
| Required status check | `CI Pass` | Aggregate gate from `.github/workflows/ci.yml`. |
| Require conversation resolution before merging | ✓ | All review comments resolved. |
| Require signed commits | ✓ | Cryptographic provenance for every commit on `main`. |
| Require linear history | ✓ | Squash or rebase only — no merge commits. |
| Include administrators | ✓ | Maintainers cannot bypass. |
| Allow force pushes | ✗ (disabled) | Permanent history. |
| Allow deletions | ✗ (disabled) | `main` cannot be deleted. |
| Restrict who can push to matching branches | enabled, allowed actors empty | Closes the "PR-required, but anyone with write access can still push directly" loophole. The empty allow-list means even maintainers must go through a PR. |
| Allow specified actors to bypass required pull requests | empty | No bypass. The "Include administrators" toggle above already covers admin enforcement; this row makes it explicit that no individual / team / app is on a bypass list. |
| Lock branch | ✗ (disabled) | A locked branch refuses every write — only used during a freeze. Default off. |

For changes touching cryptographic primitives (`hmac.go`,
`tls_policy.go`, `secrets/`) GitHub does not currently support
per-path approval counts; the 1-approval floor above is the global
minimum. CODEOWNERS still routes the review to the maintainer team,
and reviewers SHOULD pull a second maintainer in for crypto changes
even though the gate does not enforce it.

After saving, push a small test PR (e.g. a typo fix) from a fork or
feature branch and verify the merge button is disabled until the
status check passes and an approving review is recorded.

### Tag protection — every release prefix

Configure in **Settings → Tags → New rule**. GitHub matches the
pattern against the FULL tag name (not the basename), so the core
module pattern `v*` does NOT cover sub-module tags like
`file/v1.0.0`. Add one rule per release prefix in the repository:

| Setting | Value | Covers |
|---|---|---|
| Tag name pattern | `v*` | Core module: `v1.0.0`, `v1.1.0-rc.1`, etc. |
| Tag name pattern | `file/v*` | `file` sub-module. |
| Tag name pattern | `syslog/v*` | `syslog` sub-module. |
| Tag name pattern | `webhook/v*` | `webhook` sub-module. |
| Tag name pattern | `loki/v*` | `loki` sub-module. |
| Tag name pattern | `outputconfig/v*` | `outputconfig` sub-module. |
| Tag name pattern | `outputs/v*` | `outputs` convenience-package sub-module. |
| Tag name pattern | `secrets/v*` | `secrets` parent sub-module. |
| Tag name pattern | `secrets/openbao/v*` | `secrets/openbao` provider sub-module. |
| Tag name pattern | `secrets/vault/v*` | `secrets/vault` provider sub-module. |
| Tag name pattern | `cmd/audit-gen/v*` | `audit-gen` CLI sub-module. |
| Tag name pattern | `cmd/audit-validate/v*` | `audit-validate` CLI sub-module. |
| Tag name pattern | `iouring/v*` | `iouring` sub-module. |

GitHub's tag-protection rule restricts tag creation to repository
maintainers. A pushed tag is the trigger for the release workflow
(GoReleaser, Cosign signing), so this rule is what prevents an
unauthorised actor from triggering a release pipeline. **Without
the per-sub-module entries, anyone with write access can publish a
sub-module release.**

Add a new rule whenever the repository gains another sub-module
that releases independently. Audit the live tag-protection set on
every maintainer onboarding (see verification snippet below).

### Verification checklist (every release cycle)

```bash
# 1. CODEOWNERS file present and parseable.
test -f .github/CODEOWNERS && \
  gh api repos/:owner/:repo/codeowners/errors --jq '.errors | length' \
    | grep -qx 0 || echo "ERROR: CODEOWNERS has parse errors"

# 2. Branch protection enforces required checks.
gh api repos/:owner/:repo/branches/main/protection --jq '
  {
    require_signed: .required_signatures.enabled,
    require_linear: .required_linear_history.enabled,
    require_codeowner_review: .required_pull_request_reviews.require_code_owner_reviews,
    required_check: (.required_status_checks.contexts // []) | join(","),
    allow_force: .allow_force_pushes.enabled,
    allow_delete: .allow_deletions.enabled
  }'
# Expect: require_signed=true, require_linear=true,
# require_codeowner_review=true, required_check contains "CI Pass",
# allow_force=false, allow_delete=false.

# 3. Tag-protection rules — every release prefix.
gh api repos/:owner/:repo/tags/protection --jq '.[] | .pattern' | sort
# Expect (one per line):
#   cmd/audit-gen/v*
#   cmd/audit-validate/v*
#   file/v*
#   iouring/v*
#   loki/v*
#   outputconfig/v*
#   outputs/v*
#   secrets/openbao/v*
#   secrets/v*
#   secrets/vault/v*
#   syslog/v*
#   v*
#   webhook/v*
# A 404 / empty response means NO tag-protection rules exist —
# anyone with write access can publish a release. Configure the
# rules in Settings → Tags → New rule before promoting.
```

If any of the three checks reports an unexpected value, fix the
configuration in the UI before tagging the release.

---

## For Maintainers: Cutting a Release

### Release Workflow Overview

One GitHub Actions workflow handles the entire release pipeline:

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **Release** | `release.yml` | Manual (workflow_dispatch) | Runs full CI, creates tags, builds binaries + GitHub Release, verifies proxy, runs smoke test |
| **GoReleaser** | `goreleaser.yml` | Manual re-run only | Re-runs GoReleaser if the goreleaser job in release.yml failed |

**You only trigger `Release`.** It runs the entire pipeline end-to-end: CI → tags → GoReleaser (binaries, build-provenance attestations, GitHub Release) → proxy verification → smoke test. The workflow does not report success until the GitHub Release exists.

### Pre-Release Checklist

Complete every item before creating any tags. A partial or incorrect release
cannot be undone.

- [ ] CI is green on `main` — check the
      [CI workflow](https://github.com/axonops/audit/actions/workflows/ci.yml)
- [ ] `make check` passes locally with no errors or diffs
- [ ] No `replace` directives in any `go.mod` — `make check-replace` confirms this
- [ ] All inter-module dependencies reference the correct version. Each
      sub-module's `go.mod` MUST require `github.com/axonops/audit` at the
      version being released (or the most recent stable version if releasing
      only a subset of modules). Verify with:

      ```bash
      grep "axonops/audit" file/go.mod syslog/go.mod webhook/go.mod \
          loki/go.mod outputconfig/go.mod cmd/audit-gen/go.mod
      ```

- [ ] `CHANGELOG.md` updated — the `## [Unreleased]` section converted to
      `## [0.1.1] - 2026-01-01` (or the actual date)
- [ ] The version string is consistent across `CHANGELOG.md` and all tags you
      are about to create
- [ ] `go.sum` files are committed and up to date — `make tidy-check` passes
- [ ] `bench-baseline.txt` is fresh — regenerate it whenever a benchmark is
      renamed, a hot-path change lands, or before any milestone release.
      The release workflow runs `make bench-compare` as an advisory step
      (see "Benchmark regression report" in the GitHub Actions summary) —
      stale names silently break the column pairing and the report
      becomes uninformative. Regenerate with:

      ```bash
      # On consistent hardware — GitHub-hosted runners are too noisy.
      make bench-save
      git add bench-baseline.txt BENCHMARKS.md
      git commit -m "chore: refresh bench-baseline.txt ahead of vX.Y.Z"
      ```

      `make bench-baseline-check` (part of `make check`) rejects a PR
      that introduces a benchmark name to `bench-baseline.txt` that no
      longer exists in the source tree — catching renames at lint time.

### Creating a Release

> **Warning:** Once tags are pushed, they are permanent. Complete the
> pre-release checklist before triggering the workflow.

Releases are created via the
[Release workflow](https://github.com/axonops/audit/actions/workflows/release.yml).
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
5. Push all tags and run GoReleaser to build binaries and create the GitHub Release

If you need to test the workflow without burning a real version number,
use a pre-release tag like `v0.1.1-alpha.1` or `v0.1.1-rc.1`.

### After the Release

The `release.yml` workflow handles everything end-to-end: CI, tagging,
GoReleaser (binaries, build-provenance attestations, GitHub Release),
proxy verification, and smoke test. Monitor the single workflow run for
the final status.

If the GoReleaser step fails but tags were already pushed, re-run it
manually via [Actions → GoReleaser](https://github.com/axonops/audit/actions/workflows/goreleaser.yml)
on the `v*` tag ref.

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
module github.com/axonops/audit

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

## For Maintainers: CI Health

CI is only useful if it reports real failures as failures. Defence in depth:
the test layer must fail loudly, AND every workflow step must propagate that
failure out of the shell pipeline into the job result.

### Job dependency graph

Post-#759 the CI workflow is structured for fail-fast and parallelism:

```
                   ┌─────────┐
                   │ changes │
                   └────┬────┘
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
  ┌──────────┐  ┌─────────────┐  ┌──────────────┐
  │ hygiene  │  │ validate-   │  │ dep-review   │
  │(8 checks)│  │  release    │  │  (PR only)   │
  └────┬─────┘  └─────────────┘  └──────────────┘
       │
       ├──────┬──────┬───────────┬──────────┬─────────┬─────────┬───────────────┐
       ▼      ▼      ▼           ▼          ▼         ▼         ▼               ▼
   ┌─────┐ ┌────┐ ┌─────────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌─────────┐ ┌──────────────┐
   │lint │ │test│ │integ-   │ │security│ │security│ │cross-│ │examples-│ │   (etc.)     │
   │     │ │x11 │ │ration   │ │  x13   │ │ verify │ │build │ │ build   │ └──────────────┘
   └─────┘ └─┬──┘ └─────────┘ └────────┘ └────────┘ └──────┘ └─────────┘
             │
             ├──────────────┐
             ▼              ▼
        ┌──────┐  ┌──────────────────┐
        │bdd x8│  │ test-cross-      │
        └──┬───┘  │ platform x4      │
           │      │ (mac + win)      │
           ▼      └──────────────────┘
     ┌────────────┐
     │ bdd-verify │
     └────────────┘

(All roll up into ci-pass, the single aggregate gate.)
```

Hygiene is the single fan-out point: all subsequent jobs gate on it.
Cross-platform tests and BDD gate on test (Linux unit suite must pass
before macOS/Windows shards or BDD shards consume runner-minutes).

The hygiene job runs `make check-static`, which aggregates eight static
guards (`fmt-check`, `tidy-check`, `check-todos`, `check-replace`,
`check-insecure-skip-verify`, `check-example-links`, `check-bdd-strict`,
`bench-baseline-check`) in a `||`-guarded loop so every failure
surfaces on a single push rather than aborting on the first. Developers
running `make check-static` locally see the same one-shot summary.

The CI setup ceremony (Go install, workspace init, optional tool
install) lives in `.github/actions/setup-audit/` as a composite
action — every job consumes it via `uses: ./.github/actions/setup-audit`.
The cache key hashes `scripts/tool-versions.txt` so version bumps are
the only thing that invalidate the cache.



### The pipefail bug class

GitHub Actions `run:` blocks execute bash without `set -o pipefail` by default.
When a step uses a pipeline like `make test | tee output.txt`, the pipeline's
exit status is `tee`'s (always 0), not `make`'s. A failing test suite can
therefore exit the step with status 0 and the job is marked `success` even
though the tests failed.

Issue #622 fixed this for the BDD step in `ci.yml`; the rule applies to every
workflow step that uses a pipeline. Every `run:` block that contains `|` must
either:

- Set `set -eo pipefail` at the top of the block, or
- Not use a pipeline.

### Proving the mechanism

The bug class is reproducible in five seconds without touching CI:

```bash
# Without pipefail: tee's zero exit masks false's non-zero exit.
$ bash -c 'false | tee /dev/null'; echo "outer exit: $?"
outer exit: 0

# With pipefail: false's exit propagates out of the subshell.
$ bash -c 'set -eo pipefail; false | tee /dev/null'; echo "outer exit: $?"
outer exit: 1
```

### Verifying CI is honest end-to-end

After any change to workflow steps that run tests, verify the gate is real:

1. Create a disposable branch, capturing the name once:

   ```bash
   BRANCH="verify/ci-pipefail-$(date +%Y%m%d-%H%M%S)"
   git checkout -b "$BRANCH"
   ```

2. Introduce a deliberate test failure — smallest recipe is to add an
   undefined step reference in a BDD feature file:

   ```gherkin
   # Append to any scenario in tests/bdd/features/core_audit.feature
   And an intentionally undefined canary step
   ```

3. Commit, push, and open a draft PR.
4. Confirm the relevant CI job (e.g. `BDD (core)`) reports `failure`. The
   check row in the PR UI shows a red `X`, not a green check.
5. Close the PR without merging and delete the branch:

   ```bash
   git push origin --delete "$BRANCH"
   git checkout main
   git branch -D "$BRANCH"
   ```

This verifies not just the pipefail mechanism but the entire chain from test
exit code through step status through job status through PR check status. Run
it when modifying any test-execution step in `.github/workflows/`.

### OpenSSF Scorecard

The OSSF Scorecard workflow (`.github/workflows/scorecard.yml`) runs weekly on
Monday at 08:00 UTC, on every push to `main`, and whenever a branch-protection
rule is created or modified. It scores the repository against the OpenSSF
supply-chain checks (Branch-Protection, Code-Review, SAST, Pinned-Dependencies,
Token-Permissions, Vulnerabilities, etc.).

Results are uploaded as SARIF to the GitHub **Security** tab and published to
the OpenSSF public dashboard at
<https://securityscorecards.dev/viewer/?uri=github.com/axonops/audit>. The
README badge links to that dashboard.

**If the score drops between runs:**

1. Open the latest workflow run, download the `scorecard-sarif` artifact, and
   read the per-check findings.
2. Cross-reference with the GitHub **Security** tab — each finding includes
   the file path and remediation guidance.
3. File a tracking issue (labels `security`, `ci/cd`) for any regression that
   is not a transient false positive.
4. Common drift causes: a new workflow added without
   `permissions: contents: read` at the top level; an action referenced by tag
   rather than full SHA; a dependency pin bumped to a vulnerable version
   (`govulncheck` will flag this independently in `security-scan.yml`).
5. The **Pinned-Dependencies** check is the one most often dragged down by
   GitHub-Actions updates that land as tag-pinned PRs from Dependabot — they
   should be edited to a full SHA before merge, matching the convention used
   throughout `.github/workflows/`.

A score drop on **Pinned-Dependencies** or **Vulnerabilities** MUST be
resolved before the next release — these checks measure supply-chain
integrity and CVE exposure directly. Drops on other checks
(Branch-Protection, Code-Review, SAST, Token-Permissions) SHOULD be
resolved within one release cycle. File a tracking issue (labels
`security`, `ci/cd`) for every unresolved regression before tagging.

---

## For Contributors

Contributors do not cut releases. This section explains how Go module
publishing works so that contributor actions (tags, `go.mod` changes) do not
accidentally interfere with the release process.

### How a Consumer Gets Your Code

When a consumer runs `go get github.com/axonops/audit@v0.1.1`:

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

Each sub-module depends on `github.com/axonops/audit` (the core module).
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

Install only the modules you need. The core module provides the auditor,
taxonomy validation, formatters, stdout output, HTTP middleware, and the
`audittest` testing package. Output modules are separate to keep the core
dependency footprint minimal.

```bash
# Core (always required)
go get github.com/axonops/audit@v0.1.1

# Output modules — install only what you use
go get github.com/axonops/audit/file@v0.1.1         # file output with rotation
go get github.com/axonops/audit/syslog@v0.1.1       # RFC 5424 syslog (TCP/UDP/TLS/mTLS)
go get github.com/axonops/audit/webhook@v0.1.1      # batched HTTP webhook
go get github.com/axonops/audit/loki@v0.1.1         # Grafana Loki
go get github.com/axonops/audit/outputconfig@v0.1.1 # YAML-based output configuration

# Code generator (dev/build tooling, not a runtime dependency)
go get github.com/axonops/audit/cmd/audit-gen@v0.1.1
```

Each module is versioned independently. You MUST use the same version across
all modules you install — mixing versions (e.g. core at `v0.1.1` and syslog
at `v0.2.0`) is unsupported and may cause compile errors or unexpected
behaviour.

### Version Pinning

This library is pre-release (v0.x). The API MAY change between minor
versions. Pin to an exact version in your `go.mod`:

```bash
go get github.com/axonops/audit@v0.1.1
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

Every release artifact has a GitHub
[build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
that cryptographically proves it was built by the audit CI pipeline.
Verify any downloaded artifact with:

```bash
gh attestation verify audit-gen_linux_amd64.tar.gz --repo axonops/audit
```

This confirms the artifact was built by GitHub Actions from the axonops/audit
repository at the tagged commit. No keys or additional tools are needed — the
`gh` CLI handles everything via GitHub's Sigstore-based transparency log.

### Software Bill of Materials (SBOM)

This project does **not** publish SBOMs as release artifacts. Rationale (#514):

- **For library consumers**: the canonical dependency manifest is `go.mod`,
  delivered alongside the library via the Go module proxy
  (`proxy.golang.org`). `go mod graph`, `go mod verify`, and the checksum
  database (`sum.golang.org`) provide stronger guarantees than a published
  SBOM would for a Go library.
- **For binary consumers** (operators downloading `audit-gen` or
  `audit-validate` from the GitHub Releases page): build provenance is
  attested per-artifact via GitHub build attestations (above). For an SBOM
  of the binary, scan it locally with [syft](https://github.com/anchore/syft):

  ```bash
  gh release download v0.1.1 --pattern 'audit-gen_*_linux_amd64.tar.gz' --repo axonops/audit
  tar -xzf audit-gen_*_linux_amd64.tar.gz
  syft scan ./audit-gen --output cyclonedx-json > audit-gen.cdx.json
  syft scan ./audit-gen --output spdx-json     > audit-gen.spdx.json
  ```

  syft will produce the same SBOM the project would have published, derived
  directly from the binary you're going to run.

For development convenience, `make sbom` produces a source-level SBOM in
both CycloneDX and SPDX formats inside `sbom/` — useful for inspecting
the project's own dependency graph but not a release artifact.
