#!/usr/bin/env bash
# Creates and pushes annotated tags for every published module at a
# given commit SHA. Idempotent: a tag that already exists AT THE
# SAME SHA is skipped silently; a tag that exists at a different SHA
# aborts with a hard failure (a contamination needing human attention).
#
# Usage:
#   scripts/release/tag-all.sh <VERSION> <SHA>
#
# Reads the canonical module list from `make print-publish-modules`.
# Pushes in stable alphabetical-by-prefix order so partial-failure
# diagnostics are deterministic.
#
# Tagging is performed by the Go binary `release-tool create-tag`,
# which speaks the GitHub REST API directly with the release-bot App
# token. The binary path is read from $RELEASE_TOOL; CI sets it from
# the build step. For local invocation, leave it unset to use a
# PATH-resolved `release-tool`.
#
# Owner / repo are read from the env ($GH_OWNER, $GH_REPO) when set
# (the CI path), otherwise derived from `git remote get-url origin`
# (the recovery path: a clean checkout where the operator runs the
# script by hand).
#
# Partial-push behaviour: tags are pushed one at a time. A network
# failure mid-loop leaves a partial push set on origin — already-pushed
# tags are NOT rolled back (they cannot safely be; deletion does not
# unpublish from proxy.golang.org). On any failure the script emits a
# copy-paste recovery script to $GITHUB_STEP_SUMMARY (when set)
# listing the missing tags so the operator can finish the push from a
# clean checkout.
set -euo pipefail

readonly VERSION="${1:-}"
readonly SHA="${2:-}"

if [[ -z "$VERSION" || -z "$SHA" ]]; then
  echo "Usage: $0 <VERSION> <SHA>" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "tag-all: invalid version format: $VERSION" >&2
  exit 2
fi
if ! git cat-file -e "${SHA}^{commit}" 2>/dev/null; then
  echo "tag-all: SHA $SHA is not a known commit" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# PR-6 (#929): release-tool binary discovery. $RELEASE_TOOL is set
# explicitly by the workflow's build step. Locally, fall back to
# PATH (or the well-known build location).
release_tool="${RELEASE_TOOL:-release-tool}"
if ! command -v "$release_tool" >/dev/null 2>&1; then
  echo "tag-all: release-tool binary not found at '$release_tool'" >&2
  echo "tag-all: build it with: (cd cmd/release-tool && go build -trimpath -o /tmp/release-tool .)" >&2
  echo "tag-all: then re-run with RELEASE_TOOL=/tmp/release-tool" >&2
  exit 2
fi

# PR-6 (#929): owner/repo resolution. CI passes them via env; for
# local recovery, parse the origin remote URL. Supports HTTPS
# (`https://github.com/OWNER/REPO(.git)?`) and SSH
# (`git@github.com:OWNER/REPO(.git)?`) forms only. Everything else
# — http://, ssh://, embedded credentials, nested paths, trailing
# slashes, GitHub Enterprise hosts — exits 2 explicitly rather than
# silently mis-parsing. The strict `owner/repo` shape is validated
# at the end so a malformed origin can never inject an attacker-
# controlled owner segment into the App-signed tag-creation API
# call.
owner="${GH_OWNER:-}"
repo="${GH_REPO:-}"
if [[ -z "$owner" || -z "$repo" ]]; then
  remote_url="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$remote_url" ]]; then
    echo "tag-all: no GH_OWNER/GH_REPO env and no origin remote — cannot resolve repo" >&2
    exit 2
  fi
  # Strip optional trailing .git, then strip any trailing slash so
  # `https://github.com/OWNER/REPO/` doesn't yield repo="" (the
  # extglob `${pair##*/}` form would otherwise discard it).
  remote_url="${remote_url%.git}"
  remote_url="${remote_url%/}"
  case "$remote_url" in
    git@github.com:*)
      pair="${remote_url#git@github.com:}"
      ;;
    https://github.com/*)
      pair="${remote_url#https://github.com/}"
      ;;
    *)
      # http://github.com (downgraded), ssh://git@github.com/...
      # (URL form), https://user:token@github.com/... (embedded
      # credentials), GHE hosts, GitLab, Bitbucket — all rejected.
      # http:// is dropped because github.com always redirects to
      # https and an http origin is a security smell on a release
      # path.
      echo "tag-all: unsupported origin remote URL: $remote_url" >&2
      echo "tag-all: supported forms: https://github.com/OWNER/REPO[.git] or git@github.com:OWNER/REPO[.git]" >&2
      exit 2
      ;;
  esac
  # Strict shape check: exactly one '/', characters limited to the
  # set GitHub allows for owner / repo names. Catches nested paths
  # (group/sub/repo), empty segments (foo/, /bar), and shell
  # metacharacter smuggling attempts.
  if ! [[ "$pair" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "tag-all: origin URL produced malformed owner/repo: $pair" >&2
    exit 2
  fi
  owner="${pair%%/*}"
  repo="${pair##*/}"
fi
if [[ -z "$owner" || -z "$repo" ]]; then
  echo "tag-all: failed to resolve owner/repo from environment or origin" >&2
  exit 2
fi
readonly release_tool owner repo

# Up-to-date local refs so existing-tag detection is accurate.
git fetch --tags --quiet origin

modules="$(cd "$repo_root" && make -s --no-print-directory print-publish-modules | sort -t'|' -k3,3)"
if [[ -z "$modules" ]]; then
  echo "tag-all: 'make print-publish-modules' produced no output" >&2
  exit 2
fi

# Pre-flight: same conflict-check as the workflow's preflight job, in
# idempotent mode (existing tags at the target SHA are fine).
"$repo_root/scripts/release/check-tag-conflicts.sh" "$VERSION" "$SHA"

failed=()
remaining=()
skipped=()

while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  tag="${tag_prefix}${VERSION}"

  if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    existing_sha="$(git rev-list -n1 "$tag")"
    if [[ "$existing_sha" == "$SHA" ]]; then
      echo "tag-all: $tag already at $SHA — skipping (idempotent no-op)"
      skipped+=("$tag")
      continue
    fi
    echo "tag-all: $tag exists at $existing_sha but expected $SHA — ABORT" >&2
    failed+=("$tag")
    break
  fi

  remaining+=("$tag")
done <<<"$modules"

# Bail out early if the conflict pre-check found a SHA mismatch.
if (( ${#failed[@]} > 0 )); then
  exit 1
fi

# PR-6 (#929): create each tag via `release-tool create-tag` — one
# REST POST to create the annotated tag object, then one POST to
# point refs/tags/<tag> at it. The binary is App-signed end-to-end
# (release-bot identity), so required_signatures stays ON during a
# release. Failures are collected per-tag; operators see the full
# picture instead of fail-fast.
pushed=()
for tag in "${remaining[@]}"; do
  if "$release_tool" create-tag \
       --owner "$owner" \
       --repo "$repo" \
       --tag "$tag" \
       --sha "$SHA" \
       --message "Release $tag"; then
    pushed+=("$tag")
    echo "tag-all: created and pushed $tag"
  else
    echo "tag-all: failed to create $tag via release-tool" >&2
    failed+=("$tag")
  fi
done

if (( ${#failed[@]} > 0 )); then
  echo "" >&2
  echo "tag-all: ${#failed[@]} tag(s) failed: ${failed[*]}" >&2
  echo "DO NOT delete already-pushed tags." >&2
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo '## Tag-all partial failure'
      echo
      echo "Pushed (${#pushed[@]}):"
      for t in "${pushed[@]}"; do echo "- \`$t\` @ \`$SHA\`"; done
      echo
      echo "Failed (${#failed[@]}):"
      for t in "${failed[@]}"; do echo "- \`$t\`"; done
      echo
      echo '### Recovery'
      echo
      echo 'After investigating the cause, push the missing tags from a clean checkout at the same SHA.'
      echo 'The repository has `required_signatures` ON, so raw `git tag -a` + `git push` would fail —'
      echo 'use the App-signed `release-tool create-tag` binary (PR-6 #929):'
      echo
      echo '```bash'
      echo "git fetch origin"
      # PR-6 (#929) devops MAJOR-4 fix: pin the operator's working
      # tree to the merge SHA before building release-tool. Without
      # this the operator may build a stale binary from a dirty
      # local checkout.
      echo "git checkout --detach \"$SHA\" --"
      echo "(cd cmd/release-tool && go build -trimpath -o /tmp/release-tool .)"
      for t in "${failed[@]}"; do
        # PR-6 (#929): App-signed Go binary, not raw git/push —
        # required_signatures blocks the latter.
        echo "/tmp/release-tool create-tag --owner \"$owner\" --repo \"$repo\" --tag \"$t\" --sha \"$SHA\" --message \"Release $t\""
      done
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 1
fi

echo "tag-all: ${#pushed[@]} pushed, ${#skipped[@]} idempotent skips."
