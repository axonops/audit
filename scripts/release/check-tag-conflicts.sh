#!/usr/bin/env bash
# Pre-flight tag-conflict check for the release workflow.
#
# Usage:
#   scripts/release/check-tag-conflicts.sh <VERSION>
#       Strict mode — aborts if ANY tag in the published-module set
#       already exists for VERSION. Used by the workflow_dispatch path
#       before opening the release PR.
#
#   scripts/release/check-tag-conflicts.sh <VERSION> <EXPECTED_SHA>
#       Idempotent mode — tags that already exist AT EXPECTED_SHA are
#       fine; tags at a different SHA cause a hard failure. Used by
#       the v* tag-push recovery path and by `tag-all` re-checks.
#
# Reads the canonical published-module list from `make
# print-publish-modules` rather than re-encoding the list locally.
set -euo pipefail

readonly VERSION="${1:-}"
readonly EXPECTED_SHA="${2:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <VERSION> [<EXPECTED_SHA>]" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "check-tag-conflicts: invalid version format: $VERSION" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Modules in stable alphabetical-by-prefix order so the failure
# diagnostic is deterministic.
modules="$(cd "$repo_root" && make -s --no-print-directory print-publish-modules | sort -t'|' -k3,3)"
if [[ -z "$modules" ]]; then
  echo "check-tag-conflicts: 'make print-publish-modules' produced no output" >&2
  exit 2
fi

# Make sure local refs are up to date so we don't false-positive on
# tags that exist on origin but not locally.
git fetch --tags --quiet origin

abort=0
while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  tag="${tag_prefix}${VERSION}"
  if ! git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    # Tag does not exist — fine.
    continue
  fi
  existing_sha="$(git rev-list -n1 "$tag")"
  if [[ -z "$EXPECTED_SHA" ]]; then
    # Strict mode: any existing tag is a hard failure.
    echo "check-tag-conflicts: tag $tag already exists at $existing_sha" >&2
    abort=1
    continue
  fi
  if [[ "$existing_sha" != "$EXPECTED_SHA" ]]; then
    echo "check-tag-conflicts: tag $tag exists at $existing_sha but expected $EXPECTED_SHA" >&2
    echo "  This is a permanent contamination. The fix is to release a new patch" >&2
    echo "  version and retract this one — see docs/releasing.md." >&2
    abort=1
  fi
  # Idempotent mode + matching SHA: silent no-op.
done <<<"$modules"

if [[ "$abort" -eq 1 ]]; then
  exit 1
fi
echo "check-tag-conflicts: no conflicts."
