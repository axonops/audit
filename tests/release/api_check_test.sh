#!/usr/bin/env bash
# Smoke test for `make api-check` / gorelease integration.
#
# Strategy: clone the current HEAD into a throwaway git worktree,
# inject a deliberate breaking API change into a stable submodule
# (secrets/openbao Provider — narrow public surface, well-tagged),
# run gorelease against the most recent release tag, and assert
# the report flags the breakage.
#
# Using a worktree (rather than mutating the live tree with a trap)
# eliminates the corruption window: even a kill -9 mid-test cannot
# leave the developer's tree dirty.
#
# Exit codes:
#   0 — gorelease correctly flagged the injected breakage
#   1 — gorelease did NOT flag the breakage (api-check pipeline regressed)
#   2 — test setup failed (no prior tag, gorelease missing, etc.)
set -euo pipefail

readonly TARGET_MODULE_DIR="secrets/openbao"
readonly TARGET_TAG_PREFIX="secrets/openbao/"
readonly TARGET_FILE_REL="openbao.go"
readonly EXPECTED_BREAKAGE_PATTERN="incompatible"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

if ! command -v gorelease >/dev/null 2>&1; then
  if [[ -x "$(go env GOPATH)/bin/gorelease" ]]; then
    PATH="$(go env GOPATH)/bin:$PATH"
    export PATH
  else
    echo "api_check_test: gorelease not on PATH. Run 'make install-tools' first." >&2
    exit 2
  fi
fi

# Find the most recent SemVer tag for the target module.
base_tag="$(git tag --list "${TARGET_TAG_PREFIX}v*" --sort=-version:refname | head -n1)"
if [[ -z "$base_tag" ]]; then
  echo "api_check_test: no prior tag matching ${TARGET_TAG_PREFIX}v* — cannot test gorelease against an empty base." >&2
  exit 2
fi
# gorelease's -base flag wants the bare semver — when run from inside
# the sub-module's directory, the path prefix is implicit.
base_version="${base_tag#$TARGET_TAG_PREFIX}"
echo "api_check_test: base tag = $base_tag (bare = $base_version)"

# Sanity-check the target file exists.
target_file_abs="$repo_root/$TARGET_MODULE_DIR/$TARGET_FILE_REL"
if [[ ! -f "$target_file_abs" ]]; then
  echo "api_check_test: target file missing: $target_file_abs" >&2
  echo "api_check_test: this fixture must be updated to point at a current source file." >&2
  exit 2
fi

# Find an exported function definition in the target file that takes
# at least one argument — we'll inject a breakage by adding a parameter.
# Using sed + grep so this fixture has no external dependencies.
exported_func="$(grep -E '^func \([^)]+\) [A-Z][A-Za-z0-9_]+\(' "$target_file_abs" | head -n1 || true)"
if [[ -z "$exported_func" ]]; then
  echo "api_check_test: could not find an exported method in $target_file_abs" >&2
  exit 2
fi
func_name="$(echo "$exported_func" | sed -nE 's/^func \([^)]+\) ([A-Z][A-Za-z0-9_]+)\(.*/\1/p')"
if [[ -z "$func_name" ]]; then
  echo "api_check_test: could not parse method name from: $exported_func" >&2
  exit 2
fi
echo "api_check_test: will inject breakage into method $func_name"

# Create a throwaway worktree at HEAD plus a tempfile for gorelease
# output. A single trap registered before either resource is created
# guarantees cleanup even on SIGINT mid-setup.
worktree_dir="$(mktemp -d)"
output_file="$(mktemp)"
cleanup() {
  git worktree remove --force "$worktree_dir" >/dev/null 2>&1 || rm -rf "$worktree_dir"
  rm -f "$output_file"
}
trap cleanup EXIT INT TERM

git worktree add --quiet --detach "$worktree_dir" HEAD
echo "api_check_test: worktree at $worktree_dir"

worktree_file="$worktree_dir/$TARGET_MODULE_DIR/$TARGET_FILE_REL"

# Inject a breaking change: rename the method by appending a suffix.
# This is detectable by gorelease as "method removed" + "method added"
# = incompatible.
sed -i.bak -E "s/(func \([^)]+\) )${func_name}\(/\1${func_name}AuditCheckProbe(/" "$worktree_file"
rm -f "$worktree_file.bak"

if ! grep -q "${func_name}AuditCheckProbe" "$worktree_file"; then
  echo "api_check_test: injection sed did not match — fixture stale, update target pattern" >&2
  exit 2
fi

# gorelease refuses to run on a worktree with uncommitted changes —
# commit the injection inside the worktree (it never touches origin).
(
  cd "$worktree_dir"
  git -c user.email=apicheck@local -c user.name="api-check-test" \
      commit -a --allow-empty -m "fixture: inject breakage" --quiet
)

set +e
(
  cd "$worktree_dir/$TARGET_MODULE_DIR" && \
    GOFLAGS=-mod=readonly gorelease -base "$base_version"
) > "$output_file" 2>&1
gorelease_rc=$?
set -e

echo "api_check_test: gorelease exit=$gorelease_rc"
echo "----- gorelease output (head) -----"
head -n 40 "$output_file"
echo "----- end -----"

# Assertions:
#   1. gorelease should exit non-zero (it detected breakage)
#   2. output should contain "incompatible"
#   3. output should mention the renamed method name
if [[ "$gorelease_rc" -eq 0 ]]; then
  echo "FAIL: gorelease exit=0 but a breaking change was injected" >&2
  exit 1
fi
if ! grep -qi "$EXPECTED_BREAKAGE_PATTERN" "$output_file"; then
  echo "FAIL: gorelease output does not contain '$EXPECTED_BREAKAGE_PATTERN'" >&2
  exit 1
fi
if ! grep -q "$func_name" "$output_file"; then
  echo "FAIL: gorelease output does not mention '$func_name'" >&2
  exit 1
fi

echo "PASS: gorelease correctly flagged the injected breakage."
