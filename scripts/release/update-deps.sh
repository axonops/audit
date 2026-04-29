#!/usr/bin/env bash
# Pins every published-module go.mod (plus the capstone example) to a
# given VERSION for every cross-reference to another published
# axonops/audit module. Used by the release.yml `update-deps-pr` job
# to produce the single commit that the release PR contains.
#
# Usage:
#   scripts/release/update-deps.sh <VERSION>
#
# Reads the canonical module list from `make print-publish-modules`.
# Iterates every published module and rewrites its `require` directive
# for every OTHER published module to `@VERSION`. Then runs `go mod
# tidy` with `GOWORK=off GOPROXY=direct GONOSUMCHECK=...` matching the
# existing release.yml semantics.
#
# Also updates `examples/17-capstone/go.mod` (it's not published, but
# its dependency pins move with the release).
set -euo pipefail

readonly VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <VERSION>" >&2
  exit 2
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.\-]+)?$ ]]; then
  echo "update-deps: invalid version format: $VERSION" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# Build the published-module path list once.
published_paths=()
while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  published_paths+=("$module_path")
done < <(make -s --no-print-directory print-publish-modules)

if (( ${#published_paths[@]} == 0 )); then
  echo "update-deps: 'make print-publish-modules' produced no output" >&2
  exit 2
fi

# Modules to rewrite: every published module + the capstone example.
# Skip the core module itself (`.`) — core has no axonops/audit
# require directives to update.
targets=()
while IFS='|' read -r dir module_path tag_prefix; do
  [[ -z "$dir" ]] && continue
  [[ "$dir" == "." ]] && continue
  targets+=("$dir")
done < <(make -s --no-print-directory print-publish-modules)
targets+=("examples/17-capstone")

# go mod tidy semantics matching the existing release.yml: workspace
# off (so each module resolves on its own go.mod), GOPROXY=direct
# (fetches new versions from GitHub even before the proxy has indexed
# them), and GONOSUMCHECK / GONOSUMDB so the sumdb doesn't refuse a
# version that hasn't been seen yet.
export GOWORK=off
export GOPROXY=direct
export GONOSUMCHECK=github.com/axonops/audit
export GONOSUMDB=github.com/axonops/audit
export GOFLAGS=-mod=mod  # update mode required for go mod edit + tidy

for target in "${targets[@]}"; do
  if [[ ! -f "$target/go.mod" ]]; then
    echo "update-deps: $target/go.mod missing — skipping"
    continue
  fi
  echo "==> $target"
  pushd "$target" >/dev/null

  for path in "${published_paths[@]}"; do
    # Anchored regex: the path is followed by a single space then `v`
    # then a digit, ensuring `audit` doesn't false-positive on
    # `audit-extra`. Comment lines are skipped because go.mod
    # comments use `//` which doesn't satisfy the leading-whitespace
    # + path constraint here.
    if grep -qE "^[[:space:]]*${path}[[:space:]]v[0-9]" go.mod; then
      go mod edit -require "${path}@${VERSION}"
      echo "  pinned $path → $VERSION"
    fi
  done

  go mod tidy
  echo "  tidied."
  popd >/dev/null
done

echo "update-deps: pinned $VERSION in ${#targets[@]} go.mod files."
