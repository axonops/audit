#!/usr/bin/env bash
# Regenerates the auto-generated module table in docs/releasing.md
# from the canonical PUBLISH_MODULES Makefile variable.
#
# Usage:
#   scripts/release/regen-docs.sh <docs-file>          # rewrite in place
#   scripts/release/regen-docs.sh --check <docs-file>  # verify in sync, no rewrite
#
# The target file MUST contain the BEGIN/END markers exactly:
#   <!-- BEGIN PUBLISH_MODULES TABLE — do not edit; run `make regen-release-docs` to update -->
#   <!-- END PUBLISH_MODULES TABLE -->
#
# Everything between the markers (exclusive) is replaced with a
# generated markdown table. The markers themselves are preserved.
set -euo pipefail

readonly BEGIN_MARKER='<!-- BEGIN PUBLISH_MODULES TABLE — do not edit; run `make regen-release-docs` to update -->'
readonly END_MARKER='<!-- END PUBLISH_MODULES TABLE -->'

usage() {
  cat >&2 <<EOF
Usage: $0 [--check] <docs-file>
  --check   verify the file is in sync; exit 1 if regen would produce a diff
EOF
  exit 2
}

mode="rewrite"
docs_file=""
case "${1:-}" in
  --check) mode="check"; docs_file="${2:-}" ;;
  -h|--help) usage ;;
  "") usage ;;
  *) docs_file="$1" ;;
esac

if [[ -z "$docs_file" ]]; then
  usage
fi
if [[ ! -f "$docs_file" ]]; then
  echo "regen-docs: docs file not found: $docs_file" >&2
  exit 1
fi

# Locate the Makefile relative to this script (../../Makefile).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

# Pull PUBLISH_MODULES from make so this script never duplicates the list.
modules="$(cd "$repo_root" && make -s --no-print-directory print-publish-modules)"
if [[ -z "$modules" ]]; then
  echo "regen-docs: 'make print-publish-modules' produced no output" >&2
  exit 1
fi

generate_table() {
  echo "| Module | Path | Tag prefix |"
  echo "|--------|------|------------|"
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    local dir module_path tag_prefix display_dir display_prefix
    dir="$(echo "$entry" | cut -d'|' -f1)"
    module_path="$(echo "$entry" | cut -d'|' -f2)"
    tag_prefix="$(echo "$entry" | cut -d'|' -f3)"
    display_dir="$dir"
    if [[ "$dir" == "." ]]; then
      display_dir="(repo root)"
    fi
    display_prefix="${tag_prefix}v*"
    if [[ -z "$tag_prefix" ]]; then
      display_prefix="v*"
    fi
    echo "| \`$display_dir\` | \`$module_path\` | \`$display_prefix\` |"
  done <<<"$modules"
}

# Build the new content for the region between markers (exclusive).
# Surrounding blank lines keep the markdown well-formed regardless of
# how the markers are placed.
new_region="$(
  echo
  generate_table
  echo
)"

# Verify both markers exist exactly once.
begin_count=$(grep -cF "$BEGIN_MARKER" "$docs_file" || true)
end_count=$(grep -cF "$END_MARKER" "$docs_file" || true)
if [[ "$begin_count" -ne 1 || "$end_count" -ne 1 ]]; then
  echo "regen-docs: $docs_file must contain exactly one BEGIN and one END marker" >&2
  echo "  BEGIN occurrences: $begin_count" >&2
  echo "  END   occurrences: $end_count" >&2
  exit 1
fi

# Verify END appears after BEGIN.
begin_line=$(grep -nF "$BEGIN_MARKER" "$docs_file" | head -n1 | cut -d: -f1)
end_line=$(grep -nF "$END_MARKER" "$docs_file" | head -n1 | cut -d: -f1)
if [[ "$end_line" -le "$begin_line" ]]; then
  echo "regen-docs: END marker must appear after BEGIN marker in $docs_file" >&2
  exit 1
fi

tmp_out="$(mktemp)"
trap 'rm -f "$tmp_out"' EXIT

# Rewrite: take everything up to and including BEGIN marker, then the
# generated region, then everything from END marker onward.
{
  sed -n "1,${begin_line}p" "$docs_file"
  printf '%s\n' "$new_region"
  sed -n "${end_line},\$p" "$docs_file"
} > "$tmp_out"

if [[ "$mode" == "check" ]]; then
  if ! diff -u "$docs_file" "$tmp_out" >/dev/null; then
    echo "regen-docs: $docs_file is OUT OF SYNC with PUBLISH_MODULES." >&2
    echo "Run: make regen-release-docs" >&2
    diff -u "$docs_file" "$tmp_out" >&2 || true
    exit 1
  fi
  echo "regen-docs: $docs_file is in sync with PUBLISH_MODULES."
  exit 0
fi

# Rewrite mode: only touch the file if content changed.
if diff -q "$docs_file" "$tmp_out" >/dev/null 2>&1; then
  echo "regen-docs: $docs_file already up to date."
else
  cp "$tmp_out" "$docs_file"
  echo "regen-docs: $docs_file regenerated."
fi
