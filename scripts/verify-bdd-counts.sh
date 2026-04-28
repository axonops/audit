#!/usr/bin/env bash
# Aggregate per-suite BDD scenario counts produced by the CI bdd matrix
# (one bdd-count-<suite>/bdd-count.txt artefact per matrix shard) and
# verify the sum equals the expected total reported by
# scripts/count-bdd-scenarios.sh against the feature-file dirs.
#
# Usage:
#   verify-bdd-counts.sh <counts_dir> <feature_dir>...
#
# Example:
#   verify-bdd-counts.sh /tmp/bdd-counts \
#     tests/bdd/features outputconfig/tests/bdd/features
#
# Used by the bdd-verify CI job after every BDD matrix shard uploads
# its bdd-count-<suite>/bdd-count.txt artefact. Replaces the inline
# shell that previously lived in .github/workflows/ci.yml so the
# logic is locally testable and lint-friendly.

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <counts_dir> <feature_dir>..." >&2
  exit 2
fi

COUNTS_DIR="$1"
shift

# Resolve the script's own directory so we can find sibling scripts
# regardless of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

expected=$("${SCRIPT_DIR}/count-bdd-scenarios.sh" "$@")
echo "Expected total scenarios: $expected"

actual=0
for count_file in "${COUNTS_DIR}"/bdd-count-*/bdd-count.txt; do
  if [ -f "$count_file" ]; then
    suite_name=$(basename "$(dirname "$count_file")" | sed 's/bdd-count-//')
    n=$(cat "$count_file")
    echo "  $suite_name: $n scenarios"
    actual=$((actual + n))
  fi
done
echo "Actual total executed:    $actual"

if [ "$actual" -ne "$expected" ]; then
  echo ""
  echo "FAIL: scenario count mismatch!"
  echo "  Expected: $expected (from feature files)"
  echo "  Actual:   $actual (sum of runner executions)"
  echo ""
  echo "This means some scenarios were not executed by any runner."
  echo "Check that all feature files have appropriate tags and that"
  echo "the BDD matrix runner tag expressions cover all scenarios."
  exit 1
fi

echo ""
echo "PASS: all $expected scenarios were executed across the BDD matrix."
