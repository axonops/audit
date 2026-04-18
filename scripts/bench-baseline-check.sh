#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# bench-baseline-check.sh — reject stale benchmark names in bench-baseline.txt.
#
# Context (#493): bench-baseline.txt once contained
#   BenchmarkAuditDisabledLogger  — renamed to BenchmarkAuditDisabledAuditor
#   BenchmarkNewLogger_Construction — renamed to BenchmarkNew_Construction
# The rename silently broke benchstat's column pairing (the old names had
# no match in bench.txt, so the delta column was blank) and the CI
# regression gate reported no regressions. This script catches that
# class of bug at lint time.
#
# Algorithm:
#   1. Extract the set of benchmark names referenced in bench-baseline.txt
#      (lines beginning with `Benchmark<Name>[-NUM]` and whitespace-ns/op).
#   2. Extract the set of benchmark names defined in the source tree
#      (`func Benchmark<Name>(b *testing.B)`).
#   3. Fail if any baseline name is not in the source set.

set -euo pipefail

# Run from the repo root regardless of the caller's cwd so the
# `grep -rE` over source files sees the whole tree (catches a silent
# false pass when invoked from a sub-module directory).
cd "$(git rev-parse --show-toplevel)"

BASELINE=${1:-bench-baseline.txt}
if [ ! -f "$BASELINE" ]; then
  echo "scripts/bench-baseline-check.sh: $BASELINE not found" >&2
  exit 2
fi

# Names present in the baseline. Strip the GOMAXPROCS suffix
# (`-32`, `-8`, ...) so a run on a 32-core host matches a rename on a
# 16-core host. Strip the `/subtest-name` suffix added by `b.Run(...)`
# — the parent function declaration is what needs to exist in source.
baseline_names=$(awk '/^Benchmark[A-Za-z0-9_]+/ {
  name = $1
  sub(/-[0-9]+$/, "", name)
  sub(/\/.*$/, "", name)
  print name
}' "$BASELINE" | sort -u)

# Names defined in the source tree.
source_names=$(grep -rhE '^func (Benchmark[A-Za-z0-9_]+)\(' \
  --include='*.go' . 2>/dev/null | \
  awk '{ sub(/^func /, "", $2); sub(/\(.*$/, "", $2); print $2 }' | \
  sort -u)

# Compute: baseline_names - source_names. Any non-empty result is a stale name.
stale=$(comm -23 <(echo "$baseline_names") <(echo "$source_names"))

if [ -n "$stale" ]; then
  echo "bench-baseline.txt references benchmark names that no longer exist in the source tree:" >&2
  echo "$stale" | sed 's/^/  - /' >&2
  echo >&2
  echo "These stale names silently break benchstat column pairing and disable" >&2
  echo "CI regression detection. Regenerate the baseline with 'make bench-save'" >&2
  echo "after confirming the renames." >&2
  exit 1
fi

echo "bench-baseline-check: all names in $BASELINE exist in the source tree."
