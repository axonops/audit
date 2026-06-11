#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies the release-PR carve-out (#957) on the Makefile targets
# `regen-schema-artifacts-check` and `ta-diff-check`. Both targets
# shell out to `go run ./cmd/audit-gen`, which needs to resolve every
# published sub-module's go.mod. On a release/v* head ref the
# cross-module pins point at yet-to-be-tagged versions, so the check
# is intentionally skipped — but the protection must remain in force
# for every non-release branch.
#
# Each test sets / unsets GITHUB_HEAD_REF and asserts the target's
# observable behaviour on stdout + exit code. The target is invoked
# at the real repo (REPO_ROOT) — no fixture binaries are needed
# because the guard runs BEFORE any go command and the check exits
# 0 cleanly on the skip branch.

load 'test_helper.bash'

setup() {
    # Make targets always inherit the caller's PATH; no stubs needed
    # because the carve-out short-circuits before any go invocation.
    cd "$REPO_ROOT"
}

# --- regen-schema-artifacts-check ---------------------------------

@test "test_regen_schema_artifacts_check_skips_on_release_v_head_ref" {
    GITHUB_HEAD_REF=release/v0.2.3 run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    [[ "$output" == *"regen-schema-artifacts-check: skipping on release PR head ref release/v0.2.3 (#957)"* ]]
}

@test "test_regen_schema_artifacts_check_skips_on_release_prerelease_head_ref" {
    GITHUB_HEAD_REF=release/v1.0.0-rc.1 run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    [[ "$output" == *"skipping on release PR head ref release/v1.0.0-rc.1"* ]]
}

@test "test_regen_schema_artifacts_check_runs_on_unset_head_ref" {
    # Unset GITHUB_HEAD_REF (the GHA value on push, on dispatch,
    # or in a local invocation). The target must run the full check.
    unset GITHUB_HEAD_REF
    run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    # No skip line in the output — the check ran in full.
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_regen_schema_artifacts_check_runs_on_feature_head_ref" {
    GITHUB_HEAD_REF=feature/foo run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_regen_schema_artifacts_check_runs_on_release_prefix_collision" {
    # Defence in depth: a branch named `release-foo` (legacy hyphen
    # naming) MUST NOT skip — the regex requires a slash + semver.
    GITHUB_HEAD_REF=release-foo run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_regen_schema_artifacts_check_runs_on_release_non_semver_head_ref" {
    # `release/foo` would be a non-versioned branch — also MUST NOT
    # trip the skip path. The regex anchors on `release/v<semver>`.
    GITHUB_HEAD_REF=release/foo run make -s regen-schema-artifacts-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

# --- ta-diff-check -------------------------------------------------

@test "test_ta_diff_check_skips_on_release_v_head_ref" {
    GITHUB_HEAD_REF=release/v0.2.3 run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" == *"ta-diff-check: skipping on release PR head ref release/v0.2.3 (#957)"* ]]
}

@test "test_ta_diff_check_skips_on_release_prerelease_head_ref" {
    GITHUB_HEAD_REF=release/v1.0.0-rc.1 run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" == *"skipping on release PR head ref release/v1.0.0-rc.1"* ]]
}

@test "test_ta_diff_check_runs_on_unset_head_ref" {
    unset GITHUB_HEAD_REF
    run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_ta_diff_check_runs_on_feature_head_ref" {
    GITHUB_HEAD_REF=feature/foo run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_ta_diff_check_runs_on_release_prefix_collision" {
    GITHUB_HEAD_REF=release-foo run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}

@test "test_ta_diff_check_runs_on_release_non_semver_head_ref" {
    GITHUB_HEAD_REF=release/foo run make -s ta-diff-check
    [ "$status" -eq 0 ]
    [[ "$output" != *"skipping on release PR head ref"* ]]
}
