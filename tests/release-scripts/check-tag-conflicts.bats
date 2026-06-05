#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release/check-tag-conflicts.sh — locks the
# behaviour the v0.2.1 cascade depended on (#925).

load 'test_helper.bash'

setup() {
    SCRIPT="${SCRIPTS_DIR}/check-tag-conflicts.sh"
    stub_path

    # Every test runs against a fresh temp git repo. Tag scenarios
    # are driven by the FAKE_GIT_EXISTING_TAGS env var on the fake
    # git binary.
    REPO_DIR="$(make_temp_repo)"
    cd "$REPO_DIR" || return 1

    # Drop a fake Makefile so make print-publish-modules works.
    write_fake_make_makefile Makefile
}

@test "test_check_tag_conflicts_no_version_exits_2" {
    run "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" =~ Usage ]]
}

@test "test_check_tag_conflicts_invalid_version_format_exits_2" {
    run "$SCRIPT" "not-a-version"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "invalid version format" ]]
}

@test "test_check_tag_conflicts_no_tags_exit_0" {
    # No FAKE_GIT_EXISTING_TAGS means git rev-parse will exit 1
    # for every tag check, so the script sees no conflicts.
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "no conflicts" ]]
}

@test "test_check_tag_conflicts_strict_mode_existing_tag_exits_1" {
    # Tag v0.2.2 already exists (root module), so strict mode aborts.
    export FAKE_GIT_EXISTING_TAGS="v0.2.2=abc123"
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "v0.2.2 already exists" ]]
}

@test "test_check_tag_conflicts_idempotent_mode_same_sha_exits_0" {
    # Tag exists at the same SHA as the expected one — that's the
    # idempotent re-run path and must NOT fail.
    export FAKE_GIT_EXISTING_TAGS="v0.2.2=abc123"
    run "$SCRIPT" "v0.2.2" "abc123"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "no conflicts" ]]
}

@test "test_check_tag_conflicts_idempotent_mode_different_sha_exits_1" {
    # Tag exists at a different SHA than expected — contamination.
    export FAKE_GIT_EXISTING_TAGS="v0.2.2=abc123"
    run "$SCRIPT" "v0.2.2" "def456"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "permanent contamination" ]]
}

@test "test_check_tag_conflicts_empty_publish_modules_exits_2" {
    # An empty publish-modules list is a configuration error, not
    # a "no conflicts" success.
    export FAKE_MAKE_FORCE_EMPTY=1
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "produced no output" ]]
}
