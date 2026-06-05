#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Meta-tests for the fixture stub binaries (#925 AC #10).
# Each stub MUST record every invocation to $ASSERTION_DIR/<name>.args
# so the per-script tests can assert "did the script call X with Y".
# Without these meta-tests a regression in a stub silently breaks
# every test that depends on it; this file is the canary.

load 'test_helper.bash'

setup() {
    stub_path
}

@test "test_fake_go_records_args_to_assertion_file" {
    go get github.com/example@v1.0.0
    go mod tidy
    [ -f "${ASSERTION_DIR}/go.args" ]
    n="$(wc -l < "${ASSERTION_DIR}/go.args")"
    [ "$n" -eq 2 ]
    grep -qF "get github.com/example@v1.0.0" "${ASSERTION_DIR}/go.args"
    grep -qF "mod tidy" "${ASSERTION_DIR}/go.args"
}

@test "test_fake_git_records_args_to_assertion_file" {
    git --no-such-real-flag-just-records 2>/dev/null || true
    git rev-parse --verify --quiet refs/tags/v0.0.1 || true
    [ -f "${ASSERTION_DIR}/git.args" ]
    n="$(wc -l < "${ASSERTION_DIR}/git.args")"
    [ "$n" -eq 2 ]
    grep -qF "rev-parse --verify --quiet refs/tags/v0.0.1" "${ASSERTION_DIR}/git.args"
}

@test "test_fake_make_records_args_to_assertion_file" {
    export FAKE_MAKE_FORCE_EMPTY=1  # avoid hitting the real make
    make print-publish-modules
    make some-other-target
    [ -f "${ASSERTION_DIR}/make.args" ]
    n="$(wc -l < "${ASSERTION_DIR}/make.args")"
    [ "$n" -eq 2 ]
    grep -qF "print-publish-modules" "${ASSERTION_DIR}/make.args"
    grep -qF "some-other-target" "${ASSERTION_DIR}/make.args"
}
