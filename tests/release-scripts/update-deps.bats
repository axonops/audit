#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release/update-deps.sh — rewrites every
# published-module go.mod require directive to @VERSION, strips
# stale go.sum entries, never runs `go mod tidy` (#925).

load 'test_helper.bash'

setup() {
    stub_path
    REPO_ROOT_TMP="${BATS_TEST_TMPDIR}/repo"
    mkdir -p "$REPO_ROOT_TMP/scripts/release"

    install -m 0755 "${SCRIPTS_DIR}/update-deps.sh" \
        "$REPO_ROOT_TMP/scripts/release/update-deps.sh"

    write_fake_make_makefile "$REPO_ROOT_TMP/Makefile"

    # Pre-seed file/ and syslog/ with go.mods that require the
    # root module + each other at an OLD version.
    mkdir -p "$REPO_ROOT_TMP/file"
    cat > "$REPO_ROOT_TMP/file/go.mod" <<'EOF'
module github.com/axonops/audit/file

go 1.26

require (
	github.com/axonops/audit v0.1.0
	github.com/axonops/audit/syslog v0.1.0
)
EOF
    cat > "$REPO_ROOT_TMP/file/go.sum" <<'EOF'
github.com/axonops/audit v0.1.0 h1:fakehash=
github.com/axonops/audit v0.1.0/go.mod h1:fakehash=
github.com/axonops/audit/syslog v0.1.0 h1:fakehash=
github.com/axonops/audit/syslog v0.1.0/go.mod h1:fakehash=
EOF

    mkdir -p "$REPO_ROOT_TMP/syslog"
    # Single-line require form to exercise that path too.
    cat > "$REPO_ROOT_TMP/syslog/go.mod" <<'EOF'
module github.com/axonops/audit/syslog

go 1.26

require github.com/axonops/audit v0.1.0
EOF

    SCRIPT="$REPO_ROOT_TMP/scripts/release/update-deps.sh"
    cd "$REPO_ROOT_TMP" || return 1
}

@test "test_update_deps_no_version_exits_2" {
    run "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" =~ Usage ]]
}

@test "test_update_deps_invalid_version_format_exits_2" {
    run "$SCRIPT" "not-a-version"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "invalid version format" ]]
}

@test "test_update_deps_rewrites_every_cross_module_require" {
    # The fake go binary records every invocation. After a
    # successful run we expect 3 `go mod edit -require ...@v0.2.2`
    # calls: file/go.mod gets root + syslog rewrites, syslog/go.mod
    # gets one root rewrite.
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]

    args="$(args_of go)"
    edits="$(echo "$args" | grep -c 'mod edit -require')"
    [ "$edits" -eq 3 ]
    echo "$args" | grep -qF 'github.com/axonops/audit@v0.2.2'
    echo "$args" | grep -qF 'github.com/axonops/audit/syslog@v0.2.2'
}

@test "test_update_deps_strips_stale_go_sum_entries" {
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]
    # The script must have removed the stale v0.1.0 lines from
    # file/go.sum so the next `go mod download` will fetch the new
    # checksums.
    ! grep -qF "github.com/axonops/audit v0.1.0" "$REPO_ROOT_TMP/file/go.sum"
    ! grep -qF "github.com/axonops/audit/syslog v0.1.0" "$REPO_ROOT_TMP/file/go.sum"
}

@test "test_update_deps_includes_capstone_example" {
    # Add an example/21-capstone/go.mod that requires the root
    # module — the glob in the script must pick it up.
    mkdir -p "$REPO_ROOT_TMP/examples/21-capstone"
    cat > "$REPO_ROOT_TMP/examples/21-capstone/go.mod" <<'EOF'
module github.com/axonops/audit-examples/capstone

go 1.26

require github.com/axonops/audit v0.1.0
EOF
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]
    # The fake go binary's invocation log must include a pin for
    # the capstone go.mod (cwd ends in /examples/21-capstone).
    args="$(args_of go)"
    echo "$args" | grep -qF "mod edit -require github.com/axonops/audit@v0.2.2"
    # Capstone target was visited — output names the directory.
    [[ "$output" =~ "==> examples/21-capstone" ]]
}

@test "test_update_deps_does_not_run_tidy" {
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]
    # The fake go binary records every invocation. `go mod tidy`
    # must NEVER appear — running tidy at this point in the release
    # flow would fail because the target tag is not yet on origin.
    args="$(args_of go)"
    ! echo "$args" | grep -qE 'mod tidy'
}

@test "test_update_deps_handles_both_single_line_and_block_require_forms" {
    # file/go.mod uses a block (require (...)); syslog/go.mod uses
    # a single-line form. Both shapes must be rewritten.
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 0 ]
    args="$(args_of go)"
    # Block-form rewrites: 2 in file/go.mod (root + syslog)
    file_edits="$(echo "$args" | grep -c 'github.com/axonops/audit@v0.2.2\|github.com/axonops/audit/syslog@v0.2.2')"
    [ "$file_edits" -ge 2 ]
    # Single-line rewrite: 1 in syslog/go.mod (root only)
    [[ "$output" =~ "==> syslog" ]]
}

@test "test_update_deps_empty_publish_modules_exits_2" {
    export FAKE_MAKE_FORCE_EMPTY=1
    run "$SCRIPT" "v0.2.2"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "produced no output" ]]
}
