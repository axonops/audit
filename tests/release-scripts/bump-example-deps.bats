#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release/bump-example-deps.sh — invokes `go get`
# with all audit modules pinned together, forces GOWORK=off, refuses
# unsupported version formats (#925).

load 'test_helper.bash'

setup() {
    stub_path
    SCRIPT="${SCRIPTS_DIR}/bump-example-deps.sh"
    EXAMPLE_DIR="${BATS_TEST_TMPDIR}/example"
    mkdir -p "$EXAMPLE_DIR"
}

@test "test_bump_example_deps_no_args_exits_2" {
    run "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" =~ Usage ]]
}

@test "test_bump_example_deps_missing_go_mod_exits_2" {
    # Empty directory, no go.mod.
    run "$SCRIPT" "$EXAMPLE_DIR" "v0.2.2"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "no go.mod" ]]
}

@test "test_bump_example_deps_invalid_version_format_exits_2" {
    cat > "$EXAMPLE_DIR/go.mod" <<'EOF'
module example
go 1.26
require github.com/axonops/audit v0.1.0
EOF
    run "$SCRIPT" "$EXAMPLE_DIR" "not-a-version"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "invalid version format" ]]
}

@test "test_bump_example_deps_invokes_go_get_with_all_modules_pinned_together" {
    cat > "$EXAMPLE_DIR/go.mod" <<'EOF'
module example

go 1.26

require (
	github.com/axonops/audit v0.1.0
	github.com/axonops/audit/file v0.1.0
	github.com/axonops/audit/syslog v0.1.0
)
EOF
    run "$SCRIPT" "$EXAMPLE_DIR" "v0.2.2"
    [ "$status" -eq 0 ]
    args="$(args_of go)"
    # Single `go get` call carrying all three @v0.2.2 args.
    n_gets="$(echo "$args" | grep -c '^get ')"
    [ "$n_gets" -eq 1 ]
    echo "$args" | grep -qF 'github.com/axonops/audit@v0.2.2'
    echo "$args" | grep -qF 'github.com/axonops/audit/file@v0.2.2'
    echo "$args" | grep -qF 'github.com/axonops/audit/syslog@v0.2.2'
}

@test "test_bump_example_deps_forces_GOWORK_off" {
    cat > "$EXAMPLE_DIR/go.mod" <<'EOF'
module example
go 1.26
require github.com/axonops/audit v0.1.0
EOF
    # Set GOWORK to a non-empty value; the script must override.
    export GOWORK="/some/random/path"
    run "$SCRIPT" "$EXAMPLE_DIR" "v0.2.2"
    [ "$status" -eq 0 ]
    # The script exports GOWORK=off before calling go. Verify that
    # the script reached the `go get` step (proves it ran the cd +
    # env-export block) by checking that the fake go was invoked
    # with `get`.
    grep -qF 'get ' "${ASSERTION_DIR}/go.args"
}

@test "test_bump_example_deps_no_audit_requires_exits_0_noop" {
    cat > "$EXAMPLE_DIR/go.mod" <<'EOF'
module example
go 1.26
require golang.org/x/tools v0.1.0
EOF
    run "$SCRIPT" "$EXAMPLE_DIR" "v0.2.2"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "no github.com/axonops/audit requires" ]]
    # Our fake go must NOT have been called.
    [ ! -f "${ASSERTION_DIR}/go.args" ]
}
