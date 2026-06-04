#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release/tag-all.sh — partial-push recovery,
# idempotent same-SHA skip, stable order, validation gates (#925).
#
# Strategy
# --------
# tag-all.sh derives $repo_root from its own BASH_SOURCE path and
# then invokes a sibling check-tag-conflicts.sh AND
# gh-graphql-tag.sh. We can't path-shadow those (the script uses
# absolute paths), so each test copies tag-all.sh into a temp
# scripts/release/ tree alongside stub sibling scripts that we
# control. The temp repo also gets a fake Makefile so
# `make print-publish-modules` works.

load 'test_helper.bash'

setup() {
    stub_path

    REPO_ROOT_TMP="${BATS_TEST_TMPDIR}/repo"
    mkdir -p "$REPO_ROOT_TMP/scripts/release"

    # Copy the real tag-all.sh into the temp tree.
    install -m 0755 "${SCRIPTS_DIR}/tag-all.sh" \
        "$REPO_ROOT_TMP/scripts/release/tag-all.sh"

    # Stub check-tag-conflicts.sh: always pass, records argv.
    cat > "$REPO_ROOT_TMP/scripts/release/check-tag-conflicts.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${ASSERTION_DIR}/check-tag-conflicts.args"
exit 0
EOF
    chmod +x "$REPO_ROOT_TMP/scripts/release/check-tag-conflicts.sh"

    # Stub gh-graphql-tag.sh: records argv, exits 0 unless the
    # --tag value appears in $FAKE_TAG_FAILS.
    cat > "$REPO_ROOT_TMP/scripts/release/gh-graphql-tag.sh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "${ASSERTION_DIR}/gh-graphql-tag.args"
tag=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in
        --tag) tag="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
for fail in \${FAKE_TAG_FAILS:-}; do
    if [[ "\$tag" == "\$fail" ]]; then
        echo "fake gh-graphql-tag: \$tag failed" >&2
        exit 1
    fi
done
exit 0
EOF
    chmod +x "$REPO_ROOT_TMP/scripts/release/gh-graphql-tag.sh"

    # Fake Makefile at the temp repo root.
    write_fake_make_makefile "$REPO_ROOT_TMP/Makefile"

    # Init a git repo so the script's `git fetch`, `git rev-parse`
    # etc. have something to operate on.
    (
        cd "$REPO_ROOT_TMP"
        export GIT_CONFIG_GLOBAL=/dev/null
        export GIT_CONFIG_SYSTEM=/dev/null
        git init --quiet
        git config user.email "test@example.com"
        git config user.name "Test User"
        git commit --quiet --allow-empty -m "init"
    )

    SCRIPT="$REPO_ROOT_TMP/scripts/release/tag-all.sh"
    cd "$REPO_ROOT_TMP" || return 1
}

@test "test_tag_all_no_args_exits_2" {
    run "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" =~ Usage ]]
}

@test "test_tag_all_invalid_version_format_exits_2" {
    run "$SCRIPT" "not-a-version" "abc123"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "invalid version format" ]]
}

@test "test_tag_all_unknown_sha_exits_2" {
    # No FAKE_GIT_KNOWN_COMMITS — git cat-file -e will fail.
    run "$SCRIPT" "v0.2.2" "ffffffffffffffffffffffffffffffffffffffff"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "not a known commit" ]]
}

@test "test_tag_all_pushes_all_publish_modules_in_stable_order" {
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    # Three tags pushed: v0.2.2 (root), file/v0.2.2, syslog/v0.2.2
    # Order is alphabetical by tag_prefix (col 3 of publish-modules),
    # i.e. root ("") first then "file/" then "syslog/".
    [[ "$output" =~ "3 pushed" ]]
    args="$(args_of gh-graphql-tag)"
    line1="$(echo "$args" | sed -n '1p')"
    line2="$(echo "$args" | sed -n '2p')"
    line3="$(echo "$args" | sed -n '3p')"
    [[ "$line1" =~ "--tag v0.2.2" ]]
    [[ "$line2" =~ "--tag file/v0.2.2" ]]
    [[ "$line3" =~ "--tag syslog/v0.2.2" ]]
}

@test "test_tag_all_idempotent_same_sha_skips_silently" {
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    # All three tags already exist at the target SHA → all
    # idempotent skips, zero new pushes.
    export FAKE_GIT_EXISTING_TAGS="v0.2.2=$sha file/v0.2.2=$sha syslog/v0.2.2=$sha"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "0 pushed" ]]
    [[ "$output" =~ "3 idempotent skips" ]]
    # The tagging helper must not have been called at all.
    [ ! -f "${ASSERTION_DIR}/gh-graphql-tag.args" ]
}

@test "test_tag_all_partial_push_failure_writes_recovery_script_to_step_summary" {
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    # syslog/v0.2.2 fails; root + file should still be pushed.
    export FAKE_TAG_FAILS="syslog/v0.2.2"
    GITHUB_STEP_SUMMARY="${BATS_TEST_TMPDIR}/step.md"
    export GITHUB_STEP_SUMMARY
    : > "$GITHUB_STEP_SUMMARY"

    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "tag-all: 1 tag(s) failed" ]]
    # Recovery script in the step summary names the failed tag.
    grep -qF "syslog/v0.2.2" "$GITHUB_STEP_SUMMARY"
    grep -qF "Recovery" "$GITHUB_STEP_SUMMARY"
    # Two tags should have been successfully pushed before the
    # failure (root + file).
    args="$(args_of gh-graphql-tag)"
    n="$(echo "$args" | wc -l)"
    [ "$n" -eq 3 ]
}

@test "test_tag_all_push_auth_failure_surfaces_error_and_does_not_continue" {
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    # First tag (root v0.2.2) fails with auth error.
    export FAKE_TAG_FAILS="v0.2.2 file/v0.2.2 syslog/v0.2.2"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "tag-all: 3 tag(s) failed" ]]
    [[ "$output" =~ "v0.2.2" ]]
}
