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
# then invokes a sibling check-tag-conflicts.sh. We can't path-shadow
# that (the script uses an absolute path), so each test copies
# tag-all.sh into a temp scripts/release/ tree alongside stub
# sibling scripts that we control. The temp repo also gets a fake
# Makefile so `make print-publish-modules` works.
#
# PR-6 (#929) replaced the per-tag bash-helper shell-out with
# `release-tool create-tag`. The release-tool binary is resolved
# from $RELEASE_TOOL, so each test points RELEASE_TOOL at a stub
# binary that records argv and synthesises failures.

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

    # PR-6 (#929): stub release-tool binary. Records argv to
    # release-tool.args, exits 0 unless the --tag value appears in
    # $FAKE_TAG_FAILS. The `--help` invocation (used by tag-all.sh
    # to probe the binary) must succeed.
    STUB_RELEASE_TOOL="$REPO_ROOT_TMP/release-tool"
    cat > "$STUB_RELEASE_TOOL" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "--help" || "\${1:-}" == "-h" ]]; then
    echo "stub release-tool"
    exit 0
fi
printf '%s\n' "\$*" >> "${ASSERTION_DIR}/release-tool.args"
sub="\$1"; shift || true
tag=""
while [[ \$# -gt 0 ]]; do
    case "\$1" in
        --tag) tag="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ "\$sub" == "create-tag" ]]; then
    for fail in \${FAKE_TAG_FAILS:-}; do
        if [[ "\$tag" == "\$fail" ]]; then
            echo "stub release-tool: \$tag failed" >&2
            exit 1
        fi
    done
fi
exit 0
EOF
    chmod +x "$STUB_RELEASE_TOOL"
    export RELEASE_TOOL="$STUB_RELEASE_TOOL"

    # PR-6 (#929): owner/repo come from env in CI; supply them so
    # the script doesn't fall back to origin-remote parsing inside
    # the fresh `git init` repo (which has no origin remote).
    export GH_OWNER="axonops"
    export GH_REPO="audit"

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

@test "test_tag_all_pushes_via_release_tool_create_tag" {
    # PR-6 (#929): the per-tag call must invoke release-tool with
    # the `create-tag` subcommand AND propagate --owner / --repo /
    # --sha / --message from the env. Stable alphabetical-by-prefix
    # ordering for deterministic partial-failure diagnostics.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "3 pushed" ]]
    args="$(args_of release-tool)"
    line1="$(echo "$args" | sed -n '1p')"
    line2="$(echo "$args" | sed -n '2p')"
    line3="$(echo "$args" | sed -n '3p')"
    # Every call uses the create-tag subcommand and propagates
    # --owner / --repo / --sha / --message from $GH_OWNER /
    # $GH_REPO / the VERSION + SHA arguments.
    [[ "$line1" == create-tag* ]]
    [[ "$line1" =~ "--owner axonops" ]]
    [[ "$line1" =~ "--repo audit" ]]
    [[ "$line1" =~ "--tag v0.2.2" ]]
    [[ "$line1" =~ "--sha $sha" ]]
    [[ "$line1" =~ "--message Release v0.2.2" ]]
    [[ "$line2" =~ "--tag file/v0.2.2" ]]
    [[ "$line2" =~ "--sha $sha" ]]
    [[ "$line3" =~ "--tag syslog/v0.2.2" ]]
    [[ "$line3" =~ "--sha $sha" ]]
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
    # The tagging binary must not have been called at all.
    [ ! -f "${ASSERTION_DIR}/release-tool.args" ]
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
    # Three tags should have been attempted (root + file succeed,
    # syslog fails).
    args="$(args_of release-tool)"
    n="$(echo "$args" | wc -l)"
    [ "$n" -eq 3 ]
}

# --- PR-6 (#929): recovery snippet uses release-tool create-tag ---

@test "test_tag_all_recovery_snippet_uses_release_tool_create_tag" {
    # The repo has required_signatures ON, so raw `git tag -a` +
    # `git push` in the recovery snippet would immediately fail in
    # production. PR-6 emits the App-signed release-tool binary
    # instead. The previous emission was the v0.2.1 bash tag
    # helper (since deleted); this test guards against any
    # regression that reintroduces a bare-git recovery path.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_TAG_FAILS="syslog/v0.2.2"
    GITHUB_STEP_SUMMARY="${BATS_TEST_TMPDIR}/step.md"
    export GITHUB_STEP_SUMMARY
    : > "$GITHUB_STEP_SUMMARY"

    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 1 ]

    # The recovery snippet must reference release-tool create-tag,
    # NOT raw `git tag -a` / `git push origin <tag>` and not the
    # deleted bash helpers. Use `--` for flag-starting patterns so
    # grep does not try to interpret them.
    grep -qF "release-tool create-tag" "$GITHUB_STEP_SUMMARY"
    grep -qF -- "--owner" "$GITHUB_STEP_SUMMARY"
    grep -qF -- "--repo" "$GITHUB_STEP_SUMMARY"
    ! grep -qE '^git tag -a' "$GITHUB_STEP_SUMMARY"
    ! grep -qE '^git push origin "syslog/v0.2.2"' "$GITHUB_STEP_SUMMARY"
    ! grep -qF "gh-graphql-tag.sh" "$GITHUB_STEP_SUMMARY"
    ! grep -qF "gh-graphql-commit.sh" "$GITHUB_STEP_SUMMARY"
}

@test "test_tag_all_release_tool_failure_collects_per_tag" {
    # PR-6 (#929): per-tag failure collection is preserved. Every
    # invocation of release-tool that errors is recorded; the
    # script does NOT fail-fast on the first error.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    # First tag (root v0.2.2) fails with auth error.
    export FAKE_TAG_FAILS="v0.2.2 file/v0.2.2 syslog/v0.2.2"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "tag-all: 3 tag(s) failed" ]]
    [[ "$output" =~ "v0.2.2" ]]
}

@test "test_tag_all_missing_release_tool_binary_exits_2_with_guidance" {
    # PR-6 (#929): when RELEASE_TOOL points at a non-existent
    # binary (or the binary is missing from PATH for local
    # invocation), exit cleanly with operator guidance — never
    # silently fall through to a different tagging path.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export RELEASE_TOOL="${BATS_TEST_TMPDIR}/no-such-binary"
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "release-tool binary not found" ]]
    [[ "$output" =~ "go build" ]]
}

@test "test_tag_all_derives_owner_repo_from_origin_when_env_unset" {
    # PR-6 (#929): for recovery from a clean local checkout where
    # GH_OWNER/GH_REPO aren't pre-populated, tag-all parses owner
    # and repo from the `origin` remote URL. The fixture git stub
    # honours $FAKE_GIT_ORIGIN_URL on `remote get-url origin`,
    # standing in for a real configured origin. Covers the HTTPS
    # form; the SSH form is exercised by the next test.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="https://github.com/example/derived.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    args="$(args_of release-tool)"
    [[ "$args" =~ "--owner example" ]]
    [[ "$args" =~ "--repo derived" ]]
}

@test "test_tag_all_derives_owner_repo_from_ssh_origin_when_env_unset" {
    # PR-6 (#929): SSH origin form parsing, distinct grammar arm.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="git@github.com:example/sshform.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    args="$(args_of release-tool)"
    [[ "$args" =~ "--owner example" ]]
    [[ "$args" =~ "--repo sshform" ]]
}

@test "test_tag_all_unsupported_origin_url_exits_2" {
    # PR-6 (#929): unrecognised origin URL forms (e.g. GitLab,
    # Bitbucket) must fail explicitly rather than silently mis-
    # parse owner/repo. Only github.com HTTPS and SSH forms are
    # supported.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="https://gitlab.com/example/derived.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "unsupported origin remote URL" ]]
}

@test "test_tag_all_no_origin_and_no_env_exits_2" {
    # PR-6 (#929): when neither GH_OWNER/GH_REPO nor an origin
    # remote is available, fail loudly with operator guidance.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    unset GH_OWNER GH_REPO FAKE_GIT_ORIGIN_URL
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "no GH_OWNER/GH_REPO env and no origin remote" ]]
}

# --- PR-6 (#929) parser hardening regression tests ---

@test "test_tag_all_origin_with_trailing_slash_parsed_correctly" {
    # The parser strips a trailing slash so
    # `https://github.com/OWNER/REPO/` doesn't leave repo="".
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="https://github.com/example/trailing/"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 0 ]
    args="$(args_of release-tool)"
    [[ "$args" =~ "--owner example" ]]
    [[ "$args" =~ "--repo trailing" ]]
}

@test "test_tag_all_origin_with_embedded_credentials_exits_2" {
    # PR-6 (#929) security: `https://user:token@github.com/...`
    # smells like a leaked PAT in the origin URL. Reject explicitly
    # rather than silently propagating it through the parser.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="https://x-access-token:ghp_AAA@github.com/example/derived.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "unsupported origin remote URL" ]]
}

@test "test_tag_all_origin_with_ssh_scheme_exits_2" {
    # `ssh://git@github.com/OWNER/REPO.git` is a less-common URL
    # form that the parser does NOT support. Reject explicitly so
    # operators see the failure rather than silently mis-parsing.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="ssh://git@github.com/example/derived.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "unsupported origin remote URL" ]]
}

@test "test_tag_all_origin_with_http_scheme_exits_2" {
    # PR-6 (#929) security M2: github.com always redirects http→
    # https. Accepting http://github.com origin URLs on a release
    # path is a configuration smell — reject explicitly.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="http://github.com/example/derived.git"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "unsupported origin remote URL" ]]
}

@test "test_tag_all_origin_with_nested_path_exits_2" {
    # Nested paths (`OWNER/SUB/REPO`) aren't valid GitHub remotes,
    # but the previous parser would silently produce
    # `owner=OWNER, repo=REPO` and lose SUB. The strict shape
    # check exits 2 instead.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL="https://github.com/group/sub/derived"
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    [[ "$output" =~ "malformed owner/repo" ]]
}

@test "test_tag_all_origin_with_metacharacters_exits_2" {
    # Defence-in-depth: shell metacharacters in the origin URL
    # MUST NOT reach the release-tool flag values. The strict
    # `[A-Za-z0-9][A-Za-z0-9._-]*` shape check rejects any
    # quote/space/semicolon attempts. Verify that:
    #   1. exit code is 2 (parser rejection), and
    #   2. release-tool was never invoked (the metacharacters
    #      didn't smuggle past parameter expansion). The
    #      adversarial URL itself contains "HACKED" as a literal
    #      substring; what we're verifying is that no extra
    #      command was executed and that release-tool stayed in
    #      its untouched state.
    sha="abc123abc123abc123abc123abc123abc123abc1"
    export FAKE_GIT_KNOWN_COMMITS="$sha"
    export FAKE_GIT_ORIGIN_URL='https://github.com/foo";echo HACKED;#/bar'
    unset GH_OWNER GH_REPO
    run "$SCRIPT" "v0.2.2" "$sha"
    [ "$status" -eq 2 ]
    # The parser exited before any release-tool invocation.
    [ ! -f "${ASSERTION_DIR}/release-tool.args" ]
    # No line consisting solely of "HACKED" — `echo HACKED` would
    # have produced one; the literal-substring match in the URL
    # is the expected source of the substring.
    ! echo "$output" | grep -qE '^HACKED$'
}
