#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Behavioural CLI flag validity tests for release.yml and goreleaser.yml.
#
# Why this file exists
# --------------------
# PR-5 (#928) introduced `gh pr create --json url --jq '.url'` to
# replace the v0.2.1 `tail | sed` anti-pattern. The accompanying
# regression test asserted the literal string was PRESENT in
# release.yml — and it passed. But `gh pr create` does not support
# `--json`; the v0.2.2 dispatch (run 27149700917) was the first time
# the actual gh CLI ran the command, and it failed with
# `unknown flag: --json`. We had to ship PR #946 to fix it.
#
# Tests in release-yml-grep.bats are string-shape regression tests.
# Tests in this file are BEHAVIOURAL: they invoke the actual CLI
# tools used by the release workflow and validate that every flag in
# release.yml / .goreleaser.yml is supported by the version we
# install in CI. This catches the "invalid flag combination" class of
# bug BEFORE it reaches a dispatch.
#
# Tracking issue: #960.

load 'test_helper.bash'

setup() {
    RELEASE_YML="${REPO_ROOT}/.github/workflows/release.yml"
    GORELEASER_YML="${REPO_ROOT}/.github/workflows/goreleaser.yml"
    GORELEASER_CONFIG="${REPO_ROOT}/.goreleaser.yml"
    [ -f "$RELEASE_YML" ] || skip "release.yml not present"
}

# ---------------------------------------------------------------------
# gh CLI — release.yml's update-deps-pr step invokes `gh pr create`
# ---------------------------------------------------------------------

@test "test_release_yml_gh_pr_create_flags_are_documented_in_gh_help" {
    # Extract every --foo flag used with `gh pr create` in release.yml
    # and assert each appears in `gh pr create --help`. PR-5 false
    # positive happened because the bats test only checked for
    # string presence in release.yml — never against gh itself.
    command -v gh >/dev/null 2>&1 || skip "gh CLI not installed"

    help_output="$(gh pr create --help 2>&1)"
    used_flags="$(awk '
        /gh pr create/ {capture=1}
        capture && /^[[:space:]]*--[a-z-]+/ {
            # Strip leading whitespace and trailing junk; print just
            # the --flag-name token.
            for (i=1; i<=NF; i++) {
                if ($i ~ /^--[a-z-]+/) {
                    flag=$i
                    sub(/[^-a-z].*$/, "", flag)
                    print flag
                }
            }
        }
        capture && /--json url/ {ok=1}
        capture && !/--/ && !/^[[:space:]]/ {capture=0}
    ' "$RELEASE_YML" | sort -u)"

    if [ -z "$used_flags" ]; then
        skip "no gh pr create invocations found in release.yml"
    fi

    for flag in $used_flags; do
        if ! echo "$help_output" | grep -qE -- "(^[[:space:]]*${flag}[[:space:]]|, ${flag}[[:space:]])"; then
            echo "regression: release.yml passes ${flag} to 'gh pr create', but that flag is not in gh's help output." >&2
            echo "Either the flag has been removed in this gh version, or release.yml uses an unsupported flag." >&2
            return 1
        fi
    done
}

@test "test_gh_pr_create_still_does_not_have_json_flag_pr_5_canary" {
    # Negative canary: if `gh pr create` ever GAINS --json, the
    # rationale for PR #946's fix changes (we could revert to a
    # typed capture). This test fires when that day comes — flip
    # the assertion + re-evaluate.
    command -v gh >/dev/null 2>&1 || skip "gh CLI not installed"
    ! gh pr create --help 2>&1 | grep -qE -- '^[[:space:]]*--json[[:space:]]'
}

# ---------------------------------------------------------------------
# goreleaser — release.yml's goreleaser/goreleaser.yml pass --skip=X
# ---------------------------------------------------------------------

@test "test_release_yml_goreleaser_skip_values_exist_in_goreleaser_help" {
    # Extract every --skip=X value used anywhere in the release
    # workflows and assert each is in goreleaser's valid-skip set.
    # PR #954 shipped --skip=docker-manifests which goreleaser
    # rejected at dispatch time (run 27261573798); the catch in
    # PR #955 was reactive. This test makes it proactive.
    command -v goreleaser >/dev/null 2>&1 || skip "goreleaser not installed"

    # Trigger an intentional invalid-skip error to extract the
    # valid list from goreleaser's error message — most reliable
    # source-of-truth across goreleaser versions.
    valid_set="$(goreleaser release --skip=__cli_flag_validity_probe__ 2>&1 \
                  | awk -F'[][]' '/Valid options for skip are/ {print $2}')"

    if [ -z "$valid_set" ]; then
        skip "could not extract goreleaser valid skip values"
    fi

    used_skips="$(grep -hoE -- '--skip=[a-z-]+' "$RELEASE_YML" "$GORELEASER_YML" 2>/dev/null \
                   | sed 's/--skip=//' | sort -u)"

    if [ -z "$used_skips" ]; then
        skip "no --skip= values found in release workflows"
    fi

    for sk in $used_skips; do
        if ! echo "$valid_set" | tr ',' '\n' | tr -d ' ' | grep -qx "$sk"; then
            echo "regression: --skip=$sk used in workflows, but not in goreleaser valid set: $valid_set" >&2
            return 1
        fi
    done
}

# ---------------------------------------------------------------------
# cosign — .goreleaser.yml signs.args invoke `cosign sign-blob`
# ---------------------------------------------------------------------

@test "test_goreleaser_signs_args_exist_in_cosign_sign_blob_help" {
    # PR #949 added --no-new-bundle-format to .goreleaser.yml's signs
    # args — a flag cosign does not have. cosign silently rejected
    # it at v0.2.2 dispatch (the test caught nothing because we
    # only grep'd .goreleaser.yml for the string). This test asserts
    # every flag in signs.args is real.
    command -v cosign >/dev/null 2>&1 || skip "cosign not installed"
    [ -f "$GORELEASER_CONFIG" ] || skip ".goreleaser.yml not present"

    help_output="$(cosign sign-blob --help 2>&1)"
    used_flags="$(awk '
        /^signs:/ {in_signs=1; next}
        in_signs && /^[a-z]/ && !/^signs:/ {in_signs=0}
        in_signs && /--[a-z-]+/ {
            for (i=1; i<=NF; i++) {
                if ($i ~ /--[a-z-]+/) {
                    flag=$i
                    gsub(/^[^-]*/, "", flag)
                    sub(/=.*$/, "", flag)
                    sub(/[^-a-z].*$/, "", flag)
                    if (flag ~ /^--[a-z-]+$/) print flag
                }
            }
        }
    ' "$GORELEASER_CONFIG" | sort -u)"

    if [ -z "$used_flags" ]; then
        skip "no signs.args flags found"
    fi

    for flag in $used_flags; do
        if ! echo "$help_output" | grep -qE -- "(^[[:space:]]*${flag}[[:space:],=]|, ${flag}[[:space:],=])"; then
            echo "regression: .goreleaser.yml signs.args passes ${flag} to cosign sign-blob, but that flag is not in cosign's help." >&2
            return 1
        fi
    done
}
