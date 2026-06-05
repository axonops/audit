#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Shared bats helper for the release-scripts test harness (#925).
#
# Every test that touches the filesystem uses BATS_TEST_TMPDIR so
# nothing leaks between scenarios. Every test that needs to assert
# what a script invoked uses one of the fixture binaries in
# fixtures/bin/, which record their argv to a per-call assertion
# file so the test can grep for "did the script pass --foo".
#
# Conventions
# -----------
#   REPO_ROOT             — absolute path to the audit repo
#   SCRIPTS_DIR           — REPO_ROOT/scripts/release
#   FIXTURES_BIN          — tests/release-scripts/fixtures/bin
#   ASSERTION_DIR         — per-test temp dir holding *.args files
#   make_temp_repo        — initialises a temp git repo (used by
#                            check-tag-conflicts / tag-all tests)
#   stub_path             — prepends FIXTURES_BIN to PATH so the
#                            fixture binaries shadow the real ones

REPO_ROOT="${BATS_TEST_DIRNAME}/../.."
SCRIPTS_DIR="${REPO_ROOT}/scripts/release"
FIXTURES_BIN="${BATS_TEST_DIRNAME}/fixtures/bin"

# stub_path puts FIXTURES_BIN at the front of PATH and points
# ASSERTION_DIR at a fresh temp dir under BATS_TEST_TMPDIR. The
# fixture binaries append "$@" lines to "$ASSERTION_DIR/<name>.args"
# on every invocation, so tests can grep that file to assert what
# the script under test passed to them.
stub_path() {
    ASSERTION_DIR="${BATS_TEST_TMPDIR}/asserts"
    mkdir -p "$ASSERTION_DIR"
    export ASSERTION_DIR
    export PATH="${FIXTURES_BIN}:${PATH}"
}

# make_temp_repo initialises a bare-bones git repo in BATS_TEST_TMPDIR
# with one empty commit, sets local user identity, and disables the
# global / system config so the test does not bleed CI state.
make_temp_repo() {
    local dir="${1:-${BATS_TEST_TMPDIR}/repo}"
    mkdir -p "$dir"
    (
        cd "$dir"
        export GIT_CONFIG_GLOBAL=/dev/null
        export GIT_CONFIG_SYSTEM=/dev/null
        git init --quiet
        git config user.email "test@example.com"
        git config user.name "Test User"
        git commit --quiet --allow-empty -m "init"
    )
    echo "$dir"
}

# fake_publish_modules echoes a deterministic three-row publish
# modules list, matching the make print-publish-modules format
# (dir|module_path|tag_prefix, one per line).
fake_publish_modules() {
    cat <<'EOF'
.|github.com/axonops/audit|
file|github.com/axonops/audit/file|file/
syslog|github.com/axonops/audit/syslog|syslog/
EOF
}

# write_fake_make_makefile writes a minimal Makefile to $1 whose
# `print-publish-modules` target prints fake_publish_modules output.
# Used by check-tag-conflicts and tag-all tests so they don't have
# to rely on the real repo Makefile.
write_fake_make_makefile() {
    local dest="$1"
    # Use printf instead of a nested heredoc — the heredoc form is
    # fragile under bats (the tab/leading whitespace inside the
    # recipe body trips Make's "missing separator" error after the
    # outer cat heredoc closes on it).
    {
        printf '%s\n' 'print-publish-modules:'
        printf '\t@printf %%s\\\\n %s %s %s\n' \
            "'.|github.com/axonops/audit|'" \
            "'file|github.com/axonops/audit/file|file/'" \
            "'syslog|github.com/axonops/audit/syslog|syslog/'"
    } > "$dest"
}

# args_of returns the recorded argv of the i-th call to the named
# fixture binary, or empty if it was not called.
args_of() {
    local name="$1"
    local file="${ASSERTION_DIR}/${name}.args"
    [[ -f "$file" ]] && cat "$file"
}

# called_with reports zero exit if the named binary was called with
# an argv that contains the given substring on any of its lines.
called_with() {
    local name="$1"
    local needle="$2"
    local file="${ASSERTION_DIR}/${name}.args"
    [[ -f "$file" ]] && grep -qF "$needle" "$file"
}
