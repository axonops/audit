#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Tests for scripts/release/regen-docs.sh — verifies --check mode
# vs rewrite mode, marker preservation, and the auto-generated
# PUBLISH_MODULES table (#925).

load 'test_helper.bash'

BEGIN_MARKER='<!-- BEGIN PUBLISH_MODULES TABLE — do not edit; run `make regen-release-docs` to update -->'
END_MARKER='<!-- END PUBLISH_MODULES TABLE -->'

setup() {
    stub_path
    REPO_ROOT_TMP="${BATS_TEST_TMPDIR}/repo"
    mkdir -p "$REPO_ROOT_TMP/scripts/release"
    install -m 0755 "${SCRIPTS_DIR}/regen-docs.sh" \
        "$REPO_ROOT_TMP/scripts/release/regen-docs.sh"
    write_fake_make_makefile "$REPO_ROOT_TMP/Makefile"
    SCRIPT="$REPO_ROOT_TMP/scripts/release/regen-docs.sh"
    cd "$REPO_ROOT_TMP" || return 1
}

# write_in_sync_docs writes a docs file whose marker region already
# contains the table the script would generate. Used as the
# baseline for `--check exits 0` and `rewrite preserves text` tests.
write_in_sync_docs() {
    local dest="$1"
    cat > "$dest" <<EOF
# Releasing

Some preamble paragraph that must survive a rewrite.

$BEGIN_MARKER

| Module | Path | Tag prefix |
|--------|------|------------|
| \`(repo root)\` | \`github.com/axonops/audit\` | \`v*\` |
| \`file\` | \`github.com/axonops/audit/file\` | \`file/v*\` |
| \`syslog\` | \`github.com/axonops/audit/syslog\` | \`syslog/v*\` |

$END_MARKER

Some trailing paragraph that must also survive a rewrite.
EOF
}

@test "test_regen_docs_no_args_exits_2" {
    run "$SCRIPT"
    [ "$status" -eq 2 ]
    [[ "$output" =~ Usage ]]
}

@test "test_regen_docs_missing_markers_exits_2" {
    cat > docs.md <<'EOF'
# Releasing

This file has no markers.
EOF
    run "$SCRIPT" docs.md
    # The script exits 1 (validation) with "must contain exactly
    # one BEGIN and one END marker". Treating "missing markers"
    # as 2 would conflate with usage errors; the script
    # distinguishes them.
    [ "$status" -eq 1 ]
    [[ "$output" =~ "must contain exactly one BEGIN and one END" ]]
}

@test "test_regen_docs_check_mode_in_sync_exits_0" {
    # Build the in-sync baseline by running the script in rewrite
    # mode on a marker-only file — the result is byte-exact what
    # --check accepts.
    cat > docs.md <<EOF
preamble

$BEGIN_MARKER
$END_MARKER

trailing
EOF
    "$SCRIPT" docs.md
    run "$SCRIPT" --check docs.md
    [ "$status" -eq 0 ]
    [[ "$output" =~ "in sync" ]]
}

@test "test_regen_docs_check_mode_out_of_sync_exits_1" {
    # Same markers, but a deliberately-wrong table inside.
    cat > docs.md <<EOF
$BEGIN_MARKER

| Module | Path | Tag prefix |
|--------|------|------------|
| \`outdated\` | \`junk\` | \`junk\` |

$END_MARKER
EOF
    run "$SCRIPT" --check docs.md
    [ "$status" -eq 1 ]
    [[ "$output" =~ "OUT OF SYNC" ]]
}

@test "test_regen_docs_module_order_change_detected_in_check_mode" {
    # Correct entries but in the wrong order — the script must
    # detect this because the diff is content-sensitive.
    cat > docs.md <<EOF
$BEGIN_MARKER

| Module | Path | Tag prefix |
|--------|------|------------|
| \`syslog\` | \`github.com/axonops/audit/syslog\` | \`syslog/v*\` |
| \`file\` | \`github.com/axonops/audit/file\` | \`file/v*\` |
| \`(repo root)\` | \`github.com/axonops/audit\` | \`v*\` |

$END_MARKER
EOF
    run "$SCRIPT" --check docs.md
    [ "$status" -eq 1 ]
    [[ "$output" =~ "OUT OF SYNC" ]]
}

@test "test_regen_docs_rewrite_mode_preserves_markers_and_surrounding_text" {
    # Start out-of-sync but with valid markers + surrounding text.
    cat > docs.md <<EOF
# Releasing

Some preamble paragraph that must survive a rewrite.

$BEGIN_MARKER

old contents to be replaced

$END_MARKER

Some trailing paragraph that must also survive a rewrite.
EOF
    run "$SCRIPT" docs.md
    [ "$status" -eq 0 ]
    # Preamble + trailing paragraphs survived.
    grep -qF "Some preamble paragraph" docs.md
    grep -qF "Some trailing paragraph" docs.md
    # Both markers are still present (exactly one of each).
    [ "$(grep -cF "$BEGIN_MARKER" docs.md)" -eq 1 ]
    [ "$(grep -cF "$END_MARKER" docs.md)" -eq 1 ]
    # Generated table is now in sync.
    grep -qF "github.com/axonops/audit/file" docs.md
}
