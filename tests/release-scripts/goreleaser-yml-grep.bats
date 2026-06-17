#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Grep-based regression tests for .github/workflows/goreleaser.yml
# and .goreleaser.yml, locking the v0.2.2 PR-7 (#943) BLOCKER-7 +
# MAJOR-6 fixes. Each test asserts the presence (or absence) of a
# specific pattern that ties back to one fix in #943's punch list.
#
# These tests are intentionally tightly coupled to the workflow and
# goreleaser-config text so that a regression — someone editing the
# files later and accidentally re-introducing the bad pattern —
# fails loudly. The inline `# PR-7 (#943) ... fix` comments on each
# fix in the source files serve as the canonical anchors.

load 'test_helper.bash'

setup() {
    GORELEASER_YML="${REPO_ROOT}/.github/workflows/goreleaser.yml"
    GORELEASER_CONFIG="${REPO_ROOT}/.goreleaser.yml"
    [ -f "$GORELEASER_YML" ] || skip "goreleaser.yml not present"
    [ -f "$GORELEASER_CONFIG" ] || skip ".goreleaser.yml not present"
}

# --- BLOCKER-7 — mandatory version input on workflow_dispatch ---

@test "test_goreleaser_yml_workflow_dispatch_requires_version_input" {
    # The manual-rerun trigger must declare a required `version`
    # input. Without it the workflow accepts any dispatch and the
    # concurrency group falls back to github.ref_name, defeating the
    # release-yml serialisation.
    #
    # awk range: from `^on:` (inclusive) to `^permissions:`
    # (exclusive) so the on: block is the only thing seen. Using
    # `^[^[:space:]]` as the end pattern would stop on the `on:`
    # line itself because awk includes the first line in the range.
    awk '/^on:/{p=1} /^permissions:/{p=0} p' "$GORELEASER_YML" \
        | grep -qF 'version:'
    awk '/^on:/{p=1} /^permissions:/{p=0} p' "$GORELEASER_YML" \
        | grep -qF 'required: true'
}

@test "test_goreleaser_yml_concurrency_uses_inputs_version_only" {
    # The concurrency group must derive from inputs.version with no
    # github.ref_name fallback. The fallback only existed because the
    # input wasn't required; now that it is, the fallback would
    # never be reached AND would hide the regression if someone
    # dropped `required: true`.
    grep -qF 'group: release-${{ inputs.version }}' "$GORELEASER_YML"
    # Negative assertion: the literal fallback expression must not
    # reappear as the group definition. Comments above the
    # concurrency block legitimately reference the old fallback
    # to explain the BLOCKER-7 fix; the regression we care about is
    # an actual `group:` line re-introducing it.
    ! grep -qF 'group: release-${{ inputs.version || github.ref_name }}' "$GORELEASER_YML"
}

@test "test_goreleaser_yml_validates_version_format" {
    # The validation step must use the same regex as tag-all.sh
    # (vMAJOR.MINOR.PATCH[-PRE]). The anchor pattern is the exact
    # `=~` test on $VERSION.
    grep -qF -- '[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]' "$GORELEASER_YML"
    # Backup invariant — survives a YAML reformat that re-quotes
    # the inner string. Asserts SOME `=~ ^v[0-9]` test exists, even
    # if the exact line above changes shape.
    grep -qF -- '=~ ^v[0-9]' "$GORELEASER_YML"
    # The validation step must exit non-zero on a bad version.
    grep -qF 'invalid version input' "$GORELEASER_YML"
}

@test "test_goreleaser_yml_validates_version_length_cap" {
    # PR-7 (#943) defence-in-depth: a malicious operator with a
    # leaked PAT could otherwise submit a 16KB string passing the
    # regex (e.g. `v0.0.0-` + giant valid-character prerelease) and
    # collide on the GitHub concurrency-group's 255-char silent
    # truncation. The 64-char cap prevents both that exfil vector
    # and any future ref-fetch DOS amplification.
    grep -qF '"${#VERSION}" -gt 64' "$GORELEASER_YML"
    grep -qF 'version input too long' "$GORELEASER_YML"
}

@test "test_goreleaser_yml_checks_out_inputs_version_ref" {
    # Checkout must pin to the tag commit (inputs.version) rather
    # than the dispatcher's branch. Without this the build runs
    # against whatever ref the operator's `gh workflow run` happened
    # to default to.
    grep -qF 'ref: ${{ inputs.version }}' "$GORELEASER_YML"
}

@test "test_goreleaser_yml_drops_ref_type_tag_gate" {
    # The previous `if: github.ref_type == 'tag'` gate was meaningful
    # while the workflow accepted any dispatch; with a required
    # version input, the gate is dead code (the inputs.version
    # validation already constrains to tag-shaped strings, and
    # checkout pins to that ref). Removing avoids a confusing
    # "workflow ran but did nothing" outcome when the dispatcher
    # forgets to dispatch against a tag ref. This test catches
    # accidental re-introduction.
    ! grep -qF "github.ref_type == 'tag'" "$GORELEASER_YML"
}

# --- MAJOR-6 — invariants before.hooks re-enabled ---

@test "test_goreleaser_yml_before_hooks_runs_release_invariants" {
    # .goreleaser.yml MUST run `make check-release-invariants
    # VERSION={{ .Tag }}` as a before-hook. Without it, an out-of-
    # band tag (someone pushes a tag without going through
    # release.yml's update-deps-pr) would produce a broken artifact
    # set with no early signal.
    grep -qF 'check-release-invariants VERSION={{ .Tag }}' "$GORELEASER_CONFIG"
    # The previous explicitly-empty `hooks: []` form must be gone.
    ! grep -qE '^[[:space:]]+hooks: \[\]' "$GORELEASER_CONFIG"
}

@test "test_make_check_release_invariants_fails_without_version" {
    # Behavioural test: the invariant target the before-hook calls
    # MUST exit non-zero when invoked without a VERSION arg. This
    # guards against the Makefile target silently no-op'ing under
    # GoReleaser's template substitution if `{{ .Tag }}` were ever
    # to expand to empty (e.g. a tagless snapshot build) — the
    # release would then proceed without the invariant catching a
    # bad state.
    cd "${REPO_ROOT}"
    run make check-release-invariants
    [ "$status" -ne 0 ]
    [[ "$output" =~ "VERSION is required" ]]
}

@test "test_make_check_release_invariants_fails_on_misaligned_version" {
    # Behavioural test: confirm the invariant target actually BITES
    # when invoked with a version no go.mod references. This is the
    # exact failure mode the MAJOR-6 before-hook is meant to catch:
    # an out-of-band tag (someone tags v0.2.2 on a commit whose
    # go.mod files still reference v0.2.1). Without this assertion,
    # the grep-presence test alone would not detect a Makefile
    # regression where check-release-invariants silently no-ops.
    cd "${REPO_ROOT}"
    run make check-release-invariants VERSION=v0.0.0-never-released
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Release invariants failed" ]]
}

# --- #958 — collapse goreleaser tag-detection bandages ---

@test "test_goreleaser_no_skip_before" {
    # #958: --skip=before was a v0.2.2-only bandage for the
    # lightweight-tag template issue. GORELEASER_CURRENT_TAG (kept
    # below) is the structural fix; --skip=before would re-mask
    # invariant-hook regressions if reintroduced.
    ! grep -qF -- '--skip=before' "$GORELEASER_YML"
}

@test "test_goreleaser_no_cosign_release_pin" {
    # #958: the cosign-installer pin to v2.5.3 was added by #950 to
    # paper over cosign v2.6's --new-bundle-format default. The
    # signs: stanza now uses the bundle format natively, so the
    # pin is no longer needed. Re-introducing it would fight the
    # new sign-blob recipe.
    ! grep -qE "cosign-release:[[:space:]]*['\"]?v2\.5" "$GORELEASER_YML"
}

@test "test_goreleaser_keeps_current_tag_env" {
    # #958: GORELEASER_CURRENT_TAG (#951) is THE actual fix for the
    # lightweight-tag template issue and MUST stay even after the
    # other bandages collapse.
    grep -qF 'GORELEASER_CURRENT_TAG: ${{ inputs.version }}' "$GORELEASER_YML"
}

@test "test_goreleaser_signs_uses_bundle_format" {
    # #958: signs: stanza migrated to cosign v2.6 bundle format —
    # one --bundle flag instead of --output-signature +
    # --output-certificate (+ --no-new-bundle-format). Verifies the
    # forward-compatible single-file layout.
    grep -qE -- "--bundle=\\$\\{signature\\}" "$GORELEASER_CONFIG"
    grep -qF "signature: '\${artifact}.bundle'" "$GORELEASER_CONFIG"
    # Negatives: the split-file flags MUST NOT reappear.
    ! grep -qF -- '--output-signature=${signature}' "$GORELEASER_CONFIG"
    ! grep -qF -- '--output-certificate=${certificate}' "$GORELEASER_CONFIG"
    ! grep -qF -- '--no-new-bundle-format' "$GORELEASER_CONFIG"
}

@test "test_releasing_docs_uses_bundle_verifier_recipe" {
    # #958: docs/releasing.md verifier recipe migrated to the
    # cosign --bundle flag (single .bundle file). The split
    # --signature + --certificate flags MUST NOT reappear in any
    # cosign verify-blob example.
    DOCS="${REPO_ROOT}/docs/releasing.md"
    [ -f "$DOCS" ] || skip "docs/releasing.md not present"
    # Positive: every verify-blob recipe uses --bundle.
    grep -qF -- '--bundle checksums.txt.bundle' "$DOCS"
    # Negative: split-flag form is gone from runnable examples.
    # Grep for the literal flag inside `cosign verify-blob` shell
    # blocks. The narrative prose at the top of "Verify a Release
    # with Cosign" legitimately references the old .sig/.pem file
    # names — `--signature ` would only appear as a CLI argument
    # in a code block.
    ! grep -qF -- '--signature checksums.txt.sig' "$DOCS"
    ! grep -qF -- '--certificate checksums.txt.pem' "$DOCS"
}
