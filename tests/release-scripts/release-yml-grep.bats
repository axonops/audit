#!/usr/bin/env bats
# Copyright 2026 AxonOps Limited.
# SPDX-License-Identifier: Apache-2.0
#
# Grep-based regression tests for .github/workflows/release.yml,
# locking the v0.2.2 PR-5 (#927) BLOCKER + MAJOR fixes. Each test
# asserts the presence (or absence) of a specific pattern that ties
# back to a BLOCKER letter or MAJOR number in #927's punch list.
#
# These tests are intentionally tightly coupled to release.yml text
# so that a regression — someone editing the file later and
# accidentally re-introducing the bad pattern — fails loudly. The
# inline `# BLOCKER-X fix` / `# MAJOR-N fix` comments on each fix
# in release.yml serve as the canonical anchors.

load 'test_helper.bash'

setup() {
    RELEASE_YML="${REPO_ROOT}/.github/workflows/release.yml"
    [ -f "$RELEASE_YML" ] || skip "release.yml not present"
}

# --- BLOCKER-A — no tail|sed parsing of gh pr create stdout ---

@test "test_release_yml_does_not_use_tail_sed_to_parse_pr_create_output" {
    # The v0.2.1 anti-pattern was `gh pr create ... | tail -n1 | sed ...`.
    # Assert the fixed `--json url --jq '.url'` form is present AND
    # the bad pattern is absent. Use `--` to separate grep options
    # from the pattern (the pattern starts with `--`).
    grep -qF -- "--json url --jq '.url'" "$RELEASE_YML"
    ! grep -qE 'gh pr create.+tail -n.*1' "$RELEASE_YML"
}

# --- BLOCKER-B — allow_auto_merge null classified, not silently false ---

@test "test_release_yml_allow_auto_merge_handles_null_explicitly" {
    grep -qF "Could not read 'allow_auto_merge'" "$RELEASE_YML"
    grep -qF "Administration:read scope" "$RELEASE_YML"
}

# --- BLOCKER-C — recovery snippet validates SHA shape ---

@test "test_release_yml_recovery_snippet_validates_sha_shape" {
    grep -qF '[[ "$MERGE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "PR has not merged yet' "$RELEASE_YML"
}

# --- BLOCKER-D — gh pr list captured before iterating ---

@test "test_release_yml_pr_list_captured_to_file_not_inline_subshell" {
    grep -qF 'stale_prs_file="$(mktemp)"' "$RELEASE_YML"
    # The previous `for pr in $(gh pr list ...)` is gone.
    ! grep -qE 'for pr in [[:space:]]*\$\(gh pr list' "$RELEASE_YML"
}

# --- BLOCKER-E — make print-publish-modules output captured before iterating ---

@test "test_release_yml_print_publish_modules_captured_and_validated" {
    # The fix uses `modules="$(... print-publish-modules ...)"`
    # at all three sites (one with a `cd "$REPO_ROOT"` prefix, one
    # with a `|| true` fallback in the summary table). Match the
    # tail pattern that all three share.
    capture_count="$(grep -cF 'print-publish-modules' "$RELEASE_YML")"
    [ "$capture_count" -ge 3 ]
    capture_count_modules_var="$(grep -cF 'modules="$(' "$RELEASE_YML")"
    [ "$capture_count_modules_var" -ge 3 ]
    validate_count="$(grep -cF '[ -z "$modules" ]' "$RELEASE_YML")"
    [ "$validate_count" -ge 2 ]
}

# --- BLOCKER-F — branch delete no longer swallows errors ---

@test "test_release_yml_branch_delete_does_not_use_or_true" {
    # The previous `git push origin --delete "$BRANCH" || true` is
    # gone. The naked `git push origin --delete "$BRANCH"` is what
    # the fix uses.
    ! grep -qF 'git push origin --delete "$BRANCH" || true' "$RELEASE_YML"
    grep -qF 'git push origin --delete "$BRANCH"' "$RELEASE_YML"
}

# --- MAJOR-2 — summary table branches on event name ---

@test "test_release_yml_summary_table_branches_on_event_name" {
    grep -qF 'if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ]; then' "$RELEASE_YML"
    grep -qF 'workflow_dispatch CI gates skipped — recovery path' "$RELEASE_YML"
}

# --- MAJOR-3 — merge timeout exposed as workflow_dispatch input ---

@test "test_release_yml_merge_timeout_minutes_input_exposed" {
    grep -qF 'merge_timeout_minutes:' "$RELEASE_YML"
    grep -qF 'inputs.merge_timeout_minutes || 45' "$RELEASE_YML"
}

# --- MAJOR-4 — goreleaser verifies CI run for tag SHA ---

@test "test_release_yml_goreleaser_verifies_ci_run_for_tag_sha" {
    grep -qF 'gh run list --commit "$SHA" --workflow ci.yml --status success' "$RELEASE_YML"
}

# --- MAJOR-6 — pr merge exit code is captured ---

@test "test_release_yml_pr_merge_auto_exit_code_is_captured" {
    grep -qF 'if ! gh pr merge "$NUM" --auto --squash; then' "$RELEASE_YML"
}

# --- MAJOR-7 — mutation-test-attach uses App token ---

@test "test_release_yml_mutation_test_attach_uses_app_token" {
    # The fix anchor + the App-token reference in the job's
    # upload step must both be present.
    grep -qF '# MAJOR-7 fix' "$RELEASE_YML"
    # Scope to the mutation-test-attach job: start at its declaration,
    # stop at the next top-level job (2-space indent + word + colon).
    awk '/^  mutation-test-attach:/{p=1} p && /^  [a-z]/{ if(NR>NR_start && !/^  mutation-test-attach:/){exit} } p {print; NR_start=NR}' "$RELEASE_YML" \
        | grep -qF 'GH_TOKEN: ${{ steps.app.outputs.token }}'
}

# --- MAJOR-8 — smoke-test main.go generated from print-publish-modules ---

@test "test_release_yml_smoke_test_imports_generated_from_print_publish_modules" {
    grep -qF '# MAJOR-8 fix' "$RELEASE_YML"
    # The hardcoded blank-import block (`_ "github.com/axonops/audit/webhook"`
    # etc.) is gone — assert one canonical entry from the previous
    # hardcoded list is no longer present as a literal Go import
    # line, AND the generator's printf is present.
    ! grep -qF '_ "github.com/axonops/audit/secrets/openbao"' "$RELEASE_YML"
    grep -qF 'printf' "$RELEASE_YML"
}

# --- MAJOR-9 — bench-advisory step exits 0 ---

@test "test_release_yml_bench_advisory_exits_zero_with_warning" {
    grep -qF '# MAJOR-9 fix' "$RELEASE_YML"
    # The previous `exit "$rc"` at the end of bench-advisory is
    # replaced with `exit 0`. The exact line we want is "exit 0"
    # inside the bench-advisory step.
    awk '/bench-advisory/,/Upload benchmark artifacts/' "$RELEASE_YML" \
        | grep -qF 'exit 0'
}

# --- MINOR-1 — bash parameter expansion replaces echo|sed for SERIES ---

@test "test_release_yml_series_derives_via_parameter_expansion" {
    grep -qF 'NOPRE="${PUBLISH_VERSION%%-*}"' "$RELEASE_YML"
    grep -qF 'SERIES="${NOPRE%.*}.x"' "$RELEASE_YML"
    # The echo|sed form should be gone from the SERIES derivation
    # site (other echo|sed pairs may exist elsewhere; this test
    # checks the named site only).
    ! grep -qE 'SERIES=\$\(echo[[:space:]]+"\$PUBLISH_VERSION"[[:space:]]*\|[[:space:]]*sed' "$RELEASE_YML"
}

# --- PR-6 (#929) — release.yml uses release-tool, not the deleted bash helpers ---

@test "test_release_yml_uses_release_tool_commit_pinned_deps" {
    # The Open-release-PR step must shell out to the Go binary, not
    # the v0.2.1 bash helper. Two anchors must be present together:
    # the build step and the subcommand invocation. The build step
    # may live in any job; the subcommand call site must reside
    # inside update-deps-pr.
    grep -qF "release-tool" "$RELEASE_YML"
    grep -qF 'commit-pinned-deps' "$RELEASE_YML"
    grep -qF '"$RELEASE_TOOL" commit-pinned-deps' "$RELEASE_YML"
    # --owner / --repo must be propagated from the workflow context.
    # Use `--` so grep doesn't try to interpret the pattern as a
    # flag (the pattern starts with `--`).
    grep -qF -- '--owner "${{ github.repository_owner }}"' "$RELEASE_YML"
    grep -qF -- '--repo "${{ github.event.repository.name }}"' "$RELEASE_YML"
}

@test "test_release_yml_no_gh_graphql_helpers" {
    # Hard requirement (issue #929 AC #1): no reference to the
    # deleted bash helpers may remain anywhere in release.yml.
    ! grep -qF "gh-graphql-commit.sh" "$RELEASE_YML"
    ! grep -qF "gh-graphql-tag.sh" "$RELEASE_YML"
}

@test "test_release_yml_builds_release_tool_with_trimpath" {
    # The build step must use -trimpath so the embedded binary
    # paths don't leak the runner's GOPATH layout into stack
    # traces. The build was extracted into a composite action in
    # PR-6 (#929); assertions move with it.
    ACTION="${REPO_ROOT}/.github/actions/build-release-tool/action.yml"
    [ -f "$ACTION" ] || skip "composite action missing"
    grep -qF 'go build -trimpath' "$ACTION"
    grep -qF '"${RUNNER_TEMP}/release-tool"' "$ACTION"
    grep -qF 'RELEASE_TOOL=${RUNNER_TEMP}/release-tool' "$ACTION"
}

@test "test_release_yml_recovery_uses_release_tool_not_bash_helpers" {
    # The wait-for-pr-merge timeout recovery snippet must reference
    # `release-tool create-tag`, not the deleted bash helper.
    grep -qF 'release-tool create-tag' "$RELEASE_YML"
}

@test "test_release_yml_tag_all_step_propagates_gh_token_to_release_tool" {
    # PR-6 (#929) security H1: release-tool reads $GH_TOKEN via
    # os.Getenv. tag-all.sh shells out per published module, so
    # the "Run tag-all.sh" step MUST export the App token. Without
    # this, every release fails with N×exit-3 from release-tool.
    # Anchor: the step's env block must include
    # `GH_TOKEN: ${{ steps.app.outputs.token }}` alongside
    # GH_OWNER / GH_REPO.
    awk '/Run tag-all.sh \(idempotent\)/,/run: scripts\/release\/tag-all.sh/' \
        "$RELEASE_YML" \
        | grep -qF 'GH_TOKEN: ${{ steps.app.outputs.token }}'
}

@test "test_release_yml_uses_composite_build_release_tool_action" {
    # PR-6 (#929) MINOR-1 fix: extract the duplicate inline
    # build-release-tool steps into a single composite action so
    # the two callers (update-deps-pr, tag-all) stay byte-
    # identical. The action lives at .github/actions/build-release-tool.
    # Both call sites must reference the composite path.
    n="$(grep -cF 'uses: ./.github/actions/build-release-tool' "$RELEASE_YML")"
    [ "$n" -ge 2 ]
    # An inline build STEP (i.e. a step header named "Build release-tool"
    # followed by an inline `run: ... go build ...`) MUST NOT reappear:
    # the composite-action extraction was specifically to prevent the
    # release.yml callers from drifting against each other. The
    # operator-pastable recovery snippet inside the wait-for-pr-merge
    # block is a different beast (a here-doc echo, not a build step)
    # and is allowed.
    ! awk '
        /^      - name: Build release-tool$/ {flag=1; next}
        flag && /^      - name:/ {flag=0}
        flag && /run:[[:space:]]*\|/ {found=1}
        END {exit found ? 0 : 1}
    ' "$RELEASE_YML"
}

@test "test_release_yml_recovery_pins_working_tree_to_merge_sha" {
    # PR-6 (#929) devops MAJOR-4 fix: the operator-paste recovery
    # snippet pins the working tree to $MERGE_SHA before building
    # release-tool. Without this the operator may build a stale
    # binary from a dirty local clone.
    grep -qF 'git checkout --detach "$MERGE_SHA" --' "$RELEASE_YML"
}

@test "test_release_yml_recovery_quotes_owner_and_repo" {
    # PR-6 (#929) security M1: the operator-paste recovery
    # snippet quotes --owner / --repo so future repo renames or
    # namespace changes don't break copy-paste behaviour.
    grep -qF -- '--owner "${{ github.repository_owner }}"' "$RELEASE_YML"
    grep -qF -- '--repo "${{ github.event.repository.name }}"' "$RELEASE_YML"
}

@test "test_release_yml_tag_all_timeout_minutes_at_least_15" {
    # PR-6 (#929) devops MAJOR-1 fix: tag-all now does Go setup +
    # release-tool build + per-module REST tag creates. timeout=10
    # was too tight; bumped to ≥15 to match the parallel
    # wait-for-pr-merge / verify jobs.
    awk '/^  tag-all:/,/^  goreleaser:/' "$RELEASE_YML" \
        | grep -qE 'timeout-minutes: (1[5-9]|[2-9][0-9])'
}

@test "test_build_release_tool_action_pins_proxy_and_readonly" {
    # PR-6 (#929) devops MAJOR-3 fix: the composite action pins
    # GOPROXY / GOSUMDB / GOFLAGS for the release-critical build
    # so a hostile runner env can't substitute a malicious proxy
    # or silently mutate go.sum.
    ACTION="${REPO_ROOT}/.github/actions/build-release-tool/action.yml"
    [ -f "$ACTION" ] || skip "composite action missing"
    grep -qF 'GOFLAGS: -mod=readonly' "$ACTION"
    grep -qF 'GOPROXY: https://proxy.golang.org,direct' "$ACTION"
    grep -qF 'GOSUMDB: sum.golang.org' "$ACTION"
}

@test "test_build_release_tool_action_caches_on_submodule_go_sum" {
    # PR-6 (#929) devops MAJOR-2 fix: the composite action caches
    # on cmd/release-tool/go.sum (the actual sub-module deps)
    # rather than the root go.sum, so root-module changes don't
    # uselessly bust this cache.
    ACTION="${REPO_ROOT}/.github/actions/build-release-tool/action.yml"
    [ -f "$ACTION" ] || skip "composite action missing"
    grep -qF 'cache-dependency-path: cmd/release-tool/go.sum' "$ACTION"
    grep -qF 'go-version-file: cmd/release-tool/go.mod' "$ACTION"
}
