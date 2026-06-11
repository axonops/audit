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
    # The PR-5 (#927) attempt at `--json url --jq '.url'` was wrong:
    # `gh pr create` does NOT support `--json` — that flag exists
    # only on `gh pr view`/`list`. The v0.2.2 dispatch run
    # 27149700917 surfaced this. The correct pattern is to capture
    # stdout directly (gh pr create writes only the URL on success)
    # and validate the shape with a regex.
    #
    # Assert:
    #   1. The PR_URL capture has NO sub-command parsing (no tail,
    #      no sed, no --json, no --jq).
    #   2. The validation regex on the captured value is present.
    ! grep -qE 'gh pr create.+tail -n.*1' "$RELEASE_YML"
    ! grep -qF -- "--json url --jq '.url'" "$RELEASE_YML"
    grep -qF 'PR_URL=$(gh pr create' "$RELEASE_YML"
    grep -qF -- '[[ "$PR_URL" =~ ^https://github\.com/.+/pull/[0-9]+$ ]]' "$RELEASE_YML"
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

# --- #956 — goreleaser/verify/invariants run on push:tag recovery ---

@test "test_release_yml_goreleaser_uses_if_always" {
    # #956 fix: without `always() && needs.X.result == 'success' && ...`
    # the implicit "all needs must succeed" gate treats the *skipped*
    # workflow_dispatch-only upstreams as not-yet-success on the
    # push:tag path, so goreleaser silently skips. v0.2.2's push:tag
    # run 27181087721 hit exactly this. Verify the goreleaser job's
    # body contains `always() &&` and gates on preflight + tag-all.
    body=$(awk '/^  goreleaser:/,/^  verify:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'always() &&'
    echo "$body" | grep -qF "needs.preflight.result == 'success'"
    echo "$body" | grep -qF "needs.tag-all.result == 'success'"
}

@test "test_release_yml_verify_uses_if_always" {
    # Same rationale as goreleaser above (#956). The verify job
    # gates on goreleaser succeeding; without `always() && ...` it
    # cascade-skipped on the push:tag path.
    body=$(awk '/^  verify:/,/^  invariants:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'always() &&'
    echo "$body" | grep -qF "needs.preflight.result == 'success'"
    echo "$body" | grep -qF "needs.goreleaser.result == 'success'"
}

@test "test_release_yml_invariants_uses_if_always" {
    # The post-release sanity gate (#956). Must run on every
    # successful end-to-end release, including push:tag recovery.
    # Extract from `invariants:` to the next top-level job header
    # (`post-release-tidy:` since #959 inserted the new job between
    # invariants and summary).
    body=$(awk '/^  invariants:/,/^  post-release-tidy:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'always() &&'
    echo "$body" | grep -qF "needs.preflight.result == 'success'"
    echo "$body" | grep -qF "needs.tag-all.result == 'success'"
    echo "$body" | grep -qF "needs.verify.result == 'success'"
}

# --- #959 — post-release auto-tidy ---

@test "test_release_yml_post_release_tidy_step_exists" {
    # #959: after tag-all publishes the v* tags, every sub-module's
    # go.sum gains entries for the just-published version. Without
    # an auto-tidy step, main's Hygiene tidy-check fails IMMEDIATELY
    # post-release and every fix PR has to be admin-merged. The job
    # runs `make tidy` against main, App-signs the diff via
    # release-tool commit-pinned-deps, and opens an auto-merge PR.
    body=$(awk '/^  post-release-tidy:/,/^  summary:/' "$RELEASE_YML")
    # Job name is the documented anchor for #959.
    echo "$body" | grep -qF 'post-release-tidy:'
    # The job must run `make tidy` (the actual fix step).
    echo "$body" | grep -qF 'run: make tidy'
    # No-diff path is a clean exit, not a failure.
    echo "$body" | grep -qF 'no post-release drift to absorb'
    # Uses the existing release-tool commit-pinned-deps subcommand —
    # its allowlist already covers go.mod + go.sum, which is exactly
    # the post-tidy diff surface.
    echo "$body" | grep -qF 'commit-pinned-deps'
    # Branch name pattern (#959 documented anchor).
    echo "$body" | grep -qF 'chore/post-release-tidy-'
    # #956 pattern — explicit always() gate so push:tag also runs
    # this job.
    echo "$body" | grep -qF 'always() &&'
    echo "$body" | grep -qF "needs.invariants.result == 'success'"
    # Summary table must list the new job's result.
    grep -qF 'needs.post-release-tidy.result' "$RELEASE_YML"
    # Summary `needs:` list must include post-release-tidy.
    awk '/^  summary:/,/^[^[:space:]]/' "$RELEASE_YML" | grep -qE '^[[:space:]]+- post-release-tidy$'
}

# --- #967 — preflight-tidy self-healing on go.sum drift ---

@test "test_release_yml_preflight_tidy_job_exists" {
    # #967 fix: the preflight-tidy job mirrors post-release-tidy
    # (#959/#966) on the PRE-side of the release flow. v0.2.3's
    # dispatch (run 27325930898) failed because main's go.sum
    # carried v0.2.2's post-tag drift residue; this job runs
    # `make tidy` and absorbs the diff via release-tool's existing
    # commit-pinned-deps subcommand.
    body=$(awk '/^  preflight-tidy:/,/^  ci:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'preflight-tidy:'
    echo "$body" | grep -qF 'run: make tidy'
    echo "$body" | grep -qF 'preflight-tidy-check'
    echo "$body" | grep -qF 'commit-pinned-deps'
    echo "$body" | grep -qF 'chore/preflight-tidy-'
}

@test "test_release_yml_preflight_tidy_gated_on_workflow_dispatch" {
    # #967: the recovery push:tag path assumes a clean tag-commit
    # state; preflight-tidy is workflow_dispatch only.
    body=$(awk '/^  preflight-tidy:/,/^  ci:/' "$RELEASE_YML")
    echo "$body" | grep -qF "github.event_name == 'workflow_dispatch'"
}

@test "test_release_yml_preflight_tidy_enforces_go_sum_only" {
    # #967 gate 1: msgGoModModified — see
    # cmd/release-tool/cmd_preflight_tidy_check.go. The exact AC #4
    # error string must be greppable in the workflow body or the
    # subcommand wiring so a regression that mis-emits the string
    # fails the grep.
    grep -qF 'preflight-tidy: go.mod modified — aborting' \
        "${REPO_ROOT}/cmd/release-tool/cmd_preflight_tidy_check.go"
}

@test "test_release_yml_preflight_tidy_rejects_deletions" {
    # #967 gate 2: msgGoSumDeletions.
    grep -qF 'preflight-tidy: go.sum lines deleted — aborting' \
        "${REPO_ROOT}/cmd/release-tool/cmd_preflight_tidy_check.go"
}

@test "test_release_yml_preflight_tidy_cross_checks_sum_golang_org" {
    # #967 gate 4: sum.golang.org cross-check. Verify both the
    # workflow wires the sumdb endpoint AND the subcommand emits
    # the AC #4 disagree + transient strings.
    body=$(awk '/^  preflight-tidy:/,/^  ci:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'https://sum.golang.org'
    grep -qF 'preflight-tidy: sum.golang.org disagrees — aborting' \
        "${REPO_ROOT}/cmd/release-tool/cmd_preflight_tidy_check.go"
    grep -qF 'preflight-tidy: sum.golang.org timeout or 5xx — aborting' \
        "${REPO_ROOT}/cmd/release-tool/cmd_preflight_tidy_check.go"
}

@test "test_release_yml_preflight_tidy_opens_auto_merge_pr" {
    # #967 gate 5: PR-not-direct-push. The workflow must use
    # release-tool's App-signed commit-pinned-deps subcommand,
    # then gh pr create + gh pr merge --auto.
    body=$(awk '/^  preflight-tidy:/,/^  ci:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'commit-pinned-deps'
    echo "$body" | grep -qF 'gh pr create'
    echo "$body" | grep -qF -- '--auto --squash'
    echo "$body" | grep -qF 'preflight-tidy: PR opened'
    echo "$body" | grep -qF 'preflight-tidy: PR auto-merge refused — aborting'
}

@test "test_release_yml_preflight_tidy_honours_skip_input" {
    # #967 gate 6: inputs.skip_preflight_tidy escape hatch. The
    # workflow must declare the input AND emit the AC #4 string
    # when set, plus surface a ::warning:: and a GFM CAUTION block.
    grep -qF 'skip_preflight_tidy:' "$RELEASE_YML"
    body=$(awk '/^  preflight-tidy:/,/^  ci:/' "$RELEASE_YML")
    echo "$body" | grep -qF 'preflight-tidy: skipped via skip_preflight_tidy input'
    echo "$body" | grep -qF '::warning::'
    echo "$body" | grep -qF '[!CAUTION]'
}

@test "test_release_yml_preflight_tidy_emits_exact_error_strings" {
    # Property-style: every AC #4 exact string must appear at least
    # once in the workflow body OR the subcommand source. Any miss
    # means the operator-facing contract is broken.
    SUBCMD="${REPO_ROOT}/cmd/release-tool/cmd_preflight_tidy_check.go"
    # Strings the SUBCOMMAND emits (idempotent + validation paths).
    grep -qF 'preflight-tidy: no drift to absorb' "$SUBCMD"
    grep -qF 'preflight-tidy: go.mod modified — aborting' "$SUBCMD"
    grep -qF 'preflight-tidy: go.sum lines deleted — aborting' "$SUBCMD"
    grep -qF 'preflight-tidy: unrelated checksum lines — aborting' "$SUBCMD"
    grep -qF 'preflight-tidy: sum.golang.org disagrees — aborting' "$SUBCMD"
    grep -qF 'preflight-tidy: sum.golang.org timeout or 5xx — aborting' "$SUBCMD"
    # Diff-size-cap defence-in-depth string (test-analyst review).
    grep -qF 'preflight-tidy: diff exceeds 8 KiB cap — aborting' "$SUBCMD"
    # Strings the WORKFLOW emits (PR + skip paths).
    grep -qF 'preflight-tidy: PR opened' "$RELEASE_YML"
    grep -qF 'preflight-tidy: PR auto-merge refused — aborting' "$RELEASE_YML"
    grep -qF 'preflight-tidy: skipped via skip_preflight_tidy input' "$RELEASE_YML"
}

@test "test_release_yml_preflight_tidy_in_summary_needs" {
    # AC #6: summary lists preflight-tidy in needs and its result
    # in the status table.
    awk '/^  summary:/,/^[^[:space:]]/' "$RELEASE_YML" \
        | grep -qE '^[[:space:]]+- preflight-tidy$'
    grep -qF 'needs.preflight-tidy.result' "$RELEASE_YML"
}
