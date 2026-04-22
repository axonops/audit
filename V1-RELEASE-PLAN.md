# v1.0.0 Release Plan

Master tracker issue: **[#472](https://github.com/axonops/audit/issues/472)**.

This document is the in-repo index for the v1.0.0 release. It cross-references every v1.0-scope GitHub issue, captures the order of execution, records walkthrough scope decisions, and serves as a local progress tracker.

GitHub is the authoritative source for issue status. When an issue closes, tick the corresponding box here for at-a-glance progress.

---

## Status snapshot

- **Master tracker:** #472 (labelled `v1.0.0`, `P0`).
- **v1.0.0 child issues:** 140 new (#473–#612) plus 10 pre-existing.
- **Post-v1.0 placeholders (NOT v1.0-labelled):** 8 (#613–#620).
- **Issues dropped from scope:** 4 (Merkle HMAC, multi-category dedup, Helm chart, secret-provider regression test).

## Order of execution

Tracks proceed in this order. Within a track, issues may be parallelised except where explicit sequencing is called out in each issue body.

1. **Track A — Security and Correctness.** Defects and stability commitments. Must land first because they are bugs, not design decisions.
2. **Track C — Performance.** Hot-path measurement informs API choices.
3. **Track B — API Shape.** Locks the v1.0 public-API contract.
4. **Track D — CI/CD and Release Pipeline.** `gorelease` baselines the API — run once the API is stable.
5. **Track E — Documentation.** Consolidated pass after behaviour and API are locked (avoids rewriting docs twice).
6. **Track F — Tests and BDD.** Tests the final state, not an intermediate one.
7. **Track G — Consumer Deployment.** Depends on every preceding decision.

After every track completes: re-run all ten review agents over the changed surface. Only after Track G completes and the final full-suite review passes do we tag v1.0.0.

## Implementation process (per issue)

Every issue follows this sequence. Do not skip steps.

1. **Plan agent** first — identify files, dependencies, test scenarios. Update the plan as you go; clean it up when done.
2. **Before coding — consult relevant agents:**
   - code-reviewer, api-ergonomics-reviewer, security-reviewer, performance-reviewer, test-analyst, test-writer, docs-writer, user-guide-reviewer, devops — pick the ones relevant to the work. If in doubt, consult.
3. **Code + tests together** — never write code without its tests. BDD scenarios in the same PR, not "later".
4. **After coding — run agents** in order: test-analyst → code-reviewer → api-ergonomics-reviewer (if public API) → security-reviewer (if TLS/HTTP/creds/external input) → performance-reviewer (if hot path) → docs-writer (if docs) → user-guide-reviewer (if user-facing docs) → devops (if CI/CD).
5. **`make check`** must pass. Then go-quality agent as final automated gate.
6. **commit-message-reviewer** on every commit message. Non-negotiable.
7. **Push + watch CI.** Never start the next PR while current CI is red or unmerged. One PR at a time.
8. **Clean up** — plan, stale branches, memory updates.
9. **issue-closer** agent verifies every acceptance criterion before `gh issue close`.

---

## Track A — Security and Correctness (20 issues)

[GitHub issue view](https://github.com/axonops/audit/issues?q=is%3Aissue+is%3Aopen+label%3Av1.0.0+%22security%22+OR+%22fix%22)

- [x] **#473** security: include _hmac_v inside HMAC authenticated bytes — HMAC authenticity hole (code-reviewer C3, verified against `drain.go:183-192`). ✅ Merged in PR #623 (2026-04-17).
- [x] **#474** fix: atomic.Pointer for diagnostic logger in async outputs — data race across webhook/file/syslog/loki. ✅ Merged in PR #629 (2026-04-18).
- [ ] **#475** security: strip credentials from Webhook and Loki Config.String() output — token leakage via `%v` / `%+v` debug.
- [ ] **#476** fix: apply global tls_policy to loki and secret providers — injection currently only covers syslog/webhook.
- [ ] **#477** security: enforce character-set validation on taxonomy event types and field names — `^[a-z][a-z0-9_]*$`.
- [x] ~~**#478** security: reject restricted HTTP header names in webhook output config — Host / Content-Length / Transfer-Encoding.~~ **Closed as won't-do (2026-04-18)** — library is outbound-only HTTP client; `net/http` already manages transport-level concerns; CRLF injection check on header values remains in place. Full rationale in issue close comment.
- [ ] **#479** security: document and minimise secret memory retention across secret resolution and outputs.
- [ ] **#480** security: extend SSRF block list to cover AWS IPv6 IMDS and IPv6-mapped IPv4 edge cases.
- [ ] **#481** test: add fuzz targets for ParseTaxonomyYAML, outputconfig.Load, ParseRef, ExpandEnvString.
- [x] ~~**#482** security: sign release artifacts with Cosign keyless OIDC.~~ **Closed as won't-do (2026-04-18)** — GitHub `attest-build-provenance` action already present in release.yml + goreleaser.yml; same Sigstore/Fulcio/Rekor primitives as Cosign keyless, just different verifier CLI. Reopen only if a consumer specifically needs `.sig`/`.pem` assets (e.g. Cosign Policy Controller).
- [ ] **#483** security: validate HMAC verification inputs before constant-time compare.
- [ ] **#484** security: cap response body drain on 3xx redirects in webhook and loki.
- [ ] **#485** security: enforce ResponseHeaderTimeout minimum floor in webhook and loki.
- [ ] **#486** security: redact all path and key material in ParseRef error messages.
- [ ] **#487** security: preserve string semantics through envsubst — never re-marshal expanded values.
- [ ] **#488** fix: panic at init if hardcoded CGNAT CIDR cannot be parsed.
- [ ] **#489** fix: log syslog reconnect Close error at debug level.
- [x] **#490** refactor: thread diagnostic logger through output construction warnings (precedes #474). ✅ Merged in PR #628 (2026-04-18).
- [ ] **#491** docs: document middleware panic-recovery placement requirements.
- [ ] **#492** refactor: document dropLimiter window-boundary counting semantics.

**Sequencing:** #490 must merge BEFORE #474 — #474 assumes the atomic-field infrastructure #490 introduces. #473 and #483 both touch `hmac.go` — consider combining into one PR.

---

## Track C — Performance (20 issues + 1 existing)

- [ ] **#461** (existing, converted) perf: benchmark file output batch writes vs per-event flush — now the concrete bufio.Flush removal implementation.
- [ ] **#493** chore: regenerate benchmark baseline, fix interleaved output, wire CI regression gate.
- [ ] **#494** perf: eliminate per-event allocations in Loki batch stream grouping.
- [ ] **#495** perf: add WriteJSONBytes and eliminate bytesToString copy in Loki push.
- [ ] **#496** perf: eliminate per-field allocations in CEF formatter.
- [ ] **#497** refactor: zero-alloc fast path for generated builders via Fields-ownership contract.
- [ ] **#498** docs: document NewEvent heap cost and promote EventHandle for hot paths.
- [ ] **#499** perf: bump formatCache to 8 entries to avoid map allocation for multi-formatter deployments.
- [ ] **#500** perf: pool buildNDJSON body buffer in webhook output.
- [ ] **#501** perf: pool middleware hints and responseWriter structs.
- [ ] **#502** test: add missing hot-path benchmarks for validateFields, copyFieldsWithDefaults, processEntry, HMAC.
- [ ] **#503** test: add parallelism-scaling benchmark for Audit hot path.
- [ ] **#504** test: add output-specific benchmarks for Loki high-cardinality, file rotation, outputconfig load.
- [ ] **#505** perf: pre-compute JSON key fragments at taxonomy registration.
- [ ] **#506** perf: pool HMAC workspace (hexBuf, sumBuf) via sync.Pool.
- [ ] **#507** perf: eliminate LimitedReader and PID strconv allocations per event.
- [ ] **#508** perf: consolidate two AppendPostField calls into AppendPostFields batch.
- [ ] **#509** docs: document accepted performance trade-offs as code comments.
- [ ] **#510** spike: decide io_uring dependency approach for file output fast path.
- [ ] **#511** perf: implement Linux file-output fast path (io_uring or writev) per ADR.
- [ ] **#512** test: add side-by-side benchmark vs log/slog + JSON handler and publish in BENCHMARKS.md.

**Sequencing:** #493 (baseline infra) precedes every other Track C issue. #461 precedes #510/#511 (fast path spike/implementation). #510 blocks #511. #506 coordinates with #473 and #483 (all touch `hmac.go`). #508 depends on #473 landing first.

---

## Track B — API Shape (27 issues)

- [ ] **#575** feat: code generator — typed custom fields, auditIntPtr prefix, explicit setter flag, Fields() contract doc.
- [x] **#576** refactor: rename OutputRoute/OutputFormatter/OutputExcludeLabels/OutputHMAC to WithX convention.
- [x] **#577** refactor: collapse outputconfig.LoadResult, fix outputconfig.New variadic, fix outputconfig/doc.go stale example.
- [x] **#578** refactor: rename Stdout to Writer-based output with Stdout/Stderr/Writer constructors, drop core init() registration.
- [ ] **#579** refactor: pick one config pattern (Config struct vs functional options); export Version; bound fieldsPool.
- [x] **#580** refactor: align file/syslog/webhook/loki New() constructors on pointer Config receiver.
- [ ] **#581** refactor: unified OutputMetricsFactory pattern across file/syslog/webhook/loki.
- [ ] **#582** refactor: align HMAC Go and YAML field names; unify _hmac_v / _hmacVersion.
- [x] **#583** refactor: rename syslog.app_name YAML to procid or syslog_app_name; default APP-NAME from top-level app_name.
- [x] **#584** refactor: align Loki gzip YAML key and Go Compress field.
- [ ] **#585** refactor: examples use outputs convenience package instead of individual blank imports.
- [ ] **#586** refactor: replace Metrics.RecordEvent stringly-typed status with EventStatus enum.
- [ ] **#587** perf: WrapOutput conditionally implements MetadataWriter based on inner capability.
- [ ] **#588** refactor: inline rgooding/go-syncmap; drop third-party dependency on filter hot path.
- [ ] **#589** docs: fix Formatter docstring concurrency-safety contradiction with CEFFormatter sync.Once.
- [x] **#590** refactor: error API polish — clone Unwrap slice, document ComputeHMAC contract, error returns from RegisterOutputFactory and NewEventKV.
- [ ] **#591** refactor: CEFFormatter ergonomics — FieldMapping opt-out path, avoid redundant severity clamp, cite maxCEFHeaderField.
- [ ] **#592** refactor: unify error wrapping conventions across modules; align self-reporting drop metrics; drop dead redactRef parameter.
- [ ] **#593** refactor: small API polish — TLSPolicy zero-value docs, MinSeverity/MaxSeverity constants, Handle on disabled auditor, openbao Close idempotency, audittest rename, require AppName/Host, uniform nil-option handling.
- [ ] **#594** refactor: simplify 9-method Metrics interface into MetricEvent or split into lifecycle/delivery/validation interfaces.
- [ ] **#595** refactor: Fields rejects unsupported value types; WithStandardFieldDefaults accepts any.
- [ ] **#596** refactor: consolidate 6 optional Output interfaces into OutputCapabilities struct.
- [ ] **#597** refactor: enrich Event interface with Description/Categories/FieldInfo; document emission paths.
- [ ] **#598** feat: unified Sanitizer interface — scrubs audit event fields AND re-raised middleware panic values.
- [ ] **#599** feat: batched syslog writes — batch_size, flush_interval matching Loki/webhook conventions.
- [ ] **#600** feat: add AuditEventContext(ctx, evt) API alongside AuditEvent.
- [ ] **#601** feat: add Auditor.SetLogger for runtime diagnostic-logger swap (depends on atomic.Pointer migration #474).

**Sequencing:** #601 BLOCKED BY Track A #474. #582 coordinates with #473 (both touch HMAC append path — #473 first). #596 may absorb #587. #581 + #586 + #594 all touch metrics contract — consider unified API review.

---

## Track D — CI/CD and Release Pipeline (13 issues + 1 existing)

- [ ] **#437** (existing) fix: dependency-update workflow missing outputs module and example go.mod files — covers master D-02.
- [ ] **#513** chore: release process refactor — unified submodule tagging, CI-only, retire three-tier dance.
- [ ] **#514** fix: GoReleaser SBOMs generated per-binary, not per-source.
- [ ] **#515** chore: add CODEOWNERS and document branch + tag protection for v1.0.
- [ ] **#516** security: sign release artifacts with Cosign keyless OIDC (pairs with Track A #482).
- [ ] **#517** chore: add OSSF Scorecard scheduled workflow.
- [ ] **#518** chore: add timeout-minutes to ci-pass aggregate job.
- [ ] **#519** ci: add darwin and windows runners to core + file test matrix.
- [ ] **#520** refactor: extract setup-go + workspace + install-tools to reusable workflow.
- [ ] **#521** fix: dependency-update workflow preserves review comments across iterations.
- [ ] **#522** perf: parallelise govulncheck across modules via matrix.
- [ ] **#523** security: CI check rejects tls.Config{InsecureSkipVerify:true} anywhere outside tests.
- [ ] **#524** ci: add standalone mutation-testing workflow (ad-hoc + release-gate).
- [ ] **#622** bug: CI BDD step masks test failures via `| tee` pipeline + fix 8 pre-existing undefined BDD steps — combined scope: CI pipefail fix AND BDD "logger creation" → "auditor creation" rename across 6 feature files. Absorbs the "logger creation" item from Track F #557 (see #622 scope expansion comment 2026-04-17). NEXT UP after #473 merge.

**Sequencing:** #515 precedes #513 (branch protection required for PR-based release). #520 simplifies #524. #513 coordinates with #437 (Dependabot) and #493 (benchmark baseline). #516 and Track A #482 are duplicate angles — land one and close the other.

---

## Track E — Documentation (24 issues)

- [ ] **#525** docs: clean up CHANGELOG post-rename drift and duplicate section headings.
- [ ] **#526** docs: remove pre-release stability disclaimers and use present-tense for shipped implementations.
- [ ] **#527** docs: fix WithTimezone godoc inversion, syslog orphan fragment, Loki DynamicLabels, CONTRIBUTING stutter example.
- [ ] **#528** docs: expand SECURITY.md with threat model, secrets retention, production checklist.
- [ ] **#529** docs: replace stale Logger references with Auditor in user-facing docs.
- [ ] **#530** docs: fix stale any-typed setter references in code-gen docs and regenerate stale example.
- [ ] **#531** docs: repair broken example README cross-references after renumbering.
- [ ] **#532** docs: correct example 02 expected output, YAML form consistency, example 01 output, example 13 package comment.
- [ ] **#533** docs: add docs/quickstart-http-service.md — end-to-end integration guide.
- [ ] **#534** docs: README as storefront — inline Quick Start, audittest above fold, trim above-fold content.
- [ ] **#535** docs: expand migration guide with before/after tables for logrus, zap, zerolog.
- [ ] **#536** docs: add docs/reserved-standard-fields.md with complete table.
- [ ] **#537** docs: CONTRIBUTING.md Go version lifecycle + outputs.yaml filesystem + std_fields cross-link.
- [ ] **#538** docs: verify capstone bare-metal run works or gate/remove the section.
- [ ] **#539** chore: add Apache 2.0 license header to tests/bdd/docker/webhook-receiver/main.go.
- [ ] **#540** refactor: split audit.go, format_cef.go, taxonomy.go, options.go, syslog.go, audit_test.go into smaller files.
- [ ] **#541** docs: systematic YAML error-message audit against outputconfig gold standard.
- [ ] **#542** refactor: document intentional duplication of backoff, droplimit, intPtrOrDefault across modules.
- [ ] **#543** docs: add docs/playground.md noting Go Playground incompatibility.
- [ ] **#544** docs: document schema versioning model and migration contract (version: 1 locked, no migrations yet).
- [ ] **#545** docs: explain blank-import vs WithFactory guidance for output factories.
- [ ] **#546** docs: add docs/event-emission-paths.md — generated builders vs EventHandle vs NewEvent.
- [ ] **#547** docs: small polish bundle — code-generation setter types, npm-style notes, option godoc grammar.
- [ ] **#548** feat: generate and publish language-neutral schema files (JSON Schema + CEF template).

**Sequencing:** #526 precedes anything that claims v1.0 in godoc. #531 precedes #533 and #534 (same navigation surface). #544 depends on #526 cleanup. #540 (file splits) lands AFTER Track A + Track C changes stabilise.

---

## Track F — Tests and BDD (26 issues + 1 existing)

- [ ] **#465** (existing) bug: investigate flaky syslog reconnection test — will close on merge of #560.
- [ ] **#549** test: add BDD scenarios for WithSynchronousDelivery — currently zero coverage.
- [ ] **#550** test: rewrite typed_builders.feature — currently mislabeled, exercises dynamic API not generated builders.
- [ ] **#551** test: fix tautological BDD scenarios — assert complete payloads, exact values.
- [ ] **#552** test: add TLS expired and invalid-cert scenarios for syslog, webhook, loki outputs.
- [ ] **#553** test: add syslog crash-replay and rapid-restart BDD scenarios.
- [ ] **#554** test: convert webhook BDD "at least N" to "exactly N" for non-retry happy paths.
- [ ] **#555** refactor: convert white-box test packages to black-box with export_test.go where needed.
- [ ] **#556** test: migrate 334 assert.Contains error assertions to assert.ErrorIs with sentinel.
- [ ] **#557** test: BDD hygiene pass — stale field names, CEF mapping, HMAC absence, middleware panic. (The "logger creation" post-rename language item was moved to Track D #622.)
- [ ] **#558** test: add property-based tests (rapid) for webhook, loki, formatters, filter.
- [ ] **#559** test: replace httptest.Server with real containers in BDD steps per "BDD uses real containers" rule.
- [ ] **#560** test: remove time.Sleep synchronisation from 19 test files — closes #465.
- [ ] **#561** test: add missing BDD scenarios for EventHandle, audittest options, buffer_size, drain_timeout, ValidationMode warn, CEF OmitEmpty, DestinationKey, empty Name.
- [ ] **#562** test: per-output failure-mode BDD scenarios (disk-full, EPIPE, DNS, reset, timeout, 4xx/5xx).
- [ ] **#563** test: add BDD scenarios for secrets providers — TLS, partition, malformed JSON, injection safety.
- [ ] **#564** test: BDD coverage for async delivery edge cases (panic, slow output, buffer:0, invariant).
- [ ] **#565** test: add concrete unit tests per test-writer recommendations (Auditor, formatters, outputs, HMAC, secrets, outputconfig, audit-gen, routing, async).
- [x] **#566** test: expand audittest with WaitForN, PermissiveTaxonomy, WithExcludedLabels helper.
- [ ] **#567** fix: MockOutput.WriteCh uses appropriate channel capacity to avoid signal drops.
- [ ] **#568** test: expose GenerateTestCA and consolidate cert-generation helpers.
- [ ] **#569** test: Docker Compose healthchecks use wait.ForLog / wait.ForFile instead of TCP port only.
- [ ] **#570** test: add t.Parallel to audit_test.go, t.Helper to internal tests, enrich BDD step errors.
- [ ] **#571** test: add make mutation-test target + gremlins baseline for validate_fields, validate_taxonomy, hmac, filter, format_cef, sensitivity.
- [ ] **#572** test: parse received syslog messages as RFC 5424 and assert each structural field.
- [ ] **#573** test: add 12-hour soak benchmark for pre-release verification.
- [ ] **#574** test: triple-integration e2e test (secrets + outputconfig + real webhook container).

**Sequencing:** #568 precedes #552 (shared cert helpers). #571 blocks Track D #524 (make target precedes CI workflow). #550 coordinates with Track C #497 (same BDD file).

---

## Track G — Consumer Deployment (11 issues)

- [ ] **#602** docs: create docs/deployment.md — systemd, Kubernetes, Docker, parent-directory behaviour, capacity planning.
- [ ] **#603** docs: create docs/v1-changes.md summarising behavioural and API changes up to v1.0.
- [ ] **#604** feat: add file:// and env:// secret providers for K8s mounted-secret and plain-env use cases.
- [ ] **#605** docs: add docs/writing-custom-secret-providers.md with complete SecretProvider example.
- [ ] **#606** docs: add documented /healthz handler example using QueueLen/OutputNames introspection.
- [ ] **#607** docs: complete Prometheus reference implementation in capstone and docs (tested, drop-in).
- [ ] **#608** docs: add failure-mode matrix per output (destination down/slow, auth fail, disk full, TLS expired).
- [ ] **#609** docs: document file output logrotate coexistence behaviour and recommendation.
- [ ] **#610** ci: publish ghcr.io/axonops/audit-gen OCI image via GoReleaser.
- [ ] **#611** feat: standalone outputs.yaml validator for pre-deploy CI gate.
- [ ] **#612** feat: publish Grafana dashboard JSON as release artefacts.

**Sequencing:** #602 is the foundational doc — cross-linked from many others; start early. #607 and #612 coordinate with existing #435 (capstone Prometheus + Grafana). #610 depends on #482/#516 (Cosign signing) and #513 (release refactor).

---

## Pre-existing v1.0.0 issues incorporated

These were already labelled `v1.0.0` before the readiness review. Walkthrough decisions integrated them into the broader plan.

- [ ] **#193** feat: per-category severity thresholds in event routes — maintainer feature, not in agent findings.
- [ ] **#286** feat: consistent startup connectivity check across all network outputs — maintainer feature.
- [ ] **#435** feat: add Prometheus scraping and metrics dashboard to capstone — verify status before starting Track G #607/#612.
- [ ] **#436** security: file output allows arbitrary permissions — restrict to 0600/0640 only — covers master A-08 / Track A scope.
- [ ] **#437** fix: dependency-update workflow missing outputs module and example go.mod files — see Track D.
- [ ] **#441** docs: document multi-module development workflow and go.work usage — coordinates with Track E #537.
- [ ] **#460** create built-in startup shutdown audit event — maintainer feature, not in agent findings.
- [ ] **#461** perf: benchmark file output batch writes vs per-event flush — converted to concrete Track C work.
- [ ] **#465** bug: investigate flaky syslog reconnection test — will close on merge of Track F #560.
- [ ] **#467** chore: Make audit library AI coding assistant friendly for consumers — coordinates with Track E #534.

## Pre-existing issues referenced but NOT v1.0 scope

- **#174** (config file watcher) — post-v1.0. Updated with devops findings during walkthrough.

## Walkthrough decisions summary

Full decision log in the walkthrough comment on master tracker #472. Summary:

### IN v1.0.0 (incorporated into tracks above, 29 items)

Unified Sanitizer interface (#598); batched syslog (#599); AuditEventContext API (#600); Auditor.SetLogger (#601); Grafana dashboard publish (#612); Playground doc note (#543); Schema files (#548); slog comparison bench (#512); audittest sensitivity helper (#566); mutation testing Makefile (#571) + CI workflow (#524); Schema v2 doc (#544); property-based CEF (#558); RFC 5424 parsing (#572); CEF pipe-escape BDD (#557); InsecureSkipVerify CI (#523); middleware panic sanitiser (combined into #598); release process refactor (#513); Request-ID SIEM doc (#547); Linux io_uring fast path (#510/#511); OutputCapabilities (#596); Event interface enrichment (#597); blank-import vs WithFactory docs (#545); NewEventKV returns error (#590); DevTaxonomy warning (#547); CEFFormatter noCopy (#547); YAML error audit (#541); emission paths doc (#546).

### POST-v1.0 feature placeholders (#613–#620, NOT v1.0-labelled)

- [ ] **#613** Ed25519/ECDSA asymmetric signing alongside HMAC.
- [ ] **#614** WithSSRFAllowedHosts strict egress allow-list.
- [ ] **#615** Write-ahead log (absorbs structured event IDs).
- [ ] **#616** Hot-reload of TLS certificates.
- [ ] **#617** OpenTelemetry metrics bridge sub-module.
- [ ] **#618** Prometheus metrics bridge sub-module.
- [ ] **#619** Standalone cmd/audit-verify CLI.
- [ ] **#620** Capstone walkthrough screencast / video.

### OUT of scope (no issue created)

- Merkle / chained HMAC — not within library scope (per-message, not ordering-aware).
- Multi-category delivery dedup option — would interfere with performance; current behaviour intentional.
- First-class Helm chart — not what the library is.
- Secret-provider independent-Resolve regression-guard test — rare scenario, low value.

---

## Release gate

Before tagging v1.0.0, every one of the following must be green:

- [ ] Every v1.0.0 child issue on this tracker closed via issue-closer agent.
- [ ] `make check` clean.
- [ ] `make test -race -count=1` clean.
- [ ] `make test-bdd` clean with all scenarios passing.
- [ ] `make bench-compare` returns two-column benchstat output with no regressions above threshold.
- [ ] `make security` clean.
- [ ] Cross-platform build green (linux/darwin/windows).
- [ ] All ten review agents re-run against final state with no remaining blockers.
- [ ] Codex independent review completed with maintainer approval.
- [ ] Branch protection on main confirmed in GitHub UI.
- [ ] Tag protection for `v*` tags confirmed.
- [ ] Release dry-run executes end-to-end including Cosign signing.
- [ ] SBOMs verified per-binary.
- [ ] All 11+ modules covered by Dependabot.
- [ ] `gorelease` baseline established.

Only after ALL of the above: tag `v1.0.0` via the CI-based release workflow (Track D #513).

---

## Progress tracking

GitHub is authoritative. As issues close, tick their boxes above in this file. Commit updates to this file alongside track-completion PRs so progress is visible in `git log`.

Last updated: 2026-04-18. Progress: #473 #622 #490 #474 merged. Next: #475 (strip credentials from webhook/loki Config.String).
