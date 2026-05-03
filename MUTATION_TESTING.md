# Mutation Testing Baseline

This file tracks the mutation testing baseline for the audit library
(issue #571). Mutation testing measures whether the test suite verifies
behaviour or merely traverses lines: `gremlins` mutates source code
(boundary inversions, conditional negations, arithmetic flips) and
re-runs the tests; a surviving mutant reveals a contract that's not
asserted by any test.

## How to Use

```bash
make install-gremlins              # install pinned gremlins (or via install-tools)
make mutation-test                 # all 6 files (~60 min total)
make mutation-test-<target>        # one file (~10 min); see below
```

Configuration lives in `.gremlins.yaml` (thresholds, operators); the
Makefile chooses the file scope via `--exclude-files`. The
`mutation-test-*` targets fail with exit code 10 when efficacy drops
below the per-file threshold (80%). See `CONTRIBUTING.md` ("Running
mutation tests") for guidance on how to respond to a surviving mutant.

## Scope

Six security-critical files in the root `audit` package:

| Target file              | Make target                     |
|--------------------------|---------------------------------|
| `validate_fields.go`     | `mutation-test-validate-fields` |
| `validate_taxonomy.go`   | `mutation-test-validate-taxonomy` |
| `hmac.go`                | `mutation-test-hmac`            |
| `filter.go`              | `mutation-test-filter`          |
| `format_cef.go`          | `mutation-test-format-cef`      |
| `sensitivity.go`         | `mutation-test-sensitivity`     |

The five gremlins-default operators are enabled
(`arithmetic-base`, `conditionals-boundary`, `conditionals-negation`,
`increment-decrement`, `invert-negatives`). The remaining six are
explicitly disabled in `.gremlins.yaml`:
`invert-assignments`, `invert-bitwise`, `invert-bwassign`,
`invert-logical`, `invert-loopctrl`, `remove-self-assignments`.
They produce a high rate of equivalent mutants on this codebase's
short-circuit boolean chains, bitwise idioms (out of scope for the
six target files), and self-assignment patterns.

For the canonical operator list see `.gremlins.yaml`.

## Current Baseline

**Date:** 2026-05-03
**Commit:** initial baseline ([#571](https://github.com/axonops/audit/issues/571));
record the SHA of any subsequent baseline refresh in the row that
replaces this one — `git log MUTATION_TESTING.md` resolves the
historical commit for the current row at any point in time.
**gremlins:** v0.6.0
**Go:** 1.26+
**Threshold:** efficacy ≥ 80% per file
**Hardware:** AMD Ryzen 9 7950X3D 16-Core (32 threads), Linux 6.14
**Configuration:** `--workers=2` (see Known Gremlins Quirks below)

| File                   | Killed | Lived | Timed Out | Efficacy | Status |
|------------------------|-------:|------:|----------:|---------:|--------|
| validate_fields.go     |     17 |     0 |         0 |  100.00% | PASS   |
| validate_taxonomy.go   |     30 |     1 |         0 |   96.77% | PASS   |
| hmac.go                |     27 |     0 |         0 |  100.00% | PASS   |
| filter.go              |     41 |     1 |         0 |   97.62% | PASS   |
| format_cef.go          |     71 |     6 |         0 |   92.21% | PASS   |
| sensitivity.go         |     25 |     0 |         0 |  100.00% | PASS   |
| **TOTAL**              | **211** | **8** |     **0** |  **96.35%** |        |

The 8 surviving lived mutants are documented as equivalent below. None
require additional tests — see the rationale column for why each
mutation produces functionally identical behaviour to the original.

**Efficacy = Killed / (Killed + Lived)** (gremlins' formula). Timed-out
mutants are excluded from the calculation. We minimise timeouts by
running gremlins with `--workers=2` (configured in the Makefile recipe);
higher parallelism causes resource contention that slows mutated tests
past gremlins' per-mutant timeout and falsely classifies them as TIMED
OUT, masking what would otherwise be either KILLED or LIVED.

## Equivalent-Mutant Exemptions

A mutant is **equivalent** if the mutation produces functionally
identical behaviour — e.g., a redundant defensive nil-check that the
caller already guarantees, or an allocation-only difference observable
only via `testing.AllocsPerRun`. Document each exemption with file:line,
mutant operator, and a one-or-two-sentence justification.

| File:line | Operator | Rationale |
|-----------|----------|-----------|
| `format_cef.go:46:9` | CONDITIONALS_NEGATION | `buf == nil` in `putCEFBuf`. Mutation flips to `buf != nil`; pool put then no-ops on real bufs and runs on nil — both produce no observable behaviour change since output is already complete and pool reuse is allocation-only. |
| `format_cef.go:46:29` | CONDITIONALS_BOUNDARY | `buf.Cap() > maxPooledBufCap` boundary. Pool capacity threshold; mutation changes which bufs return to pool. Allocation-only difference; no output-correctness consequence. |
| `format_cef.go:46:29` | CONDITIONALS_NEGATION | Same condition inverted; same allocation-only rationale as the boundary mutation above. |
| `format_cef.go:487:49` | ARITHMETIC_BASE | `len(defaults) + len(cf.FieldMapping)` is a `make()` capacity hint passed to the runtime allocator. Mutation flips `+` to `-`; the map still grows correctly because the hint is advisory. No correctness impact. |
| `format_cef.go:629:13` | CONDITIONALS_BOUNDARY | `b.Len() > extStart` in `writeExtField`. Boundary differs only when `b.Len() == extStart`; in the production call path this helper is invoked only AFTER the unconditional `rt=` extension has been written (line 334-335), so equality is unreachable. Any future refactor making `rt=` optional would need to revisit this exemption. |
| `format_cef.go:668:13` | CONDITIONALS_BOUNDARY | `b.Len() > extStart` in `writeExtFieldValue`. Identical reasoning to `629:13`: the unconditional `rt=` write makes `b.Len() > extStart` strictly true at every call site. |
| `validate_taxonomy.go:371:72` | CONDITIONALS_BOUNDARY | `len(annotations) > 0` in `isBareReservedStandardField`. The only path that populates `def.fieldAnnotations` (`taxonomy_yaml.go:461`) gates on `len(fieldDef.Labels) > 0`, so an entry with zero annotations cannot exist; the mutation `>= 0` differs only on the unreachable empty-slice state. |
| `filter.go:181:13` | CONDITIONALS_NEGATION | `len(ss) == 0` early-return in `toSet`. Mutation flips to `len(ss) != 0`, returning nil for non-empty input and an empty map for empty input. Masked by `inSet` (`filter.go:249-254`), which falls back to `slices.Contains` on the original slice when the pre-computed set is nil — both code paths produce identical match results. |

When adding an exemption, also add a comment in the source code at the
mutated line referencing this file. If you can't articulate why the
mutation is equivalent in plain English in 30 seconds, it's not
equivalent — you have a missing test, not an exemption.

## Refresh Procedure

Before each milestone release tag:

1. Run `make mutation-test` end-to-end on consistent hardware.
2. If any file's efficacy drops below 80%, follow the response order in
   `CONTRIBUTING.md` ("Running mutation tests"): kill the mutant, then
   document as equivalent, then (last resort) lower threshold with PR
   review.
3. Update the **Current Baseline** table above with the new numbers.
4. Append any new exemption rows.
5. Commit as `chore: refresh mutation-test baseline (#571)` with the
   release tag rationale in the body.

## Known Gremlins Quirks

- **`covdata` race on parallel cover builds.** Gremlins runs
  `go test -cover ./...`, which Go instruments per-package. With
  multi-module workspaces, parallel cover builds race on the lazily-
  built `covdata` tool ("go: no such tool covdata"). Mitigated by
  `--coverpkg=github.com/axonops/audit` in the Makefile recipe; this
  scopes coverage to the root package only.
- **Workers ≠ NumCPU.** Gremlins' default worker count (auto = NumCPU)
  causes parallel mutant test runs to compete for system resources,
  triggering spurious TIMED OUT classifications that mask real LIVED
  mutants. `.gremlins.yaml` keeps `workers: 0` (gremlins' default),
  but the Makefile recipe overrides it at invocation time with
  `--workers=$(GREMLINS_WORKERS)`, defaulting to 2. **Do not change
  `workers:` in `.gremlins.yaml`** — the CLI flag takes precedence and
  the default is the canonical setting for this repository's hardware.
  CI shards or beefier machines can override per-run:
  `make mutation-test-hmac GREMLINS_WORKERS=4`.
- **TIMED OUT excluded from efficacy.** Gremlins' efficacy metric is
  `Killed / (Killed + Lived)`. A high TIMED OUT count without LIVED
  mutants still scores 100%, but indicates flaky measurement. We aim
  for zero timeouts; the Makefile config achieves this on the project
  CI hardware.
- **Re-run flakes.** Two consecutive runs of the same target can
  occasionally produce different timeout counts (gremlins issue #272).
  Run `go clean -cache` between runs if results look anomalous.
