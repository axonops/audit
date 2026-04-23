# ADR-0004: HMAC Wire-Field Naming Convention

## Status

Accepted — 2026-04-23

## Context

The audit library emits HMAC metadata on every HMAC-enabled event in two
wire formats: newline-delimited JSON and RFC-5424 CEF. Each record
carries a salt-version identifier alongside the HMAC digest itself, so
consumers can look up the correct salt during verification.

Before this decision the JSON and CEF output used inconsistent keys for
the salt-version identifier:

- JSON emitted `_hmac_v` (abbreviated).
- CEF emitted `_hmacVersion` (full word, camelCase).

The divergence produced three consumer problems. First, the
abbreviation `_v` was ambiguous: a reader of raw JSON could not
tell whether it meant *version*, *value*, or *verify* without cross-
referencing the library docs. Second, every other paired wire field
uses a consistent snake/camel symmetry (`event_category` /
`eventCategory`, `event_type` / `eventType`) — `_hmac_v` broke the
convention. Third, external verifier implementations had to carry a
named special case for the HMAC version key, where every other field
could be handled uniformly by lowercasing and removing underscores.

The `_hmac` key itself (the HMAC digest) already used the same literal
string in both formats, so only the version-identifier key was
inconsistent.

#473 (merged 2026-04-17) canonicalised `_hmac_v` inside the
authenticated region of each record to prevent salt-redirect attacks.
Any rename must preserve that invariant: the version-identifier key
must remain inside the HMAC-authenticated byte range, in the same
position relative to the digest.

## Decision

**Rename the JSON key from `_hmac_v` to `_hmac_version`.** The CEF key
remains `_hmacVersion`.

The pair `_hmac_version` (JSON snake_case) / `_hmacVersion` (CEF
camelCase) matches the convention already used for `event_category` /
`eventCategory` and `event_type` / `eventType`. External verifiers
that previously looked for `_hmac_v` in JSON must update to
`_hmac_version`. CEF consumers see no change.

The authenticated-region invariant from #473 is preserved: the
renamed key occupies the identical byte position — immediately
preceding the `_hmac` digest — and is part of the HMAC input byte
range.

## Consequences

### Positive

- Consumer code can handle the version key with the same uniform
  field-name normalisation used for every other wire field.
- Abbreviation ambiguity is eliminated. `_hmac_version` self-describes.
- The wire-format audit log is internally consistent: every JSON key
  is snake_case; every CEF key is camelCase; pairs are related by a
  mechanical transformation.
- The ecosystem precedent aligns: CloudTrail, GCP Audit Logs, and
  Kubernetes audit logs emit snake_case JSON for operational
  identifiers. No established audit-log format abbreviates to `_v`.

### Negative

- Seven additional bytes per event in JSON output. At 10,000
  events/second this adds approximately 70 KB/s to JSON output
  throughput. Measured against the 44+ base-64-encoded bytes of the
  HMAC digest already present on every record the overhead is
  negligible.
- External JSON verifiers written against the v0.x `_hmac_v` key must
  migrate. The library is pre-v1.0 (v0.x) so breaking changes are
  acceptable; migration is a single string replacement and the
  CHANGELOG entry for #582 carries the recipe.

## Alternatives considered

### Keep `_hmac_v` and document the abbreviation

Rejected. The ambiguity of `_v` is a durable documentation cost on
every consumer who reads raw JSON logs. The 7-byte saving is below
the noise floor relative to the HMAC digest. Pre-v1.0 is the correct
moment to fix the naming; post-v1.0 the migration cost compounds.

### Rename both keys to `_hmac_version` (JSON + CEF)

Rejected. CEF extension keys are camelCase per the ArcSight CEF
specification. The library already uses `eventCategory` / `eventType`
in CEF to match that convention; switching to snake_case for one
key would create a new inconsistency inside the CEF format.

### Rename CEF to `_hmac_v` instead of JSON to `_hmac_version`

Rejected. Short keys in CEF go against ArcSight convention and make
the CEF format harder to read for SIEM operators who already expect
`deviceEventCategory`-style keys.

## Coordination with #473

#473 established that `_hmac_v` lives inside the authenticated byte
range immediately before `_hmac`. This ADR preserves that order and
position; only the literal key name changes. A consumer that verified
against #473's authenticated-region contract must:

1. Update the string constant from `_hmac_v` to `_hmac_version` in
   the JSON verifier.
2. Continue to strip only `_hmac` (never `_hmac_version`) before
   recomputing the HMAC.
3. Make no changes to CEF verification — the CEF key is unchanged.

## References

- Issue #582 — refactor: align HMAC Go and YAML field names; unify
  `_hmac_v` / `_hmacVersion`.
- Issue #473 — security: include `_hmac_v` inside HMAC authenticated
  bytes (merged 2026-04-17).
- [ArcSight CEF Implementation Standard](https://community.microfocus.com/cfs-file/__key/communityserver-wikis-components-files/00-00-00-00-22/3731.CommonEventFormatv23.pdf)
  — CEF extension key conventions.
- ADR-0001 — fields ownership contract (preceding ADR for formatter
  wire-format invariants).
