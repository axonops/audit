# Sanitizer — privacy and panic-value scrubbing

The `audit.Sanitizer` interface is the single integration point for
privacy-sensitive content scrubbing. It runs on TWO paths:

- **Every event field**: `SanitizeField(key, value)` is invoked once
  per field on every `Auditor.Audit` / `Auditor.AuditEvent` call —
  middleware emissions and direct emissions alike.
- **Middleware re-raised panic values**: `SanitizePanic(value)` is
  invoked once per panic recovered by `audit.Middleware`. The
  sanitised value flows to BOTH the audit event AND the re-raise to
  the outer panic handler (Sentry, parent recovery middleware,
  panic logger).

A consumer that registers a Sanitizer once via `audit.WithSanitizer`
gets uniform scrubbing across every audit-emit path.

## When to use a Sanitizer

Use a Sanitizer when ANY of the following apply:

- The application allows operators to populate audit fields with
  arbitrary data (free-text reasons, error messages, role claims,
  identifiers from external systems).
- Compliance regimes (GDPR, HIPAA, PCI-DSS) require redaction or
  pseudonymisation of specific values that may appear in audit
  events.
- Handler panics carry values that contain operational secrets
  (database connection strings in error wrapping, in-memory PII).
- A downstream panic handler (Sentry, parent recovery middleware,
  panic-logging interceptor) is NOT trusted to scrub values itself.

Do NOT use a Sanitizer for:

- Removing fields entirely from outputs based on labels — use the
  per-output `WithExcludeLabels` option instead. SanitizeField
  cannot remove a key, only transform its value.
- Adding fields. Sanitizer is read-modify-write per existing field.

## Interface contract

```go
type Sanitizer interface {
    SanitizeField(key string, value any) any
    SanitizePanic(val any) any
}
```

### Concurrency

Sanitizers MUST be safe for concurrent use by multiple goroutines.
Both methods may be invoked concurrently from the audit caller's
goroutine and from the middleware-handler goroutine. If your
Sanitizer holds state (e.g. a compiled regex), guard it with a
`sync.Mutex` or use immutable values.

### Ownership

Sanitizers MUST NOT retain references to the value passed in. The
audit pipeline takes ownership of the returned value; the passed-in
value may be backed by pooled memory that is recycled after the
call.

### Return type

`SanitizeField` SHOULD return a value of the supported `Fields`
vocabulary (`string`, `int`, `int32`, `int64`, `float64`, `bool`,
`time.Time`, `time.Duration`, `[]string`, `map[string]string`, or
`nil`). Returning an unsupported type causes the value to be coerced
via `fmt.Sprintf` when emitted. To avoid allocations on the common
case where no scrub is needed, RETURN THE ORIGINAL `value`
ARGUMENT UNCHANGED.

`SanitizeField` cannot remove a field — return any value and
configure per-output `WithExcludeLabels` to strip the key.

## Failure modes

The library cannot trust consumer code to be panic-free. Both
methods are invoked under a `recover()`; the failure semantics are
documented and predictable so security teams can build alerts
around them.

### SanitizeField panic

If `SanitizeField` panics for a particular key:

1. The offending field's value is replaced with the sentinel string
   `"[sanitizer_panic]"` (constant `audit.SanitizerPanicSentinel`).
2. The field key is appended to the framework field
   `sanitizer_failed_fields` (a `[]string`, alphabetically sorted).
3. Other fields in the same event continue to be sanitised; the
   event is emitted normally.
4. A diagnostic-level log message is written via the configured
   `WithDiagnosticLogger`. The log records ONLY the field key, the
   value's Go type, and the panic value's Go type. **The raw
   value the sanitiser was meant to scrub is NEVER logged.**

This is fail-open at the event level (the event still emits) and
fail-closed at the value level (the unsanitised value never appears
in the output).

### SanitizePanic panic (middleware)

If the Sanitizer's `SanitizePanic` itself panics during middleware
panic-recovery:

1. The ORIGINAL (unsanitised) panic value is used in BOTH the audit
   event AND the re-raise. This is fail-open in both directions:
   the audit log records that something happened, and the outer
   panic handler still receives a meaningful value.
2. The framework field `sanitizer_failed` is set to `true` on the
   audit event so SIEM tooling can route an alert.
3. A diagnostic-level log message is written. As with SanitizeField,
   only types are logged — never the original panic value.

The library considers a missing audit event WORSE than an event
containing the original (potentially sensitive) panic value: silent
gaps hide both the security event and the sanitiser failure.

## Common patterns

The library ships only the interface and a `NoopSanitizer`
embed-helper. Reference implementations are deliberately left to
the consumer for v1.0.

### Pattern 1 — drop-by-key

Replace specific known-sensitive fields with a fixed sentinel:

```go
type DropPasswords struct{ audit.NoopSanitizer }

func (DropPasswords) SanitizeField(key string, value any) any {
    switch key {
    case "password", "secret", "api_key":
        return "[redacted]"
    }
    return value
}
```

### Pattern 2 — regex masking

Compile patterns once at construction; safe for concurrent use:

```go
type CCNumberMasker struct {
    audit.NoopSanitizer
    re *regexp.Regexp
}

func NewCCNumberMasker() *CCNumberMasker {
    return &CCNumberMasker{
        re: regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
    }
}

func (c *CCNumberMasker) SanitizeField(_ string, value any) any {
    s, ok := value.(string)
    if !ok {
        return value // not a string → pass through
    }
    return c.re.ReplaceAllString(s, "[cc-redacted]")
}
```

### Pattern 3 — hash-and-replace (pseudonymisation)

```go
type HashUserIDs struct {
    audit.NoopSanitizer
    salt []byte
}

func (h HashUserIDs) SanitizeField(key string, value any) any {
    if key != "actor_id" && key != "target_id" {
        return value
    }
    s, ok := value.(string)
    if !ok {
        return value
    }
    sum := sha256.Sum256(append(h.salt, []byte(s)...))
    return hex.EncodeToString(sum[:8])
}
```

### Pattern 4 — error-wrapping-aware panic redactor

```go
type RedactErrorChains struct{ audit.NoopSanitizer }

func (RedactErrorChains) SanitizePanic(val any) any {
    if err, ok := val.(error); ok {
        return fmt.Errorf("redacted: %s", err.Error())
    }
    return "[panic redacted]"
}
```

## Performance

When no Sanitizer is registered (`WithSanitizer` unset), the
per-event overhead is a single nil-check on the auditor's
`sanitizer` field — zero allocations, zero interface dispatch, no
measurable impact on benchmark results.

When a Sanitizer is registered, every emitted event pays:

- One interface dispatch per field (`SanitizeField` call).
- Whatever work the Sanitizer itself does.
- One additional `if` branch on the value-changed check inside
  `applyFieldSanitizer` (avoids an unnecessary map write when the
  Sanitizer returned the input unchanged — recommended return
  pattern).

The middleware `SanitizePanic` path runs once per panic — out of
the hot path; performance is irrelevant.

## Threat model — timing side-channels

A Sanitizer that performs operations whose duration depends on
secret values (e.g. early-exit regex matching for credit-card
patterns) leaks timing information. The async drain pipeline
attenuates but does not eliminate caller-observable timing. If
your threat model includes an attacker who:

1. Controls the values that flow through `SanitizeField`, AND
2. Can measure end-to-end audit-emit latency from outside the
   process,

then either (a) implement Sanitizer operations in constant time,
or (b) use synchronous-delivery mode at your peril (it makes the
leak more direct).

For typical content-scrubbing use cases (PII redaction, free-text
masking) this threat is theoretical and not actionable; document
your decision and move on.

## Interaction with sensitivity labels

The Sanitizer runs in the caller's goroutine BEFORE the drain-side
per-output `WithExcludeLabels` strip. Order of operations:

1. Caller calls `Auditor.AuditEvent(evt)`.
2. Library validates the event (rejects unknown / required-missing).
3. Library invokes `SanitizeField` on every field (this is where
   your Sanitizer transforms values).
4. Library enqueues to drain.
5. Drain loop fans out to outputs; per-output the configured
   `WithExcludeLabels` strips fields matching label config.

Important: a Sanitizer cannot remove a field. If you need to drop a
labelled field on a specific output, configure
`WithExcludeLabels(outputName, "pii")` — that runs at step 5 and is
the correct primitive for label-based stripping. Use the Sanitizer
to TRANSFORM values; use `WithExcludeLabels` to REMOVE keys.

## Testing your Sanitizer

The `audittest` package's recorder runs full audit pipeline behind
the scenes, including your Sanitizer. Use it like any other
auditor:

```go
func TestRedactPasswords(t *testing.T) {
    rec := audittest.NewRecorder(t,
        audit.WithTaxonomy(taxonomy),
        audit.WithSanitizer(DropPasswords{}),
    )
    require.NoError(t, rec.AuditEvent(audit.NewEvent("login", audit.Fields{
        "outcome":  "success",
        "password": "supersecret",
    })))
    ev := rec.Events()[0]
    assert.Equal(t, "[redacted]", ev["password"])
}
```

## See also

- `WithExcludeLabels` (in `options.go`) — per-output label-based
  field stripping; the right primitive for "remove this field
  entirely from this output".
- `WithDiagnosticLogger` — wire your operational logger so
  Sanitizer panics are recorded for SOC tooling.
- Issue #598 — the v1.0 design discussion that locked the
  Sanitizer interface shape and failure modes.
