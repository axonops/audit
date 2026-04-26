// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
)

// Sanitizer scrubs sensitive content from audit events and from
// re-raised middleware panic values. Register one with
// [WithSanitizer]; the same instance is consulted on every
// [Auditor.Audit] / [Auditor.AuditEvent] call AND on the
// middleware panic-recovery path.
//
// # Concurrency contract
//
// Implementations MUST be safe for concurrent use by multiple
// goroutines. Both methods may be invoked concurrently from any
// number of caller goroutines and from the middleware-handler
// goroutine.
//
// # Ownership contract
//
// Implementations MUST NOT retain references to the value passed
// in after returning. The audit pipeline takes ownership of the
// returned values; passed-in values may be backed by pooled memory
// that is recycled after the call.
//
// # Return-type contract
//
// [Sanitizer.SanitizeField] SHOULD return a value of the supported
// [Fields] vocabulary (string, int, int32, int64, float64, bool,
// time.Time, time.Duration, []string, map[string]string, or nil).
// Returning an unsupported type causes the value to be coerced via
// fmt.Sprintf when emitted, matching the behaviour of warn / permissive
// [ValidationMode]. To avoid allocations on the common case where no
// scrub is needed, return the original `value` argument unchanged.
//
// Note: validation runs BEFORE the Sanitizer (so that strict mode
// rejects malformed events without paying scrub cost). A Sanitizer
// that returns an unsupported type AFTER strict validation has
// passed is NOT re-validated — the value flows to formatters and
// is coerced via fmt.Sprintf there. Consumers running in
// [ValidationStrict] mode who want absolute type-policy enforcement
// MUST ensure their Sanitizer preserves the supported vocabulary;
// the library deliberately does not pay for a second validation
// pass to catch sanitiser type drift.
//
// [Sanitizer.SanitizeField] cannot remove a field — it operates on
// values, not keys. To remove a field entirely, configure per-output
// [WithExcludeLabels] in your output options.
//
// # Failure modes
//
// If [Sanitizer.SanitizeField] panics, the offending field's value is
// replaced with the [SanitizerPanicSentinel] string and the field key
// is appended to the framework field "sanitizer_failed_fields"
// ([]string). Other fields in the same event continue to be sanitised
// and the event is emitted.
//
// If [Sanitizer.SanitizePanic] panics during middleware panic-recovery,
// the original (unsanitised) panic value is used in BOTH the audit
// event AND the re-raise (fail-open). The framework field
// "sanitizer_failed" (bool) is set to true so SIEM tooling can route
// on the failure signal.
//
// In both failure modes, a diagnostic-level message is logged via the
// auditor's [WithDiagnosticLogger]. The diagnostic log records ONLY
// the field key (for SanitizeField) or value type (for SanitizePanic);
// it never logs the raw value the Sanitizer was meant to scrub.
type Sanitizer interface {
	// SanitizeField returns a scrubbed version of the value for the
	// given field key. Return value unchanged when no scrub is needed.
	SanitizeField(key string, value any) any
	// SanitizePanic returns a scrubbed version of a recovered panic
	// value. Called once per middleware-recovered panic; the result
	// flows to BOTH the audit event AND the re-raise.
	SanitizePanic(val any) any
}

// SanitizerPanicSentinel is the placeholder value substituted into
// [Fields] when [Sanitizer.SanitizeField] panics on a particular
// key. Callers can search for this string in audit logs to identify
// fields that failed scrubbing without leaking the original value.
const SanitizerPanicSentinel = "[sanitizer_panic]"

// FieldSanitizerFailedFields names the framework field appended to
// the event when one or more [Sanitizer.SanitizeField] calls panicked.
// The value is a []string of the offending field keys, sorted for
// stability.
const FieldSanitizerFailedFields = "sanitizer_failed_fields"

// FieldSanitizerFailed names the framework field set to true on the
// middleware audit event when [Sanitizer.SanitizePanic] itself panicked
// during panic-recovery. The original panic value is used in both the
// audit event and the re-raise.
const FieldSanitizerFailed = "sanitizer_failed"

// NoopSanitizer is the zero-value [Sanitizer] that returns inputs
// unchanged. Embed it in custom Sanitizers to override only the method
// you care about — the [http.ResponseWriter] adapter pattern.
//
//	type RedactPasswords struct {
//	    audit.NoopSanitizer
//	}
//	func (RedactPasswords) SanitizeField(key string, value any) any {
//	    if key == "password" { return "[redacted]" }
//	    return value
//	}
type NoopSanitizer struct{}

// SanitizeField returns value unchanged.
func (NoopSanitizer) SanitizeField(_ string, value any) any { return value }

// SanitizePanic returns val unchanged.
func (NoopSanitizer) SanitizePanic(val any) any { return val }

// applyFieldSanitizer iterates fields, invoking SanitizeField for each
// key/value pair. Panics from individual SanitizeField calls are
// recovered: the value is replaced with [SanitizerPanicSentinel] and
// the key is added to the returned list. Returns nil when nothing
// panicked, otherwise an alphabetically-sorted []string of the
// offending keys; callers append it under [FieldSanitizerFailedFields].
//
// fields is mutated in place. The map MUST be detached from any caller
// reference (e.g. the post-validation copy returned by validateEvent)
// because we write back into it.
func applyFieldSanitizer(s Sanitizer, fields Fields, logger *slog.Logger) []string {
	if s == nil || len(fields) == 0 {
		return nil
	}
	var failed []string
	for k, v := range fields {
		newVal, panicked := safeSanitizeField(s, logger, k, v)
		if panicked {
			failed = append(failed, k)
			fields[k] = SanitizerPanicSentinel
			continue
		}
		// Avoid a writeback when the sanitiser returned the input
		// unchanged. This is the documented common case for keys the
		// sanitiser doesn't care about and saves an unnecessary map
		// store on every field.
		if newVal != v {
			fields[k] = newVal
		}
	}
	if len(failed) > 1 {
		sort.Strings(failed)
	}
	return failed
}

// safeSanitizeField wraps a single SanitizeField call with a recover()
// that logs only key + value-type, never the value itself.
func safeSanitizeField(s Sanitizer, logger *slog.Logger, key string, value any) (result any, panicked bool) {
	result = value
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			if logger != nil {
				logger.Error("audit: Sanitizer.SanitizeField panicked",
					"field_key", key,
					"value_type", fmt.Sprintf("%T", value),
					"panic_type", fmt.Sprintf("%T", v),
					"stack", truncateString(string(debug.Stack()), 2048),
				)
			}
		}
	}()
	return s.SanitizeField(key, value), false
}

// safeSanitizePanic wraps a single SanitizePanic call with a recover()
// that logs only original-value-type and panic-value-type, never the
// values themselves. Returns (sanitised value, false) on success or
// (original value, true) when the sanitiser panicked.
func safeSanitizePanic(s Sanitizer, logger *slog.Logger, original any) (result any, panicked bool) {
	result = original
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			if logger != nil {
				logger.Error("audit: Sanitizer.SanitizePanic panicked",
					"original_type", fmt.Sprintf("%T", original),
					"panic_type", fmt.Sprintf("%T", v),
					"stack", truncateString(string(debug.Stack()), 2048),
				)
			}
		}
	}()
	return s.SanitizePanic(original), false
}
