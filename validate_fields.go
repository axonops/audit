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
	"slices"
	"strings"
	"time"
)

func (a *Auditor) validateFields(eventType string, def *EventDef, fields Fields) error {
	if err := checkLibraryReservedFields(eventType, fields); err != nil {
		return err
	}
	if err := checkRequiredFields(eventType, def, fields); err != nil {
		return err
	}
	if err := a.checkFieldValueTypes(eventType, fields); err != nil {
		return err
	}
	return a.checkUnknownFields(eventType, def, fields)
}

// isSupportedFieldValue reports whether v is one of the value types
// the audit pipeline guarantees faithful rendering for. The set is
// the v1.0-locked vocabulary documented on [Fields]:
//
//   - string
//   - int / int32 / int64
//   - float64
//   - bool
//   - time.Time
//   - time.Duration
//   - []string
//   - map[string]string
//   - nil
//
// Other types render via fmt.Sprintf("%v", v) and may produce SIEM-
// hostile output (e.g. struct dumps, "{}" for empty maps). The
// validateFields path either rejects or coerces them depending on
// the auditor's ValidationMode (#595 B-43).
func isSupportedFieldValue(v any) bool {
	switch v.(type) {
	case nil,
		string,
		int, int32, int64,
		float64,
		bool,
		time.Time, time.Duration,
		[]string,
		map[string]string:
		return true
	}
	return false
}

// checkFieldValueTypes enforces the supported-type vocabulary for
// Fields values per #595 B-43. Behaviour is mode-driven:
//
//   - Strict: returns a [ValidationError] wrapping [ErrUnknownFieldType]
//     listing every unsupported field name.
//   - Warn: coerces in place via fmt.Sprintf("%v", v) and emits a
//     diagnostic-logger warning naming the affected fields.
//   - Permissive: coerces in place silently.
//
// Coercion mutates the caller's Fields map (warn / permissive paths).
// The audit pipeline already takes ownership of Fields by the time
// validation runs (defensive copy in the slow path; FieldsDonor
// transfer in the fast path), so no caller-visible mutation occurs.
func (a *Auditor) checkFieldValueTypes(eventType string, fields Fields) error {
	var unsupported []string
	for k, v := range fields {
		if !isSupportedFieldValue(v) {
			unsupported = append(unsupported, k)
		}
	}
	if len(unsupported) == 0 {
		return nil
	}
	slices.Sort(unsupported)

	switch a.cfg.ValidationMode {
	case ValidationStrict:
		return newValidationError(ErrUnknownFieldType,
			"audit: event %q has unsupported field value types: [%s] — see Fields godoc for the supported vocabulary",
			eventType, strings.Join(unsupported, ", "))
	case ValidationWarn:
		for _, k := range unsupported {
			fields[k] = fmt.Sprintf("%v", fields[k])
		}
		a.logger.Warn("audit: event has unsupported field value types — coerced via fmt.Sprintf",
			"event_type", eventType,
			"unsupported_fields", unsupported)
	case ValidationPermissive:
		for _, k := range unsupported {
			fields[k] = fmt.Sprintf("%v", fields[k])
		}
	}
	return nil
}

// libraryReservedFields are field names the library emits on every
// HMAC-enabled event. Consumer-supplied fields using these names would
// collide with library output and could enable canonicalisation-
// ambiguity attacks on HMAC verifiers (issue #473). Rejection runs
// regardless of ValidationMode — permissive mode cannot opt out of
// this check.
var libraryReservedFields = map[string]struct{}{
	"_hmac":         {},
	"_hmac_version": {},
}

// checkLibraryReservedFields rejects events whose Fields map contains
// library-internal reserved names. Runs in every validation mode
// including permissive.
func checkLibraryReservedFields(eventType string, fields Fields) error {
	var collisions []string
	for k := range fields {
		if _, ok := libraryReservedFields[k]; ok {
			collisions = append(collisions, k)
		}
	}
	if len(collisions) == 0 {
		return nil
	}
	slices.Sort(collisions)
	return newValidationError(ErrReservedFieldName,
		"audit: event %q uses library-reserved field names [%s] — these are emitted by the library and cannot be set by the consumer",
		eventType, strings.Join(collisions, ", "))
}

// checkRequiredFields returns an error listing any missing required fields.
func checkRequiredFields(eventType string, def *EventDef, fields Fields) error {
	var missing []string
	for _, f := range def.Required {
		if _, ok := fields[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return newValidationError(ErrMissingRequiredField, "audit: event %q missing required fields: [%s]",
		eventType, strings.Join(missing, ", "))
}

// checkUnknownFields validates unknown fields per the validation mode.
func (a *Auditor) checkUnknownFields(eventType string, def *EventDef, fields Fields) error {
	if a.cfg.ValidationMode == ValidationPermissive {
		return nil
	}

	known := effectiveKnownFields(def)
	var unknown []string
	for k := range fields {
		if _, ok := known[k]; !ok && !IsReservedStandardField(k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}

	slices.Sort(unknown)

	switch a.cfg.ValidationMode {
	case ValidationStrict:
		return newValidationError(ErrUnknownField, "audit: event %q has unknown fields: [%s]",
			eventType, strings.Join(unknown, ", "))
	case ValidationWarn:
		a.logger.Warn("audit: event has unknown fields",
			"event_type", eventType,
			"unknown_fields", unknown)
	case ValidationPermissive:
		// Unreachable: early return at function entry guards this case.
		// Kept to satisfy exhaustive switch linter.
	}
	return nil
}

// isZeroValue reports whether v is a zero value for its type. It uses
// a type switch for common types to avoid reflection overhead and
// panics. Unknown types fall back to a non-nil check only.
//
//nolint:cyclop,gocyclo // flat type switch over primitive types; linear structure, not true branch complexity
func isZeroValue(v any) bool {
	if v == nil {
		return true
	}
	switch val := v.(type) {
	case string:
		return val == ""
	case bool:
		return !val
	case int:
		return val == 0
	case int64:
		return val == 0
	case float64:
		return val == 0
	case int32:
		return val == 0
	case float32:
		return val == 0
	case uint:
		return val == 0
	case uint64:
		return val == 0
	default:
		// For slices, maps, funcs, and other complex types, we only
		// check nil. We do not use reflect to avoid panics on types
		// like func or chan.
		return false
	}
}
