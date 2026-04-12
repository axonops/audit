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
	"slices"
	"strings"
)

func (l *Logger) validateFields(eventType string, def *EventDef, fields Fields) error {
	if err := checkRequiredFields(eventType, def, fields); err != nil {
		return err
	}
	return l.checkUnknownFields(eventType, def, fields)
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
func (l *Logger) checkUnknownFields(eventType string, def *EventDef, fields Fields) error {
	if l.cfg.ValidationMode == ValidationPermissive {
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

	switch l.cfg.ValidationMode {
	case ValidationStrict:
		return newValidationError(ErrUnknownField, "audit: event %q has unknown fields: [%s]",
			eventType, strings.Join(unknown, ", "))
	case ValidationWarn:
		l.logger.Warn("audit: event has unknown fields",
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
