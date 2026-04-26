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

import "time"

// ReservedFieldType identifies the Go-level value type that a reserved
// standard field accepts. Consumers use it via
// [ReservedStandardFieldType] to validate per-field defaults and to
// drive type-aware tooling (linters, IDE plugins, code generators).
//
// The library guarantees a stable enum identity for v1.x: existing
// constants do not change value, but new types may be added. Callers
// SHOULD include a default branch when switching on a value.
type ReservedFieldType uint8

// Defined ReservedFieldType values. Values are stable within a major
// version. New values are added in minor releases.
const (
	// ReservedFieldString accepts Go string values.
	ReservedFieldString ReservedFieldType = iota

	// ReservedFieldInt accepts Go int values. Distinct from
	// ReservedFieldInt64 because some reserved fields (port numbers)
	// are bounded and idiomatically represented as int.
	ReservedFieldInt

	// ReservedFieldInt64 accepts Go int64 values.
	ReservedFieldInt64

	// ReservedFieldFloat64 accepts Go float64 values.
	ReservedFieldFloat64

	// ReservedFieldBool accepts Go bool values.
	ReservedFieldBool

	// ReservedFieldTime accepts Go [time.Time] values.
	ReservedFieldTime

	// ReservedFieldDuration accepts Go [time.Duration] values.
	ReservedFieldDuration
)

// String returns the canonical string label for a ReservedFieldType.
// The label matches the Go source-level name of the underlying type
// (`string`, `int`, `int64`, `float64`, `bool`, `time.Time`,
// `time.Duration`) so it is suitable for embedding in error messages
// and YAML schemas.
func (t ReservedFieldType) String() string {
	switch t {
	case ReservedFieldString:
		return "string"
	case ReservedFieldInt:
		return "int"
	case ReservedFieldInt64:
		return "int64"
	case ReservedFieldFloat64:
		return "float64"
	case ReservedFieldBool:
		return "bool"
	case ReservedFieldTime:
		return "time.Time"
	case ReservedFieldDuration:
		return "time.Duration"
	}
	return "unknown"
}

// reservedStandardFieldTypes is the canonical map of reserved standard
// field name → Go value type. The single source of truth for both
// [ReservedStandardFieldNames] and [ReservedStandardFieldType], and
// the basis for [WithStandardFieldDefaults] type validation.
//
// Adding a reserved field MUST update this map. Because
// [ReservedStandardFieldNames] is derived from this map directly,
// the two views are trivially consistent.
var reservedStandardFieldTypes = map[string]ReservedFieldType{
	"action":      ReservedFieldString,
	"actor_id":    ReservedFieldString,
	"actor_uid":   ReservedFieldString,
	"dest_host":   ReservedFieldString,
	"dest_ip":     ReservedFieldString,
	"dest_port":   ReservedFieldInt,
	"end_time":    ReservedFieldTime,
	"file_hash":   ReservedFieldString,
	"file_name":   ReservedFieldString,
	"file_path":   ReservedFieldString,
	"file_size":   ReservedFieldInt,
	"message":     ReservedFieldString,
	"method":      ReservedFieldString,
	"outcome":     ReservedFieldString,
	"path":        ReservedFieldString,
	"protocol":    ReservedFieldString,
	"reason":      ReservedFieldString,
	"referrer":    ReservedFieldString,
	"request_id":  ReservedFieldString,
	"role":        ReservedFieldString,
	"session_id":  ReservedFieldString,
	"source_host": ReservedFieldString,
	"source_ip":   ReservedFieldString,
	"source_port": ReservedFieldInt,
	"start_time":  ReservedFieldTime,
	"target_id":   ReservedFieldString,
	"target_role": ReservedFieldString,
	"target_type": ReservedFieldString,
	"target_uid":  ReservedFieldString,
	"transport":   ReservedFieldString,
	"user_agent":  ReservedFieldString,
}

// ReservedStandardFieldType reports the declared Go value type for a
// reserved standard field. The second return value is false if name
// is not a reserved standard field — see
// [ReservedStandardFieldNames] for the canonical list.
//
// Consumers use this for type-aware linting, IDE assistance, or to
// validate their own configuration before passing it to
// [WithStandardFieldDefaults].
func ReservedStandardFieldType(name string) (ReservedFieldType, bool) {
	t, ok := reservedStandardFieldTypes[name]
	return t, ok
}

// valueMatchesReservedType reports whether v's Go type matches the
// declared ReservedFieldType. Used by [WithStandardFieldDefaults] to
// reject deployment-time type mismatches before any event is
// processed.
func valueMatchesReservedType(v any, t ReservedFieldType) bool {
	switch t {
	case ReservedFieldString:
		_, ok := v.(string)
		return ok
	case ReservedFieldInt:
		_, ok := v.(int)
		return ok
	case ReservedFieldInt64:
		_, ok := v.(int64)
		return ok
	case ReservedFieldFloat64:
		_, ok := v.(float64)
		return ok
	case ReservedFieldBool:
		_, ok := v.(bool)
		return ok
	case ReservedFieldTime:
		_, ok := v.(time.Time)
		return ok
	case ReservedFieldDuration:
		_, ok := v.(time.Duration)
		return ok
	}
	return false
}
