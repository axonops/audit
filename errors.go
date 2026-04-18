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
	"errors"
	"fmt"
)

// Sentinel errors returned by the audit package.
// Use [errors.Is] to test for these in consumer code.
var (
	// ErrClosed is returned by [Auditor.AuditEvent] when the auditor has
	// been shut down via [Auditor.Close]. Once returned, all subsequent
	// [Auditor.AuditEvent] calls return ErrClosed immediately.
	ErrClosed = errors.New("audit: auditor is closed")

	// ErrQueueFull is returned by [Auditor.AuditEvent] when the async
	// intake queue is at capacity and the event is dropped. Consumers
	// SHOULD treat this as a drop notification rather than a fatal error.
	// Increasing [Config.QueueSize] or reducing event emission rate
	// reduces the frequency of this error.
	ErrQueueFull = errors.New("audit: queue full")

	// ErrDuplicateDestination is returned by [WithOutputs] and
	// [WithNamedOutput] when two outputs implement [DestinationKeyer]
	// and return the same key. This prevents accidental double-delivery
	// to the same file, syslog address, or webhook URL.
	ErrDuplicateDestination = errors.New("audit: duplicate destination")

	// ErrConfigInvalid is the sentinel error wrapped by all configuration
	// validation failures. Use [errors.Is] to test for it:
	//
	//	if errors.Is(err, audit.ErrConfigInvalid) { ... }
	ErrConfigInvalid = errors.New("audit: config validation failed")

	// ErrHandleNotFound is returned by [Auditor.Handle], and wrapped in
	// the panic value of [Auditor.MustHandle], when the requested event
	// type is not registered in the taxonomy.
	ErrHandleNotFound = errors.New("audit: event type not found")

	// ErrOutputClosed is returned by [Output.Write] when the output has
	// already been closed.
	ErrOutputClosed = errors.New("audit: output is closed")

	// ErrDisabled is returned by methods that require a taxonomy
	// ([Auditor.EnableCategory], [Auditor.DisableCategory],
	// [Auditor.EnableEvent], [Auditor.DisableEvent],
	// [Auditor.SetOutputRoute]) when called on a disabled auditor.
	// [Auditor.Handle] returns a valid no-op handle instead.
	ErrDisabled = errors.New("audit: auditor is disabled")

	// ErrTaxonomyInvalid is the sentinel error wrapped by taxonomy
	// validation failures. Use [errors.Is] to test for it:
	//
	//	if errors.Is(err, audit.ErrTaxonomyInvalid) { ... }
	ErrTaxonomyInvalid = errors.New("audit: taxonomy validation failed")

	// ErrInvalidTaxonomyName is returned by [ValidateTaxonomy] when a
	// category name, sensitivity label name, event type key, or field
	// name fails the character-set or length rule. Names must match
	// `^[a-z][a-z0-9_]*$` and be no longer than 128 bytes — enforced
	// at load to keep bidi overrides, Unicode confusables, CEF/JSON
	// metacharacters, and all C0/C1 control bytes out of downstream
	// log consumers and SIEM dashboards (issue #477).
	//
	// Always wrapped alongside [ErrTaxonomyInvalid] via [errors.Join],
	// so either sentinel satisfies [errors.Is]:
	//
	//	if errors.Is(err, audit.ErrInvalidTaxonomyName) { ... }
	//	if errors.Is(err, audit.ErrTaxonomyInvalid)     { ... }
	ErrInvalidTaxonomyName = errors.New("audit: invalid taxonomy name")

	// ErrInvalidInput is returned by [ParseTaxonomyYAML] when the input
	// is structurally unsuitable — empty, larger than [MaxTaxonomyInputSize],
	// a multi-document YAML stream, or syntactically invalid. Taxonomy
	// content validation errors wrap [ErrTaxonomyInvalid] instead.
	ErrInvalidInput = errors.New("audit: invalid input")

	// ErrValidation is the parent sentinel for all [Auditor.AuditEvent]
	// validation failures (unknown event type, missing required fields,
	// unknown fields in strict mode). Use [errors.Is] to catch any
	// validation failure:
	//
	//	if errors.Is(err, audit.ErrValidation) { ... }
	//
	// [ErrQueueFull] and [ErrClosed] are NOT validation errors.
	ErrValidation = errors.New("audit: validation error")

	// ErrUnknownEventType is returned by [Auditor.AuditEvent] when the
	// event type is not registered in the taxonomy. Always wrapped
	// alongside [ErrValidation] via [ValidationError].
	ErrUnknownEventType = errors.New("audit: unknown event type")

	// ErrMissingRequiredField is returned by [Auditor.AuditEvent] when
	// one or more required fields are absent. Always wrapped alongside
	// [ErrValidation] via [ValidationError].
	ErrMissingRequiredField = errors.New("audit: missing required field")

	// ErrUnknownField is returned by [Auditor.AuditEvent] in strict
	// validation mode when one or more fields are not declared in the
	// taxonomy. Always wrapped alongside [ErrValidation] via
	// [ValidationError].
	ErrUnknownField = errors.New("audit: unknown field")

	// ErrReservedFieldName is returned by [Auditor.AuditEvent] when
	// the event's Fields map uses a name reserved for library-emitted
	// fields (for example `_hmac`, `_hmac_v`). These names would
	// collide with library output and could enable canonicalisation-
	// ambiguity attacks on HMAC verifiers (issue #473). This check runs
	// regardless of [ValidationMode]; permissive mode cannot opt out.
	// Always wrapped alongside [ErrValidation] via [ValidationError].
	ErrReservedFieldName = errors.New("audit: reserved field name")
)

// ValidationError is returned by [Auditor.AuditEvent] for event
// validation failures. It wraps both [ErrValidation] and a specific
// sentinel ([ErrUnknownEventType], [ErrMissingRequiredField],
// [ErrUnknownField], or [ErrReservedFieldName]). Use [errors.Is] to
// match broadly or narrowly, and [errors.As] to access the structured
// error:
//
//	var ve *audit.ValidationError
//	if errors.As(err, &ve) { log.Println(ve.Error()) }
type ValidationError struct {
	wrapped [2]error // pre-allocated to avoid per-Unwrap heap allocation
	msg     string
}

// Error returns the human-readable error message. The text is
// identical to the pre-sentinel format for backwards compatibility.
func (e *ValidationError) Error() string { return e.msg }

// Unwrap returns the sentinel errors that this validation error wraps.
// Always includes [ErrValidation]; also includes the specific sentinel
// when set.
func (e *ValidationError) Unwrap() []error {
	return e.wrapped[:]
}

// newValidationError creates a [ValidationError] with the given
// specific sentinel and formatted message.
func newValidationError(sentinel error, format string, args ...any) *ValidationError {
	ve := &ValidationError{
		msg: fmt.Sprintf(format, args...),
	}
	ve.wrapped[0] = ErrValidation
	ve.wrapped[1] = sentinel
	return ve
}
