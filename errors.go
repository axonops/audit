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
	// ErrClosed is returned by [Logger.AuditEvent] when the logger has
	// been shut down via [Logger.Close]. Once returned, all subsequent
	// [Logger.AuditEvent] calls return ErrClosed immediately.
	ErrClosed = errors.New("audit: logger is closed")

	// ErrBufferFull is returned by [Logger.AuditEvent] when the async
	// buffer is at capacity and the event is dropped. Consumers SHOULD
	// treat this as a drop notification rather than a fatal error.
	// Increasing [Config.BufferSize] or reducing event emission rate
	// reduces the frequency of this error.
	ErrBufferFull = errors.New("audit: buffer full")

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

	// ErrHandleNotFound is returned by [Logger.Handle], and wrapped in
	// the panic value of [Logger.MustHandle], when the requested event
	// type is not registered in the taxonomy.
	ErrHandleNotFound = errors.New("audit: event type not found")

	// ErrOutputClosed is returned by [Output.Write] when the output has
	// already been closed.
	ErrOutputClosed = errors.New("audit: output is closed")

	// ErrTaxonomyInvalid is the sentinel error wrapped by taxonomy
	// validation failures. Use [errors.Is] to test for it:
	//
	//	if errors.Is(err, audit.ErrTaxonomyInvalid) { ... }
	ErrTaxonomyInvalid = errors.New("audit: taxonomy validation failed")

	// ErrInvalidInput is returned by [ParseTaxonomyYAML] when the input
	// is structurally unsuitable — empty, larger than [MaxTaxonomyInputSize],
	// a multi-document YAML stream, or syntactically invalid. Taxonomy
	// content validation errors wrap [ErrTaxonomyInvalid] instead.
	ErrInvalidInput = errors.New("audit: invalid input")

	// ErrValidation is the parent sentinel for all [Logger.AuditEvent]
	// validation failures (unknown event type, missing required fields,
	// unknown fields in strict mode). Use [errors.Is] to catch any
	// validation failure:
	//
	//	if errors.Is(err, audit.ErrValidation) { ... }
	//
	// [ErrBufferFull] and [ErrClosed] are NOT validation errors.
	ErrValidation = errors.New("audit: validation error")

	// ErrUnknownEventType is returned by [Logger.AuditEvent] when the
	// event type is not registered in the taxonomy. Always wrapped
	// alongside [ErrValidation] via [ValidationError].
	ErrUnknownEventType = errors.New("audit: unknown event type")

	// ErrMissingRequiredField is returned by [Logger.AuditEvent] when
	// one or more required fields are absent. Always wrapped alongside
	// [ErrValidation] via [ValidationError].
	ErrMissingRequiredField = errors.New("audit: missing required field")

	// ErrUnknownField is returned by [Logger.AuditEvent] in strict
	// validation mode when one or more fields are not declared in the
	// taxonomy. Always wrapped alongside [ErrValidation] via
	// [ValidationError].
	ErrUnknownField = errors.New("audit: unknown field")
)

// ValidationError is returned by [Logger.AuditEvent] for event
// validation failures. It wraps both [ErrValidation] and a specific
// sentinel ([ErrUnknownEventType], [ErrMissingRequiredField], or
// [ErrUnknownField]). Use [errors.Is] to match broadly or narrowly,
// and [errors.As] to access the structured error:
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
