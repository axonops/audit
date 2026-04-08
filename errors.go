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

import "errors"

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
)
