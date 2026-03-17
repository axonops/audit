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

// EventType is a handle for a registered audit event type. It carries
// the event type name and a reference to the owning [Logger], enabling
// zero-allocation audit calls without repeated string lookup.
//
// Obtain a handle via [Logger.Handle] or [Logger.MustHandle].
type EventType struct {
	name   string
	logger *Logger
}

// Audit emits an audit event using this handle's event type. It
// returns [ErrBufferFull] if the buffer is full, [ErrClosed] if the
// logger is shut down, or a validation error if required fields are
// missing.
func (e *EventType) Audit(fields Fields) error {
	return e.logger.Audit(e.name, fields)
}

// Name returns the event type name this handle represents.
func (e *EventType) Name() string {
	return e.name
}

// auditEntry is the internal representation of an audit event as it
// travels through the async channel. It is not exported.
type auditEntry struct {
	eventType string
	fields    Fields
}

// ErrHandleNotFound is returned by [Logger.Handle], and wrapped in
// the panic value of [Logger.MustHandle], when the requested event
// type is not registered in the taxonomy.
var ErrHandleNotFound = errors.New("audit: event type not found")
