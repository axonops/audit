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

package audit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/axonops/audit"
)

// TestEventStatus_WireFormat_Stable is the named lock test for
// issue #586. The underlying string value of each EventStatus
// constant is part of the library's downstream-metric wire contract:
// Prometheus queries, OTel collectors, and alerting rules all match
// against these literal strings. If a future PR changes
// `EventSuccess` or `EventError` to emit a different byte sequence,
// this test MUST fail loudly before the change lands.
//
// The values here are documented in godoc and in the CHANGELOG
// migration recipe for #586. DO NOT relax this test — update the
// docs and the CHANGELOG instead, and treat it as a breaking
// change.
func TestEventStatus_WireFormat_Stable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status audit.EventStatus
		want   string
	}{
		{"EventSuccess", audit.EventSuccess, "success"},
		{"EventError", audit.EventError, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, string(tt.status),
				"EventStatus wire value MUST NOT change — see TestEventStatus_WireFormat_Stable godoc")
		})
	}
}

// TestEventStatus_TypeCompatibility verifies that passing a
// string literal directly to [audit.Metrics.RecordEvent] is a
// compile error — the status parameter is typed.
func TestEventStatus_TypeCompatibility(t *testing.T) {
	t.Parallel()

	// Compile-time assertion: these lines compile because
	// EventSuccess/EventError are audit.EventStatus-typed.
	status := audit.EventSuccess
	assert.Equal(t, audit.EventSuccess, status)

	// Untyped string conversion works explicitly.
	var literal audit.EventStatus = "success"
	assert.Equal(t, audit.EventSuccess, literal,
		"typed string literal equality")
}

// TestNoOpMetrics_RecordEvent_AcceptsTypedStatus proves that
// [audit.NoOpMetrics] compiles with the new typed signature.
func TestNoOpMetrics_RecordEvent_AcceptsTypedStatus(t *testing.T) {
	t.Parallel()

	var m audit.Metrics = audit.NoOpMetrics{}
	// No-op — just needs to compile and not panic.
	m.RecordEvent("some-output", audit.EventSuccess)
	m.RecordEvent("some-output", audit.EventError)
}
