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

// Package audittest provides test helpers for consumers of the go-audit
// library. It provides an in-memory [Recorder] that captures audit
// events for assertion, a [MetricsRecorder] that captures all metrics
// calls, and convenience constructors that eliminate test boilerplate.
//
// The test logger is a fully functional [audit.Logger] — same
// validation, same taxonomy enforcement — but events land in memory
// instead of being written to a file, syslog, or webhook.
//
// Both [NewLogger] and [NewLoggerQuick] default to synchronous
// delivery: events are available in the [Recorder] immediately after
// [audit.Logger.AuditEvent] returns. No Close-before-assert ceremony
// is needed. Use [WithAsync] to opt into asynchronous delivery for
// tests that exercise drain timeout or buffer backpressure.
//
// # Quick Start
//
//	func TestMyHandler(t *testing.T) {
//	    logger, events, metrics := audittest.NewLogger(t, taxonomyYAML)
//	    myHandler(logger) // code under test
//
//	    // Assert immediately — synchronous delivery means events are already available.
//	    require.Equal(t, 1, events.Count())
//	    assert.Equal(t, "user_create", events.Events()[0].EventType)
//	    assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
//	}
//
// # Table-Driven Tests
//
// Use [Recorder.Reset] to clear captured events between sub-tests
// without creating a new logger:
//
//	for _, tc := range tests {
//	    t.Run(tc.name, func(t *testing.T) {
//	        events.Reset()
//	        svc.Do(tc.action)
//	        // assert on events for this sub-test only
//	    })
//	}
package audittest
