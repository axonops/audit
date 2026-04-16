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

package syslog

// BackoffDuration is exported for testing only.
var BackoffDuration = backoffDuration

// MapSeverity is exported for testing only.
var MapSeverity = mapSeverity

// SimulateWriteFailure exercises the error path in writeEntry by
// temporarily setting the writer to nil. This causes
// errSyslogNotConnected to be returned, triggering handleWriteFailure
// which records RecordRetry/RecordError. Called synchronously from
// the test goroutine while writeLoop is blocked on an empty channel.
func (s *Output) SimulateWriteFailure() {
	saved := s.writer
	s.writer = nil
	s.writeEntry(syslogEntry{data: []byte("trigger-error"), priority: 0})
	s.writer = saved
}
