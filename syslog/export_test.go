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

// SimulatePanicOnNextWrite exercises the error path in writeEntry
// by temporarily setting the writer to nil. This causes
// errSyslogNotConnected to be returned, triggering handleWriteFailure
// which records RecordError when retries are exhausted. Called
// synchronously from the test goroutine, not from writeLoop.
func (s *Output) SimulatePanicOnNextWrite() {
	saved := s.writer
	s.writer = nil
	s.writeEntry(syslogEntry{data: []byte("trigger-error"), priority: 0})
	s.writer = saved
}
