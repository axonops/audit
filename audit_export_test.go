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

// This file exports unexported functions for black-box testing.
package audit

// CopyFieldsForTest exposes copyFields for benchmarking.
var CopyFieldsForTest = copyFields

// IsEnabledForTest checks whether the given event type is enabled in
// the logger's current filter state. Lock-free, matching the
// production Audit() hot path.
func IsEnabledForTest(l *Logger, eventType string) bool {
	return l.filter.isEnabled(eventType, l.taxonomy)
}
