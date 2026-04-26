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

// IsFrameworkField is exported for testing only.
var IsFrameworkField = isFrameworkField

// IsZeroValueForTest is exported for testing only. Direct coverage
// of the float32 / uint / uint64 branches in isZeroValue, which are
// no longer reachable through AuditEvent (#595 B-43 coerces those
// types to string upstream of OmitEmpty in non-strict modes).
var IsZeroValueForTest = isZeroValue
