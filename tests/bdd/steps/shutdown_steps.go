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

package steps

import "github.com/cucumber/godog"

// registerShutdownSteps registers step definitions for shutdown scenarios.
// Most shutdown steps reuse file_steps and audit_steps; this file
// registers any shutdown-specific steps not covered elsewhere.
func registerShutdownSteps(_ *godog.ScenarioContext, _ *AuditTestContext) {
	// All shutdown scenarios use steps from audit_steps.go and file_steps.go:
	// - "I close the logger" (audit_steps)
	// - "I close the logger again" (file_steps)
	// - "the second close should return no error" (file_steps)
	// - "the file should contain exactly N events" (file_steps)
	// - "the audit call should return an error containing" (audit_steps)
}
