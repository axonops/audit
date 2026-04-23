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

import (
	"fmt"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// blockingMockOutput is a synchronous output whose Write blocks forever.
// Used to verify that the drain timeout mechanism works correctly when
// an output hangs. Close returns immediately so the auditor can shut down.
type blockingMockOutput struct {
	blockCh chan struct{} // closed on cleanup to unblock Write
}

func (b *blockingMockOutput) Name() string { return "blocking-output" }

func (b *blockingMockOutput) Write(_ []byte) error {
	<-b.blockCh // block until cleanup
	return nil
}

func (b *blockingMockOutput) Close() error { return nil }

// registerShutdownSteps registers step definitions for shutdown scenarios.
func registerShutdownSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Most shutdown scenarios use steps from audit_steps.go and file_steps.go:
	// - "I close the auditor" (audit_steps)
	// - "I close the auditor again" (file_steps)
	// - "the second close should return no error" (file_steps)
	// - "the file should contain exactly N events" (file_steps)
	// - "closing the auditor should complete within N seconds" (file_steps)

	ctx.Step(`^an auditor with a blocking output and drain timeout (\d+)s$`, func(timeoutSecs int) error {
		blocking := &blockingMockOutput{blockCh: make(chan struct{})}
		tc.AddCleanup(func() { close(blocking.blockCh) })

		auditor, err := audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(blocking),
			audit.WithShutdownTimeout(time.Duration(timeoutSecs)*time.Second),
		)
		if err != nil {
			return fmt.Errorf("create auditor with blocking output: %w", err)
		}
		tc.Auditor = auditor
		return nil
	})
}
