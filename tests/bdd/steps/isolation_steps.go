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
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// recordingMockOutput collects events in memory. Thread-safe.
type recordingMockOutput struct {
	name   string
	events [][]byte
	mu     sync.Mutex
}

func (o *recordingMockOutput) Write(data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	o.mu.Lock()
	o.events = append(o.events, cp)
	o.mu.Unlock()
	return nil
}

func (o *recordingMockOutput) Close() error { return nil }
func (o *recordingMockOutput) Name() string { return o.name }

func (o *recordingMockOutput) eventCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.events)
}

// registerIsolationSteps registers BDD step definitions for output
// isolation scenarios.
func registerIsolationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,gocyclo,cyclop // BDD step registration
	var (
		stdoutBuf        *bytes.Buffer
		recOut1, recOut2 *recordingMockOutput
	)

	ctx.Step(`^an auditor with stdout and a recording mock output$`, func() error {
		stdoutBuf = &bytes.Buffer{}
		stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: stdoutBuf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}
		recOut1 = &recordingMockOutput{name: "recording-1"}
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(stdout, recOut1),
			audit.WithQueueSize(1000),
		)
		return err //nolint:wrapcheck // BDD step
	})

	ctx.Step(`^an auditor with synchronous delivery and a recording mock output$`, func() error {
		recOut1 = &recordingMockOutput{name: "recording-1"}
		var err error
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(recOut1),
			audit.WithSynchronousDelivery(),
		)
		return err //nolint:wrapcheck // BDD step
	})

	ctx.Step(`^an auditor with stdout output only$`, func() error {
		stdoutBuf = &bytes.Buffer{}
		stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: stdoutBuf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(stdout),
			audit.WithQueueSize(1000),
		)
		return err //nolint:wrapcheck // BDD step
	})

	ctx.Step(`^an auditor with two recording mock outputs$`, func() error {
		recOut1 = &recordingMockOutput{name: "recording-1"}
		recOut2 = &recordingMockOutput{name: "recording-2"}
		var err error
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(recOut1, recOut2),
			audit.WithQueueSize(1000),
		)
		return err //nolint:wrapcheck // BDD step
	})

	ctx.Step(`^an auditor with synchronous delivery and two recording mock outputs$`, func() error {
		recOut1 = &recordingMockOutput{name: "recording-1"}
		recOut2 = &recordingMockOutput{name: "recording-2"}
		var err error
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(recOut1, recOut2),
			audit.WithSynchronousDelivery(),
		)
		return err //nolint:wrapcheck // BDD step
	})

	ctx.Step(`^stdout should have received all (\d+) events$`, func(n int) error {
		if stdoutBuf == nil {
			return fmt.Errorf("no stdout buffer configured")
		}
		lines := countLines(stdoutBuf.String())
		if lines < n {
			return fmt.Errorf("stdout has %d events, expected %d", lines, n)
		}
		return nil
	})

	ctx.Step(`^the recording output should have received all (\d+) events$`, func(n int) error {
		if recOut1 == nil {
			return fmt.Errorf("no recording output configured")
		}
		if recOut1.eventCount() < n {
			return fmt.Errorf("recording output has %d events, expected %d", recOut1.eventCount(), n)
		}
		return nil
	})

	// "exactly" variant for scenarios where 0 events is the contract —
	// the lower-bound `received all` step above is vacuous at n=0
	// (count >= 0 is always true). Use this for absence assertions.
	ctx.Step(`^the recording output should have received exactly (\d+) events$`, func(n int) error {
		if recOut1 == nil {
			return fmt.Errorf("no recording output configured")
		}
		got := recOut1.eventCount()
		if got != n {
			return fmt.Errorf("recording output has %d events, expected exactly %d", got, n)
		}
		return nil
	})

	ctx.Step(`^both recording outputs should have received all (\d+) events$`, func(n int) error {
		if recOut1 == nil || recOut2 == nil {
			return fmt.Errorf("recording outputs not configured")
		}
		if recOut1.eventCount() < n {
			return fmt.Errorf("recording-1 has %d events, expected %d", recOut1.eventCount(), n)
		}
		if recOut2.eventCount() < n {
			return fmt.Errorf("recording-2 has %d events, expected %d", recOut2.eventCount(), n)
		}
		return nil
	})

	// "exactly" variant rules out duplicate-fan-out regressions in
	// addition to the dominant 0-events failure mode. Use for
	// synchronous-delivery scenarios where the count is deterministic.
	ctx.Step(`^both recording outputs should have received exactly (\d+) events$`, func(n int) error {
		if recOut1 == nil || recOut2 == nil {
			return fmt.Errorf("recording outputs not configured")
		}
		if got := recOut1.eventCount(); got != n {
			return fmt.Errorf("recording-1 has %d events, expected exactly %d", got, n)
		}
		if got := recOut2.eventCount(); got != n {
			return fmt.Errorf("recording-2 has %d events, expected exactly %d", got, n)
		}
		return nil
	})

	ctx.Step(`^stdout should have received the event before close returned$`, func() error {
		if stdoutBuf == nil {
			return fmt.Errorf("no stdout buffer configured")
		}
		lines := countLines(stdoutBuf.String())
		if lines < 1 {
			return fmt.Errorf("stdout has 0 events — synchronous delivery not working")
		}
		return nil
	})
}

func countLines(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}
