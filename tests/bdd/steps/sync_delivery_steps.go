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
	"errors"
	"fmt"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

// slowMockOutput is an audit.Output whose Write blocks for `delay`
// then returns nil. Used to test that synchronous delivery makes the
// caller's AuditEvent block for the duration of the slowest output's
// Write call.
type slowMockOutput struct {
	delay time.Duration
}

func (s *slowMockOutput) Write(_ []byte) error {
	time.Sleep(s.delay)
	return nil
}
func (s *slowMockOutput) Close() error { return nil }
func (s *slowMockOutput) Name() string { return "slow-output" }

// registerSyncDeliverySteps registers BDD step definitions for #549
// (synchronous-delivery feature file). The 4 step phrases below are
// exclusive to sync_delivery.feature; sync auditor builders that
// recur across feature files live in isolation_steps.go and
// async_edges_steps.go.
//
//nolint:gocognit // BDD step registration: 4 closures inline; splitting hurts readability
func registerSyncDeliverySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// audittest scenario state — local to sync_delivery scenarios.
	var (
		audittestAuditor  *audit.Auditor
		audittestRecorder *audittest.Recorder
	)

	ctx.Step(`^an auditor with synchronous delivery and a slow output that blocks (\d+)ms per write$`, func(delayMs int) error {
		out := &slowMockOutput{delay: time.Duration(delayMs) * time.Millisecond}
		var err error
		tc.Auditor, err = audit.New(
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithOutputs(out),
			audit.WithSynchronousDelivery(),
		)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.AddCleanup(func() { _ = tc.Auditor.Close() })
		return nil
	})

	ctx.Step(`^the audit call should have taken at least (\d+) milliseconds$`, func(minMs int) error {
		want := time.Duration(minMs) * time.Millisecond
		if tc.LastAuditDuration < want {
			return fmt.Errorf("audit call took %s, expected at least %s",
				tc.LastAuditDuration, want)
		}
		return nil
	})

	ctx.Step(`^an audittest auditor created via NewQuick with a standard taxonomy$`, func() error {
		// QuickTaxonomy with a single permissive event type covers the
		// standard "user_create" event used elsewhere in this feature.
		// audittest.NewQuick defaults to synchronous delivery — the
		// behaviour this scenario pins.
		tb := &bddTB{}
		auditor, rec, _ := audittest.NewQuick(tb, "user_create")
		if tb.Failed() {
			return fmt.Errorf("audittest.NewQuick failed: %s", tb.fatalMsg)
		}
		audittestAuditor = auditor
		audittestRecorder = rec
		// Cleanup: NewQuick registers tb.Cleanup; run those on scenario end.
		tc.AddCleanup(func() { tb.runCleanups() })
		return nil
	})

	ctx.Step(`^I audit event "([^"]*)" with required fields via the audittest auditor$`, func(eventType string) error {
		if audittestAuditor == nil {
			return errors.New("audittest auditor not initialised")
		}
		fields := audit.Fields{"outcome": "success", "actor_id": "actor-1"}
		if err := audittestAuditor.AuditEvent(audit.NewEvent(eventType, fields)); err != nil {
			return fmt.Errorf("audit event: %w", err)
		}
		return nil
	})

	ctx.Step(`^the audittest recorder should contain exactly (\d+) "([^"]+)" event with no Close call$`, func(n int, eventType string) error {
		if audittestRecorder == nil {
			return errors.New("audittest recorder not initialised")
		}
		// CRITICAL: do NOT call Close on the audittest auditor before
		// reading Events(). The contract under test is that
		// synchronous delivery makes events visible to the recorder
		// immediately after AuditEvent returns, with no Close-before-
		// assert ceremony.
		events := audittestRecorder.Events()
		if len(events) != n {
			return fmt.Errorf("audittest recorder has %d events, expected exactly %d", len(events), n)
		}
		for i, ev := range events {
			if ev.EventType != eventType {
				return fmt.Errorf("event[%d] has event_type %q, expected %q", i, ev.EventType, eventType)
			}
		}
		return nil
	})
}
