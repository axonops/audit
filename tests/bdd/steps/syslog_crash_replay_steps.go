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
	"net"
	"os/exec"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// registerSyslogCrashReplaySteps wires the steps used by the
// crash-replay and rapid-restart scenarios in
// tests/bdd/features/syslog_output.feature (#553). These exercise
// failure modes the reconnect path must survive without leaking
// goroutines, looping unbounded, or breaking metric accounting:
//
//   - syslog-ng killed mid-buffer; the auditor reconnects after
//     restart and accounts for every submitted event.
//   - rapid restarts in succession; reconnect backoff stays bounded.
//   - 1000 in-flight events when the daemon dies; on restart the
//     metric totals (submitted == delivered + dropped + filtered +
//     errors + buffer-drops) hold.
//
// Steps reuse the existing kill/restart docker-exec primitives in
// syslog_steps.go.
//
//nolint:gocognit,gocyclo,cyclop // independent ctx.Step registrations.
func registerSyslogCrashReplaySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the auditor uses core metrics$`, func() error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return nil
	})

	ctx.Step(`^I rapidly restart syslog-ng (\d+) times within (\d+) seconds$`,
		func(restarts, withinSeconds int) error {
			if restarts < 1 {
				return fmt.Errorf("restarts must be >= 1")
			}
			deadline := time.Now().Add(time.Duration(withinSeconds) * time.Second)
			interval := time.Duration(withinSeconds) * time.Second / time.Duration(restarts)
			for i := 0; i < restarts; i++ {
				if time.Now().After(deadline) {
					return fmt.Errorf("rapid restart loop exceeded %d s deadline at iteration %d", withinSeconds, i)
				}
				_, _ = exec.Command("docker", "exec", "bdd-syslog-ng-1",
					"sh", "-c",
					"kill $(cat /var/run/syslog-ng.pid 2>/dev/null) 2>/dev/null; "+
						"syslog-ng --no-caps -F &").CombinedOutput()
				// scenario-control delay (#559): half-interval pause
				// between the kill and the next restart to scatter
				// crashes deterministically across the deadline window.
				time.Sleep(interval / 2)
			}
			// Final restart so the remainder of the scenario has a
			// running daemon.
			_, _ = exec.Command("docker", "exec", "bdd-syslog-ng-1",
				"sh", "-c", "syslog-ng --no-caps -F &").CombinedOutput()
			return waitForSyslogReady(15 * time.Second)
		})

	// Accounting invariant: every event the caller submitted reaches
	// the buffer (Submitted) and then resolves to one of the terminal
	// counters:
	//
	//   submitted == delivered + buffer_drops
	//                + output_errors + output_filtered
	//                + validation_errors + serialization_errors
	//
	// Two flavours are exposed:
	//
	//   - "should hold" — strict equality. Use only when the scenario
	//     drains to completion without aborting (no kills mid-Close).
	//
	//   - "should hold within tolerance N" — allow up to N events to
	//     remain unaccounted. Drainable failure modes (kill +
	//     Close-with-bounded-timeout) can abandon a small number of
	//     in-flight events before any terminal counter fires; the
	//     bounded gap is the documented trade-off for the
	//     ShutdownTimeout contract.
	checkAccounting := func(submittedExpected int, tolerance int) error {
		if tc.MockMetrics == nil {
			return fmt.Errorf("no MockMetrics configured (Given step missing?)")
		}
		m := tc.MockMetrics
		submitted := m.Submitted

		var delivered int
		for k, v := range m.Events {
			if len(k) > 8 && k[len(k)-8:] == ":success" {
				delivered += v
			}
		}
		outputErrors := 0
		for _, v := range m.OutputErrors {
			outputErrors += v
		}
		outputFiltered := 0
		for _, v := range m.OutputFiltered {
			outputFiltered += v
		}
		validationErrors := 0
		for _, v := range m.ValidationErrors {
			validationErrors += v
		}
		serializationErrors := 0
		for _, v := range m.SerializationErrs {
			serializationErrors += v
		}
		accounted := delivered + m.BufferDrops + outputFiltered +
			validationErrors + serializationErrors + outputErrors

		if submittedExpected > 0 && submitted < submittedExpected {
			return fmt.Errorf("submitted=%d below expected %d",
				submitted, submittedExpected)
		}
		gap := submitted - accounted
		if gap < 0 {
			return fmt.Errorf(
				"impossible accounting: submitted=%d < accounted=%d "+
					"(delivered=%d drops=%d filtered=%d val=%d ser=%d errs=%d)",
				submitted, accounted, delivered, m.BufferDrops,
				outputFiltered, validationErrors, serializationErrors,
				outputErrors)
		}
		if gap > tolerance {
			return fmt.Errorf(
				"accounting gap %d exceeds tolerance %d: "+
					"submitted=%d delivered=%d drops=%d filtered=%d "+
					"val=%d ser=%d errs=%d",
				gap, tolerance, submitted, delivered, m.BufferDrops,
				outputFiltered, validationErrors, serializationErrors,
				outputErrors)
		}
		return nil
	}

	ctx.Step(`^the audit metrics accounting should hold$`,
		func() error { return checkAccounting(0, 0) })

	ctx.Step(`^the audit metrics accounting should hold within tolerance (\d+)$`,
		func(tolerance int) error { return checkAccounting(0, tolerance) })

	ctx.Step(`^the audit metrics submitted count should be (\d+)$`,
		func(want int) error {
			if tc.MockMetrics == nil {
				return fmt.Errorf("no MockMetrics configured (Given step missing?)")
			}
			got := tc.MockMetrics.Submitted
			if got != want {
				return fmt.Errorf("submitted count = %d, want %d", got, want)
			}
			return nil
		})

	ctx.Step(`^the syslog reconnect count should be at most (\d+)$`,
		func(maxReconnects int) error {
			if tc.SyslogMetrics == nil {
				return fmt.Errorf("no SyslogMetrics configured (Given step missing?)")
			}
			tc.SyslogMetrics.mu.Lock()
			got := tc.SyslogMetrics.reconnects
			tc.SyslogMetrics.mu.Unlock()
			if got > maxReconnects {
				return fmt.Errorf("reconnect count %d exceeds max %d (storm?)", got, maxReconnects)
			}
			return nil
		})
}

// waitForSyslogReady polls the syslog-ng TCP listener until it
// accepts a connection or the deadline expires. Used after rapid
// restarts to guarantee the next steps see a running daemon.
func waitForSyslogReady(timeout time.Duration) error {
	if pollUntil(timeout, 500*time.Millisecond, func() bool {
		conn, err := net.DialTimeout("tcp", "localhost:5514", 1*time.Second)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}) {
		return nil
	}
	return fmt.Errorf("syslog-ng not ready after %s", timeout)
}
