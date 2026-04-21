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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
)

// MockSyslogMetrics captures syslog.Metrics calls.
type MockSyslogMetrics struct {
	mu         sync.Mutex
	reconnects int
}

// RecordSyslogReconnect satisfies syslog.Metrics.
func (m *MockSyslogMetrics) RecordSyslogReconnect(_ string, _ bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconnects++
}

func registerSyslogSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSyslogGivenSteps(ctx, tc)
	registerSyslogWhenSteps(ctx, tc)
	registerSyslogThenSteps(ctx, tc)
}

func registerSyslogGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)"$`, func(network, address string) error {
		return createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address})
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with app name "([^"]*)"$`, func(network, address, appName string) error {
		return createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address, AppName: appName})
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with facility "([^"]*)"$`, func(network, address, facility string) error {
		return createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address, Facility: facility})
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with hostname "([^"]*)"$`, func(network, address, hostname string) error {
		return createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address, Hostname: hostname})
	})

	ctx.Step(`^I try to create a syslog output on "([^"]*)" to "([^"]*)" with hostname "([^"]*)"$`, func(network, address, hostname string) error {
		err := createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address, Hostname: hostname})
		if err != nil {
			tc.LastErr = err
		}
		return nil
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with max retries (\d+)$`, func(network, address string, retries int) error {
		return createSyslogAuditor(tc, &syslog.Config{Network: network, Address: address, MaxRetries: retries})
	})

	ctx.Step(`^mock syslog metrics are configured$`, func() error {
		tc.SyslogMetrics = &MockSyslogMetrics{}
		return nil
	})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with metrics and max retries (\d+)$`, func(network, address string, retries int) error {
		return createSyslogAuditorWithMetrics(tc, &syslog.Config{
			Network: network, Address: address, MaxRetries: retries,
		})
	})

	ctx.Step(`^an auditor with syslog TLS output to "([^"]*)" with CA cert$`, func(address string) error {
		certs := certDir()
		return createSyslogAuditor(tc, &syslog.Config{
			Network: "tcp+tls",
			Address: address,
			TLSCA:   filepath.Join(certs, "ca.crt"),
		})
	})

	// Batching (#599). Three Given variants cover the AC scenarios:
	//   - batch size + flush interval only
	//   - batch size + flush interval + max batch bytes
	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with batch size (\d+) and flush interval "([^"]*)"$`,
		func(network, address string, batchSize int, flushInterval string) error {
			d, err := time.ParseDuration(flushInterval)
			if err != nil {
				return fmt.Errorf("parse flush interval %q: %w", flushInterval, err)
			}
			return createSyslogAuditor(tc, &syslog.Config{
				Network:       network,
				Address:       address,
				BatchSize:     batchSize,
				FlushInterval: d,
			})
		})

	ctx.Step(`^an auditor with syslog output on "([^"]*)" to "([^"]*)" with batch size (\d+) and flush interval "([^"]*)" and max batch bytes (\d+)$`,
		func(network, address string, batchSize int, flushInterval string, maxBatchBytes int) error {
			d, err := time.ParseDuration(flushInterval)
			if err != nil {
				return fmt.Errorf("parse flush interval %q: %w", flushInterval, err)
			}
			return createSyslogAuditor(tc, &syslog.Config{
				Network:       network,
				Address:       address,
				BatchSize:     batchSize,
				FlushInterval: d,
				MaxBatchBytes: maxBatchBytes,
			})
		})

	ctx.Step(`^an auditor with syslog mTLS output to "([^"]*)"$`, func(address string) error {
		certs := certDir()
		return createSyslogAuditor(tc, &syslog.Config{
			Network: "tcp+tls",
			Address: address,
			TLSCA:   filepath.Join(certs, "ca.crt"),
			TLSCert: filepath.Join(certs, "client.crt"),
			TLSKey:  filepath.Join(certs, "client.key"),
		})
	})
}

func registerSyslogWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSyslogWhenBasicSteps(ctx, tc)
	registerSyslogWhenReconnectSteps(ctx, tc)
	registerSyslogWhenValidationSteps(ctx, tc)
}

func registerSyslogWhenBasicSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit (\d+) uniquely marked events$`, func(count int) error {
		for i := range count {
			m := marker("BDD")
			tc.Markers[fmt.Sprintf("multi_%d", i)] = m
			fields := defaultRequiredFields(tc.Taxonomy, "user_create")
			fields["marker"] = m
			if err := tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
				return fmt.Errorf("audit event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I audit an event with a (\d+)-byte payload$`, func(size int) error {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = strings.Repeat("x", size)
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields))
		return nil
	})

	// Oversized marker for the batching oversized-event scenario.
	// Uses a unique marker so the assertion can find this specific
	// event on the syslog server.
	ctx.Step(`^I audit a uniquely marked event with a (\d+)-byte payload$`, func(size int) error {
		m := marker("OVERSIZED")
		tc.Markers["default"] = m
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		// Prefix the marker so it is searchable; the padding makes
		// the total payload cross MaxBatchBytes in the scenario.
		fields["marker"] = m + strings.Repeat("x", size)
		return tc.Auditor.AuditEvent(audit.NewEvent("user_create", fields))
	})

	ctx.Step(`^I try to create a syslog output on "([^"]*)" to "([^"]*)" with invalid CA$`, func(network, address string) error {
		certs := certDir()
		out, err := syslog.New(&syslog.Config{
			Network: network,
			Address: address,
			TLSCA:   filepath.Join(certs, "invalid.crt"),
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with TLS cert but no key$`, func() error {
		certs := certDir()
		out, err := syslog.New(&syslog.Config{
			Network: "tcp+tls",
			Address: "localhost:6514",
			TLSCA:   filepath.Join(certs, "ca.crt"),
			TLSCert: filepath.Join(certs, "client.crt"),
			// No TLSKey
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

}

func registerSyslogWhenReconnectSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I stop the syslog-ng process$`, func() error { return stopSyslogAndScheduleRestart(tc) })
	ctx.Step(`^I audit (\d+) uniquely marked events after syslog down$`,
		func(n int) error { return auditMarkedEventsAfterSyslogDown(tc, n) })

	ctx.Step(`^I restart the syslog-ng process$`, func() error {
		// Kill and restart syslog-ng inside the Docker container.
		out, err := exec.Command("docker", "exec", "bdd-syslog-ng-1",
			"sh", "-c", "kill $(cat /var/run/syslog-ng.pid 2>/dev/null) 2>/dev/null; syslog-ng --no-caps -F &").CombinedOutput()
		if err != nil {
			// syslog-ng may restart automatically, or PID file may not exist.
			// Log but don't fail — the restart may happen via container health check.
			_ = out
		}
		return nil
	})

	ctx.Step(`^I wait for syslog-ng to be ready$`, func() error {
		// Poll until syslog-ng accepts TCP connections on port 5514.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", "localhost:5514", 1*time.Second)
			if err == nil {
				_ = conn.Close()
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("syslog-ng not ready after 15 seconds")
	})

	ctx.Step(`^I audit a second uniquely marked "([^"]*)" event$`, func(eventType string) error {
		m := marker("BDD2")
		tc.Markers["second"] = m
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		fields["marker"] = m
		// The first write after restart may fail and trigger reconnect.
		// Retry a few times to allow reconnection.
		for range 10 {
			err := tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
			if err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		tc.LastErr = tc.Auditor.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^the syslog server should contain the second marker within (\d+) seconds$`, func(timeout int) error {
		m, ok := tc.Markers["second"]
		if !ok {
			return fmt.Errorf("no second marker set")
		}
		return assertSyslogContains(m, time.Duration(timeout)*time.Second)
	})

}

// stopSyslogAndScheduleRestart kills the syslog-ng process inside the
// test container and schedules a cleanup that restarts it after the
// scenario completes. The restart waits until syslog-ng accepts TCP
// connections again so subsequent scenarios have working infrastructure.
func stopSyslogAndScheduleRestart(tc *AuditTestContext) error {
	_, _ = exec.Command("docker", "exec", "bdd-syslog-ng-1",
		"sh", "-c", "kill $(cat /var/run/syslog-ng.pid 2>/dev/null) 2>/dev/null").CombinedOutput()
	time.Sleep(200 * time.Millisecond)
	tc.AddCleanup(func() {
		_, _ = exec.Command("docker", "exec", "bdd-syslog-ng-1",
			"sh", "-c", "syslog-ng --no-caps -F &").CombinedOutput()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", "localhost:5514", 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
	return nil
}

// auditMarkedEventsAfterSyslogDown emits n valid user_create events
// with unique markers via the auditor under test. Events include every
// required field so the validator accepts them — otherwise they never
// reach the fanout/drain pipeline and the file-isolation assertion
// silently measures "zero events because validation rejected them"
// instead of the intended "zero events because syslog blocked file".
func auditMarkedEventsAfterSyslogDown(tc *AuditTestContext, n int) error {
	for i := range n {
		marker := fmt.Sprintf("after-syslog-down-%d", i)
		tc.Markers[fmt.Sprintf("event-%d", i)] = marker
		ev := audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": fmt.Sprintf("bdd-user-%d", i),
			"reason":   marker,
		})
		if err := tc.Auditor.AuditEvent(ev); err != nil {
			return fmt.Errorf("AuditEvent %d returned unexpected error: %w", i, err)
		}
	}
	return nil
}

func registerSyslogWhenValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a syslog output with TLS key but no cert$`, func() error {
		certs := certDir()
		out, err := syslog.New(&syslog.Config{
			Network: "tcp+tls",
			Address: "localhost:6514",
			TLSCA:   filepath.Join(certs, "ca.crt"),
			TLSKey:  filepath.Join(certs, "client.key"),
			// No TLSCert
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with empty address$`, func() error {
		out, err := syslog.New(&syslog.Config{Network: "tcp", Address: ""}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output on "([^"]*)" to "([^"]*)"$`, func(network, address string) error {
		out, err := syslog.New(&syslog.Config{Network: network, Address: address}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with facility "([^"]*)"$`, func(facility string) error {
		out, err := syslog.New(&syslog.Config{
			Network:  "tcp",
			Address:  "localhost:5514",
			Facility: facility,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
		}
		tc.LastErr = err
		return nil
	})
}

func registerSyslogThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the syslog server should contain the marker within (\d+) seconds$`, func(t int) error { return assertSyslogDefaultMarker(tc, t) })
	ctx.Step(`^the syslog server should contain "([^"]*)" within (\d+) seconds$`, func(text string, t int) error { return assertSyslogContains(text, time.Duration(t)*time.Second) })
	ctx.Step(`^the syslog server should contain all (\d+) markers within (\d+) seconds$`, func(c, t int) error { return assertSyslogAllMarkers(tc, c, t) })
	ctx.Step(`^the syslog line with the marker should contain "([^"]*)"$`, func(text string) error { return assertSyslogMarkerLineContains(tc, text) })
	ctx.Step(`^the syslog line with the marker should contain the current year$`, func() error { return assertSyslogMarkerLineContains(tc, time.Now().Format("2006")) })
	ctx.Step(`^the syslog line with "([^"]*)" should contain "([^"]*)"$`, assertSyslogLineContainsBoth)
	ctx.Step(`^the syslog construction should fail with exact error:$`, func(doc *godog.DocString) error {
		return assertSyslogConstructionExactError(tc, strings.TrimSpace(doc.Content))
	})
	ctx.Step(`^the syslog construction should fail with an error containing "([^"]*)"$`, func(s string) error { return assertSyslogConstructionError(tc, s) })
	// Batching framing assertion (#599 AC #4d). Each audited event
	// in a batch must arrive as a distinct RFC 5424 message, not
	// concatenated bytes. syslog-ng writes one log line per
	// received syslog message, so each marker should appear in
	// exactly ONE line. If the library broke framing by
	// concatenating, markers would collide in a single line.
	ctx.Step(`^each of the (\d+) delivered messages should be a distinct RFC 5424 frame$`,
		func(count int) error {
			logText := readSyslogLogFromDocker()
			for i := range count {
				key := fmt.Sprintf("multi_%d", i)
				m, ok := tc.Markers[key]
				if !ok {
					return fmt.Errorf("expected marker %s not recorded", key)
				}
				occurrences := strings.Count(logText, m)
				if occurrences != 1 {
					return fmt.Errorf("marker %q appeared %d times (expected exactly 1 — concatenated batch?)", m, occurrences)
				}
			}
			return nil
		})

	ctx.Step(`^the syslog metrics should have recorded at least (\d+) reconnect$`, func(minCount int) error {
		if tc.SyslogMetrics == nil {
			return fmt.Errorf("no syslog metrics configured")
		}
		tc.SyslogMetrics.mu.Lock()
		defer tc.SyslogMetrics.mu.Unlock()
		if tc.SyslogMetrics.reconnects < minCount {
			return fmt.Errorf("expected >= %d syslog reconnects, got %d", minCount, tc.SyslogMetrics.reconnects)
		}
		return nil
	})
}

func assertSyslogDefaultMarker(tc *AuditTestContext, timeoutSec int) error {
	m, ok := tc.Markers["default"]
	if !ok {
		return fmt.Errorf("no default marker set")
	}
	return assertSyslogContains(m, time.Duration(timeoutSec)*time.Second)
}

func assertSyslogAllMarkers(tc *AuditTestContext, count, timeoutSec int) error {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for i := range count {
		key := fmt.Sprintf("multi_%d", i)
		m, ok := tc.Markers[key]
		if !ok {
			return fmt.Errorf("no marker with key %q", key)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timeout waiting for marker %d (%s)", i, m)
		}
		if err := assertSyslogContains(m, remaining); err != nil {
			return fmt.Errorf("marker %d: %w", i, err)
		}
	}
	return nil
}

func assertSyslogLineContainsBoth(searchMarker, text string) error {
	log := readSyslogLogFromDocker()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, searchMarker) && strings.Contains(line, text) {
			return nil
		}
	}
	return fmt.Errorf("no syslog line containing both %q and %q", searchMarker, text)
}

func assertSyslogConstructionExactError(tc *AuditTestContext, expected string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
	}
	if tc.LastErr.Error() != expected {
		return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
	}
	return nil
}

func assertSyslogConstructionError(tc *AuditTestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected syslog construction error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}

// --- Internal helpers ---

// createSyslogAuditor creates an auditor with a syslog output.
func createSyslogAuditor(tc *AuditTestContext, cfg *syslog.Config) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(out),
	}
	opts = append(opts, tc.Options...)

	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// createSyslogAuditorWithMetrics creates an auditor with syslog output and metrics.
func createSyslogAuditorWithMetrics(tc *AuditTestContext, cfg *syslog.Config) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	var sm syslog.Metrics
	if tc.SyslogMetrics != nil {
		sm = tc.SyslogMetrics
	}
	out, err := syslog.New(cfg, sm)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.AddCleanup(func() { _ = out.Close() })

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(out),
	}
	opts = append(opts, tc.Options...)

	auditor, err := audit.New(opts...)
	if err != nil {
		return fmt.Errorf("create auditor: %w", err)
	}
	tc.Auditor = auditor
	tc.AddCleanup(func() { _ = auditor.Close() })
	return nil
}

// certDir returns the absolute path to the test certificates directory.
// BDD tests run from tests/bdd/ so certs are at ../testdata/certs.
func certDir() string {
	abs, err := filepath.Abs("../testdata/certs")
	if err != nil {
		return "../testdata/certs"
	}
	return abs
}

// readSyslogLogFromDocker reads the syslog-ng audit log from the container.
func readSyslogLogFromDocker() string {
	out, err := exec.Command("docker", "exec", "bdd-syslog-ng-1",
		"cat", "/var/log/syslog-ng/audit.log").CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// assertSyslogContains polls syslog until text appears or timeout.
func assertSyslogContains(text string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(readSyslogLogFromDocker(), text) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("syslog does not contain %q after %v", text, timeout)
}

// assertSyslogMarkerLineContains finds the syslog line with the default
// marker and checks it contains the given text.
func assertSyslogMarkerLineContains(tc *AuditTestContext, text string) error {
	m, ok := tc.Markers["default"]
	if !ok {
		return fmt.Errorf("no default marker set")
	}
	log := readSyslogLogFromDocker()
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, m) {
			if strings.Contains(line, text) {
				return nil
			}
			return fmt.Errorf("syslog line with marker %q does not contain %q: %s", m, text, line)
		}
	}
	return fmt.Errorf("no syslog line found with marker %q", m)
}
