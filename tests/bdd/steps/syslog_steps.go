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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/syslog"
)

func registerSyslogSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerSyslogGivenSteps(ctx, tc)
	registerSyslogWhenSteps(ctx, tc)
	registerSyslogThenSteps(ctx, tc)
}

func registerSyslogGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with syslog output on "([^"]*)" to "([^"]*)"$`, func(network, address string) error {
		return createSyslogLogger(tc, &syslog.Config{Network: network, Address: address})
	})

	ctx.Step(`^a logger with syslog output on "([^"]*)" to "([^"]*)" with app name "([^"]*)"$`, func(network, address, appName string) error {
		return createSyslogLogger(tc, &syslog.Config{Network: network, Address: address, AppName: appName})
	})

	ctx.Step(`^a logger with syslog TLS output to "([^"]*)" with CA cert$`, func(address string) error {
		certs := certDir()
		return createSyslogLogger(tc, &syslog.Config{
			Network: "tcp+tls",
			Address: address,
			TLSCA:   filepath.Join(certs, "ca.crt"),
		})
	})

	ctx.Step(`^a logger with syslog mTLS output to "([^"]*)"$`, func(address string) error {
		certs := certDir()
		return createSyslogLogger(tc, &syslog.Config{
			Network: "tcp+tls",
			Address: address,
			TLSCA:   filepath.Join(certs, "ca.crt"),
			TLSCert: filepath.Join(certs, "client.crt"),
			TLSKey:  filepath.Join(certs, "client.key"),
		})
	})
}

func registerSyslogWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit (\d+) uniquely marked events$`, func(count int) error {
		for i := range count {
			m := marker("BDD")
			tc.Markers[fmt.Sprintf("multi_%d", i)] = m
			fields := defaultRequiredFields(tc.Taxonomy, "user_create")
			fields["marker"] = m
			if err := tc.Logger.Audit("user_create", fields); err != nil {
				return fmt.Errorf("audit event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I audit an event with a (\d+)-byte payload$`, func(size int) error {
		fields := defaultRequiredFields(tc.Taxonomy, "user_create")
		fields["marker"] = strings.Repeat("x", size)
		tc.LastErr = tc.Logger.Audit("user_create", fields)
		return nil
	})

	ctx.Step(`^I try to create a syslog output on "([^"]*)" to "([^"]*)" with invalid CA$`, func(network, address string) error {
		certs := certDir()
		_, err := syslog.New(&syslog.Config{
			Network: network,
			Address: address,
			TLSCA:   filepath.Join(certs, "invalid.crt"),
		}, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with TLS cert but no key$`, func() error {
		certs := certDir()
		_, err := syslog.New(&syslog.Config{
			Network: "tcp+tls",
			Address: "localhost:6514",
			TLSCA:   filepath.Join(certs, "ca.crt"),
			TLSCert: filepath.Join(certs, "client.crt"),
			// No TLSKey
		}, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with empty address$`, func() error {
		_, err := syslog.New(&syslog.Config{Network: "tcp", Address: ""}, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output on "([^"]*)" to "([^"]*)"$`, func(network, address string) error {
		_, err := syslog.New(&syslog.Config{Network: network, Address: address}, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a syslog output with facility "([^"]*)"$`, func(facility string) error {
		_, err := syslog.New(&syslog.Config{
			Network:  "tcp",
			Address:  "localhost:5514",
			Facility: facility,
		}, nil)
		tc.LastErr = err
		return nil
	})
}

func registerSyslogThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the syslog server should contain the marker within (\d+) seconds$`, func(timeout int) error {
		m, ok := tc.Markers["default"]
		if !ok {
			return fmt.Errorf("no default marker set")
		}
		return assertSyslogContains(m, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the syslog server should contain "([^"]*)" within (\d+) seconds$`, func(text string, timeout int) error {
		return assertSyslogContains(text, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the syslog server should contain all (\d+) markers within (\d+) seconds$`, func(count, timeout int) error {
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
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
	})

	ctx.Step(`^the syslog line with the marker should contain "([^"]*)"$`, func(text string) error {
		return assertSyslogMarkerLineContains(tc, text)
	})

	ctx.Step(`^the syslog line with the marker should contain the current year$`, func() error {
		return assertSyslogMarkerLineContains(tc, time.Now().Format("2006"))
	})

	ctx.Step(`^the syslog line with "([^"]*)" should contain "([^"]*)"$`, func(searchMarker, text string) error {
		log := readSyslogLogFromDocker()
		for _, line := range strings.Split(log, "\n") {
			if strings.Contains(line, searchMarker) && strings.Contains(line, text) {
				return nil
			}
		}
		return fmt.Errorf("no syslog line containing both %q and %q", searchMarker, text)
	})

	ctx.Step(`^the syslog construction should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected syslog construction error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})
}

// --- Internal helpers ---

// createSyslogLogger creates a logger with a syslog output.
func createSyslogLogger(tc *AuditTestContext, cfg *syslog.Config) error {
	if cfg.Facility == "" {
		cfg.Facility = "local0"
	}
	out, err := syslog.New(cfg, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(out),
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
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
