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

package main

import (
	"log"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/syslog"
	"github.com/axonops/go-audit/webhook"
)

// setupAuditLogger creates the logger with five named outputs:
//
//  1. stdout — all events, JSON (dev visibility)
//  2. audit.log — exclude read events, JSON (persistent log)
//  3. admin-audit.log — admin events only, CEF (SIEM trail)
//  4. syslog TCP — security events only, JSON (central syslog)
//  5. webhook HTTP — all events, JSON (external SIEM/Splunk)
func setupAuditLogger(tax audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	opts := []audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithMetrics(m),
	}

	// 1. Stdout — all events.
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		return nil, err
	}
	opts = append(opts, audit.WithNamedOutput(
		audit.WrapOutput(stdout, "console"), nil, nil,
	))

	// 2. audit.log — exclude read events.
	auditFile, err := file.New(file.Config{
		Path:        envOr("AUDIT_LOG_PATH", "./audit.log"),
		MaxSizeMB:   100,
		MaxBackups:  5,
		Permissions: "0600",
	}, m) // m satisfies file.Metrics
	if err != nil {
		return nil, err
	}
	opts = append(opts, audit.WithNamedOutput(
		audit.WrapOutput(auditFile, "audit_log"),
		&audit.EventRoute{ExcludeCategories: []string{CategoryRead}},
		nil,
	))

	// 3. admin-audit.log — admin events only, CEF format.
	adminFile, err := file.New(file.Config{
		Path:        envOr("ADMIN_LOG_PATH", "./admin-audit.log"),
		MaxSizeMB:   50,
		Permissions: "0600",
	}, m)
	if err != nil {
		return nil, err
	}
	cefFmt := &audit.CEFFormatter{
		Vendor:  "AxonOps",
		Product: "CRUDExample",
		Version: "0.1.0",
		SeverityFunc: func(eventType string) int {
			if eventType == EventAuthFailure {
				return 8
			}
			return 5
		},
	}
	opts = append(opts, audit.WithNamedOutput(
		audit.WrapOutput(adminFile, "admin_log"),
		&audit.EventRoute{IncludeCategories: []string{CategoryAdmin}},
		cefFmt,
	))

	// 4. Syslog — security events only.
	syslogAddr := envOr("SYSLOG_ADDR", "localhost:5514")
	syslogOut, err := syslog.New(&syslog.Config{
		Network: "tcp",
		Address: syslogAddr,
		AppName: "crud-api",
	}, m) // m satisfies syslog.Metrics
	if err != nil {
		log.Printf("syslog output unavailable (%s): %v — continuing without it", syslogAddr, err)
	} else {
		opts = append(opts, audit.WithNamedOutput(
			audit.WrapOutput(syslogOut, "syslog_security"),
			&audit.EventRoute{IncludeCategories: []string{CategorySecurity}},
			nil,
		))
	}

	// 5. Webhook — all events.
	webhookURL := envOr("WEBHOOK_URL", "http://localhost:8081/events")
	webhookOut, err := webhook.New(&webhook.Config{
		URL:                webhookURL,
		BatchSize:          50,
		FlushInterval:      5 * time.Second,
		Timeout:            10 * time.Second,
		MaxRetries:         3,
		AllowInsecureHTTP:  true, // dev only — use HTTPS in production
		AllowPrivateRanges: true, // dev only — localhost webhook receiver
	}, m, m) // m satisfies both audit.Metrics and webhook.Metrics
	if err != nil {
		log.Printf("webhook output unavailable (%s): %v — continuing without it", webhookURL, err)
	} else {
		opts = append(opts, audit.WithNamedOutput(
			audit.WrapOutput(webhookOut, "webhook_siem"), nil, nil,
		))
	}

	return audit.NewLogger(audit.Config{
		Version: 1,
		Enabled: true,
	}, opts...)
}
