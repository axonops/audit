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
	_ "embed"
	"log"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/outputconfig"
	"github.com/axonops/go-audit/syslog"
	"github.com/axonops/go-audit/webhook"
)

//go:embed outputs.yaml
var outputsYAML []byte

// setupAuditLogger creates the logger with five named outputs:
//
//  1. console (stdout) — all events, JSON — from outputs.yaml
//  2. audit_log (file) — exclude read events, JSON — from outputs.yaml
//  3. admin_log (file) — admin events only, CEF — from outputs.yaml
//  4. syslog_security (syslog TCP) — security events only — from outputs.yaml
//  5. webhook_siem (webhook HTTP) — all events — created programmatically
//
// Outputs 1-4 are loaded from outputs.yaml. The webhook output is
// created programmatically because the dev environment uses plain HTTP,
// and AllowInsecureHTTP cannot be set via YAML (by design — insecure
// options require the programmatic API). In production with HTTPS, you
// would move the webhook into outputs.yaml.
func setupAuditLogger(tax audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	// Override init()-registered default factories with metrics-aware
	// factories so file rotations, syslog reconnects, and webhook
	// flushes are tracked in Prometheus.
	audit.RegisterOutputFactory("file", file.NewFactory(m))
	audit.RegisterOutputFactory("syslog", syslog.NewFactory(m))

	// Load outputs 1-4 from YAML. Environment variables in the YAML
	// (like ${SYSLOG_ADDR:-localhost:5514}) are resolved at load time.
	result, err := outputconfig.Load(outputsYAML, &tax, m)
	if err != nil {
		log.Printf("load outputs: %v", err)
		log.Printf("hint: run 'docker compose up -d' to start the infrastructure")
		return nil, err
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithMetrics(m),
	}
	opts = append(opts, result.Options...)

	// Output 5: webhook — created programmatically because the dev
	// environment uses plain HTTP (AllowInsecureHTTP). In production
	// with HTTPS, move this to outputs.yaml instead.
	webhookURL := envOr("WEBHOOK_URL", "http://localhost:8081/events")
	webhookOut, webhookErr := webhook.New(&webhook.Config{
		URL:                webhookURL,
		BatchSize:          50,
		FlushInterval:      5 * time.Second,
		Timeout:            10 * time.Second,
		MaxRetries:         3,
		AllowInsecureHTTP:  true, // dev only — use HTTPS in production
		AllowPrivateRanges: true, // dev only — localhost webhook receiver
	}, m, m) // m satisfies both audit.Metrics and webhook.Metrics
	if webhookErr != nil {
		log.Printf("webhook output unavailable (%s): %v — continuing without it", webhookURL, webhookErr)
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
