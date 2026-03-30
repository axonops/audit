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

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/outputconfig"
	"github.com/axonops/go-audit/syslog"
	"github.com/axonops/go-audit/webhook"
)

//go:embed outputs.yaml
var outputsYAML []byte

// setupAuditLogger creates the logger with five named outputs, all
// loaded from outputs.yaml:
//
//  1. console (stdout) — all events, JSON
//  2. audit_log (file) — exclude read events, JSON
//  3. admin_log (file) — admin events only, CEF
//  4. syslog_security (syslog TCP) — security events only, JSON
//  5. webhook_siem (webhook HTTP) — all events, JSON
//
// Per-output-type metrics (file rotation, syslog reconnection,
// webhook flush) are wired by registering custom factories before
// loading the YAML config.
func setupAuditLogger(tax audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	// Override init()-registered default factories with metrics-aware
	// factories so file rotations, syslog reconnects, and webhook
	// flushes are tracked in Prometheus.
	audit.RegisterOutputFactory("file", file.NewFactory(m))
	audit.RegisterOutputFactory("syslog", syslog.NewFactory(m))
	audit.RegisterOutputFactory("webhook", webhook.NewFactory(m))

	// Load all five outputs from YAML. Environment variables in the
	// YAML (like ${SYSLOG_ADDR:-localhost:5514}) are resolved at
	// load time.
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

	return audit.NewLogger(audit.Config{
		Version: 1,
		Enabled: true,
	}, opts...)
}
