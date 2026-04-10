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
	"context"
	_ "embed"
	"log"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/loki"
	"github.com/axonops/go-audit/outputconfig"
)

//go:embed outputs.yaml
var outputsYAML []byte

// setupAuditLogger creates the logger with four named outputs, all
// loaded from outputs.yaml:
//
//  1. console (stdout) — all events, JSON, no HMAC
//  2. compliance_archive (file) — all events, CEF, HMAC v1 (SHA-256)
//  3. security_feed (file) — security + compliance, severity ≥ 7, HMAC v2 (SHA-512)
//  4. loki_dashboard (loki) — all events, JSON, PII stripped
//
// Per-output-type metrics (file rotation, Loki flush/drop) are wired
// by registering custom factories before loading the YAML config.
func setupAuditLogger(tax audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	// Override init()-registered default factories with metrics-aware
	// factories so file rotations and Loki flushes/drops are tracked
	// in Prometheus.
	audit.RegisterOutputFactory("file", file.NewFactory(m))
	audit.RegisterOutputFactory("loki", loki.NewFactory(m))

	// Load all four outputs from YAML. Environment variables in the
	// YAML (like ${LOKI_URL:-http://loki:3100/...}) are resolved at
	// load time.
	result, err := outputconfig.Load(context.Background(), outputsYAML, &tax, m)
	if err != nil {
		log.Printf("load outputs: %v", err)
		log.Printf("hint: run 'docker compose up -d' to start Loki and Postgres")
		return nil, err
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithMetrics(m),
	}
	opts = append(opts, result.Options...)

	return audit.NewLogger(result.Config, opts...)
}
