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
	"fmt"
	"log"
	"os"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/loki"
	"github.com/axonops/go-audit/outputconfig"
)

// setupAuditLogger loads outputs.yaml from the filesystem and creates
// the logger. The taxonomy is embedded (compile-time contract), but
// output configuration is loaded at runtime so it can change per
// environment without rebuilding the binary.
//
// The four outputs defined in outputs.yaml:
//  1. console (stdout) — all events, JSON, no HMAC
//  2. compliance_archive (file) — all events, CEF, HMAC v1 (SHA-256)
//  3. security_feed (file) — security + compliance, severity ≥ 7, HMAC v2 (SHA-512)
//  4. loki_dashboard (loki) — all events, JSON, PII stripped
func setupAuditLogger(tax audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	// Load output configuration from the filesystem. In production,
	// this path comes from a flag or environment variable so each
	// environment (dev/staging/prod) can use different output configs
	// without rebuilding.
	configPath := envOr("AUDIT_CONFIG_PATH", "outputs.yaml")
	outputsYAML, err := os.ReadFile(configPath) //nolint:gosec // config path from trusted source (env var or default)
	if err != nil {
		return nil, fmt.Errorf("read output config %s: %w", configPath, err)
	}

	// Register metrics-aware factories so file rotations and Loki
	// flushes/drops are tracked in Prometheus. Without this, the
	// blank imports (via outputconfig) register default factories
	// that work but don't report metrics.
	audit.RegisterOutputFactory("file", file.NewFactory(m))
	audit.RegisterOutputFactory("loki", loki.NewFactory(m))

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
