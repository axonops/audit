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
	"os"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register "file" output type
	_ "github.com/axonops/audit/loki" // register "loki" output type
	"github.com/axonops/audit/outputconfig"
)

// setupAuditLogger loads outputs.yaml from the filesystem and creates
// the logger. The taxonomy is embedded (compile-time contract), but
// output configuration is loaded at runtime so it can change per
// environment without rebuilding the binary.
//
// Blank imports register each output type's factory via init().
// The YAML file defines which outputs are active — adding or removing
// outputs is a config change, not a code change. Per-output metrics
// (file rotation, Loki flush) will be auto-detected from the core
// metrics interface once issue #386 is resolved.
func setupAuditLogger(tax *audit.Taxonomy, m *auditMetrics) (*audit.Logger, error) {
	// Load output configuration from the filesystem. In production,
	// this path comes from a flag or environment variable so each
	// environment (dev/staging/prod) can use different output configs
	// without rebuilding.
	configPath := envOr("AUDIT_CONFIG_PATH", "outputs.yaml")
	outputsYAML, err := os.ReadFile(configPath) //nolint:gosec // config path from trusted source (env var or default)
	if err != nil {
		return nil, fmt.Errorf("read output config %s: %w", configPath, err)
	}

	// Load all outputs from YAML. The core metrics (m) are passed
	// for event counting, buffer drops, and validation errors.
	// Output-specific metrics (file.Metrics, loki.Metrics) will be
	// auto-detected via type assertion once #386 lands.
	result, err := outputconfig.Load(context.Background(), outputsYAML, tax, outputconfig.WithCoreMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("load output config: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tax),
		audit.WithMetrics(m),
	}
	opts = append(opts, result.Options...)

	return audit.NewLogger(opts...)
}
