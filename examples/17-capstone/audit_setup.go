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

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register "file" output type
	_ "github.com/axonops/audit/loki" // register "loki" output type
	"github.com/axonops/audit/outputconfig"
)

// setupAuditLogger creates a logger using the NewLogger facade.
// The taxonomy is embedded (compile-time contract), and output
// configuration is loaded from the filesystem at runtime so it can
// change per environment without rebuilding the binary.
//
// Blank imports register each output type's factory via init().
// The YAML file defines which outputs are active — adding or removing
// outputs is a config change, not a code change. Per-output metrics
// (file rotation, Loki flush) are auto-detected from the core metrics
// interface via type assertion when passed through WithCoreMetrics.
//
// HMAC salts, versions, algorithms, and enabled flags are resolved
// from OpenBao at startup via ref+openbao:// URIs in outputs.yaml.
// The OpenBao provider is configured declaratively in the outputs.yaml
// secrets: section — no programmatic provider setup is needed.
func setupAuditLogger(m *auditMetrics) (*audit.Logger, error) {
	configPath := envOr("AUDIT_CONFIG_PATH", "outputs.yaml")
	return outputconfig.NewLogger(context.Background(), taxonomyYAML, configPath,
		[]outputconfig.LoadOption{outputconfig.WithCoreMetrics(m)},
		audit.WithMetrics(m),
	)
}
