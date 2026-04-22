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

package file

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.RegisterOutputFactory("file", defaultFactory)
}

// defaultFactory creates a file output from YAML config. Per-output
// metrics are auto-detected via type assertion on coreMetrics.
// The logger is plumbed through to construction-time permission-mode
// warnings.
func defaultFactory(name string, rawConfig []byte, coreMetrics audit.Metrics, logger *slog.Logger, _ audit.FrameworkContext) (audit.Output, error) {
	var fileMetrics Metrics
	if fm, ok := coreMetrics.(Metrics); ok {
		fileMetrics = fm
	}
	return buildOutput(name, rawConfig, fileMetrics, logger)
}

// NewFactory returns an [audit.OutputFactory] that creates file outputs
// from YAML configuration with the provided file-specific metrics
// captured in the closure. Pass nil to disable file metrics.
func NewFactory(fileMetrics Metrics) audit.OutputFactory {
	return func(name string, rawConfig []byte, _ audit.Metrics, logger *slog.Logger, _ audit.FrameworkContext) (audit.Output, error) {
		return buildOutput(name, rawConfig, fileMetrics, logger)
	}
}

// yamlFileConfig is the YAML-specific representation of file output
// configuration. It maps snake_case YAML fields to the Go Config
// struct. The existing Config struct does not gain yaml tags —
// this struct is the mapping layer.
type yamlFileConfig struct { //nolint:govet // fieldalignment: readability preferred over packing
	Path        string `yaml:"path"`
	Permissions string `yaml:"permissions"`
	MaxSizeMB   int    `yaml:"max_size_mb"`
	MaxBackups  int    `yaml:"max_backups"`
	MaxAgeDays  int    `yaml:"max_age_days"`
	Compress    *bool  `yaml:"compress"`
	BufferSize  *int   `yaml:"buffer_size"`
}

// intPtrOrDefault returns the pointed-to value if non-nil, or the
// default if nil (field not specified in YAML). When the pointer is
// non-nil and the value is zero, returns -1 as a sentinel.
// applyDefaults treats values <= 0 as "not set" and replaces them
// with the default, so explicit YAML zero silently becomes the
// default. This matches the webhook and loki pattern.
func intPtrOrDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	if *p == 0 {
		return -1 // sentinel: explicit zero from YAML → rejected by validation
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, fileMetrics Metrics, logger *slog.Logger) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit: file output %q: config is required", name)
	}

	var yc yamlFileConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit: file output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg := Config{
		Path:        yc.Path,
		Permissions: yc.Permissions,
		MaxSizeMB:   yc.MaxSizeMB,
		MaxBackups:  yc.MaxBackups,
		MaxAgeDays:  yc.MaxAgeDays,
		Compress:    yc.Compress,
		BufferSize:  intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
	}

	out, err := New(cfg, fileMetrics, WithDiagnosticLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("audit: file output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}
