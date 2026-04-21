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

package syslog

import (
	"bytes"
	"fmt"
	"log/slog"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.RegisterOutputFactory("syslog", defaultFactory)
}

// defaultFactory creates a syslog output from YAML config. Per-output
// metrics are auto-detected via type assertion on coreMetrics.
// The logger is plumbed through to construction-time TLS warnings.
func defaultFactory(name string, rawConfig []byte, coreMetrics audit.Metrics, logger *slog.Logger) (audit.Output, error) {
	var syslogMetrics Metrics
	if sm, ok := coreMetrics.(Metrics); ok {
		syslogMetrics = sm
	}
	return buildOutput(name, rawConfig, syslogMetrics, logger)
}

// NewFactory returns an [audit.OutputFactory] that creates syslog
// outputs from YAML configuration with the provided syslog-specific
// metrics captured in the closure. Pass nil to disable syslog metrics.
func NewFactory(syslogMetrics Metrics) audit.OutputFactory {
	return func(name string, rawConfig []byte, _ audit.Metrics, logger *slog.Logger) (audit.Output, error) {
		return buildOutput(name, rawConfig, syslogMetrics, logger)
	}
}

// yamlTLSPolicy maps TLS policy fields from YAML.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlSyslogConfig is the YAML-specific representation of syslog
// output configuration. Maps snake_case YAML fields to the Go
// Config struct.
type yamlSyslogConfig struct { //nolint:govet // fieldalignment: readability preferred
	Network       string         `yaml:"network"`
	Address       string         `yaml:"address"`
	AppName       string         `yaml:"app_name"`
	Facility      string         `yaml:"facility"`
	TLSCert       string         `yaml:"tls_cert"`
	TLSKey        string         `yaml:"tls_key"`
	TLSCA         string         `yaml:"tls_ca"`
	TLSPolicy     *yamlTLSPolicy `yaml:"tls_policy"`
	Hostname      string         `yaml:"hostname"`
	MaxRetries    int            `yaml:"max_retries"`
	BufferSize    *int           `yaml:"buffer_size"`
	BatchSize     *int           `yaml:"batch_size"`
	FlushInterval string         `yaml:"flush_interval"`
	MaxBatchBytes *int           `yaml:"max_batch_bytes"`
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
		return -1 // sentinel: explicit zero from YAML
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, syslogMetrics Metrics, logger *slog.Logger) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit: syslog output %q: config is required", name)
	}

	var yc yamlSyslogConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit: syslog output %q: %w", name, audit.WrapUnknownFieldError(err, yc))
	}

	cfg := &Config{
		Network:       yc.Network,
		Address:       yc.Address,
		AppName:       yc.AppName,
		Facility:      yc.Facility,
		TLSCert:       yc.TLSCert,
		TLSKey:        yc.TLSKey,
		TLSCA:         yc.TLSCA,
		Hostname:      yc.Hostname,
		MaxRetries:    yc.MaxRetries,
		BufferSize:    intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
		BatchSize:     intPtrOrDefault(yc.BatchSize, DefaultBatchSize),
		MaxBatchBytes: intPtrOrDefault(yc.MaxBatchBytes, DefaultMaxBatchBytes),
	}
	if yc.FlushInterval != "" {
		d, err := time.ParseDuration(yc.FlushInterval)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog output %q: flush_interval %q: %w", name, yc.FlushInterval, audit.ErrConfigInvalid)
		}
		cfg.FlushInterval = d
	}
	if yc.TLSPolicy != nil {
		cfg.TLSPolicy = &audit.TLSPolicy{
			AllowTLS12:       yc.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: yc.TLSPolicy.AllowWeakCiphers,
		}
	}

	out, err := New(cfg, syslogMetrics, WithDiagnosticLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("audit: syslog output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}
