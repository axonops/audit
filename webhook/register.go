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

package webhook

import (
	"bytes"
	"fmt"
	"time"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

func init() {
	audit.RegisterOutputFactory("webhook", defaultFactory)
}

// defaultFactory creates a webhook output from YAML config. Core
// metrics are forwarded for delivery reporting. Per-output metrics
// are auto-detected via type assertion on coreMetrics.
func defaultFactory(name string, rawConfig []byte, coreMetrics audit.Metrics) (audit.Output, error) {
	var webhookMetrics Metrics
	if wm, ok := coreMetrics.(Metrics); ok {
		webhookMetrics = wm
	}
	return buildOutput(name, rawConfig, coreMetrics, webhookMetrics)
}

// NewFactory returns an [audit.OutputFactory] that creates webhook
// outputs from YAML configuration with the provided webhook-specific
// metrics captured in the closure. Pass nil to disable webhook metrics.
func NewFactory(webhookMetrics Metrics) audit.OutputFactory {
	return func(name string, rawConfig []byte, coreMetrics audit.Metrics) (audit.Output, error) {
		return buildOutput(name, rawConfig, coreMetrics, webhookMetrics)
	}
}

// yamlWebhookConfig is the YAML-specific representation of webhook
// output configuration. Maps snake_case YAML fields to the Go Config
// struct.
type yamlWebhookConfig struct { //nolint:govet // fieldalignment: readability preferred
	URL                string            `yaml:"url"`
	Headers            map[string]string `yaml:"headers"`
	TLSCA              string            `yaml:"tls_ca"`
	TLSCert            string            `yaml:"tls_cert"`
	TLSKey             string            `yaml:"tls_key"`
	TLSPolicy          *yamlTLSPolicy    `yaml:"tls_policy"`
	FlushInterval      yamlDuration      `yaml:"flush_interval"`
	Timeout            yamlDuration      `yaml:"timeout"`
	BatchSize          *int              `yaml:"batch_size"`
	BufferSize         *int              `yaml:"buffer_size"`
	MaxRetries         *int              `yaml:"max_retries"`
	AllowInsecureHTTP  bool              `yaml:"allow_insecure_http"`
	AllowPrivateRanges bool              `yaml:"allow_private_ranges"`
}

// yamlTLSPolicy maps TLS policy fields from YAML.
type yamlTLSPolicy struct {
	AllowTLS12       bool `yaml:"allow_tls12"`
	AllowWeakCiphers bool `yaml:"allow_weak_ciphers"`
}

// yamlDuration is a time.Duration that unmarshals from a YAML string
// like "5s", "100ms", "10m".
type yamlDuration time.Duration

func (d *yamlDuration) UnmarshalYAML(data []byte) error {
	var s string
	if err := yaml.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("decode duration: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = yamlDuration(parsed)
	return nil
}

// intPtrOrDefault returns the pointed-to value if non-nil, or the
// default if nil (field not specified in YAML). When the pointer is
// non-nil and the value is zero, returns -1 as a sentinel so that
// applyDefaults (which treats 0 as "not set") does not silently
// override the explicit zero. The -1 sentinel is caught by validation
// which rejects values < 1.
func intPtrOrDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	if *p == 0 {
		return -1 // sentinel: explicit zero from YAML → rejected by validation
	}
	return *p
}

func buildOutput(name string, rawConfig []byte, coreMetrics audit.Metrics, webhookMetrics Metrics) (audit.Output, error) {
	if len(rawConfig) == 0 {
		return nil, fmt.Errorf("audit: webhook output %q: config is required", name)
	}

	var yc yamlWebhookConfig
	dec := yaml.NewDecoder(bytes.NewReader(rawConfig), yaml.DisallowUnknownField())
	if err := dec.Decode(&yc); err != nil {
		return nil, fmt.Errorf("audit: webhook output %q: %w", name, err)
	}

	cfg := &Config{
		URL:                yc.URL,
		Headers:            yc.Headers,
		TLSCA:              yc.TLSCA,
		TLSCert:            yc.TLSCert,
		TLSKey:             yc.TLSKey,
		FlushInterval:      time.Duration(yc.FlushInterval),
		Timeout:            time.Duration(yc.Timeout),
		BatchSize:          intPtrOrDefault(yc.BatchSize, DefaultBatchSize),
		BufferSize:         intPtrOrDefault(yc.BufferSize, DefaultBufferSize),
		MaxRetries:         intPtrOrDefault(yc.MaxRetries, DefaultMaxRetries),
		AllowInsecureHTTP:  yc.AllowInsecureHTTP,
		AllowPrivateRanges: yc.AllowPrivateRanges,
	}
	if yc.TLSPolicy != nil {
		cfg.TLSPolicy = &audit.TLSPolicy{
			AllowTLS12:       yc.TLSPolicy.AllowTLS12,
			AllowWeakCiphers: yc.TLSPolicy.AllowWeakCiphers,
		}
	}

	out, err := New(cfg, coreMetrics, webhookMetrics)
	if err != nil {
		return nil, fmt.Errorf("audit: webhook output %q: %w", name, err)
	}
	return audit.WrapOutput(out, name), nil
}
