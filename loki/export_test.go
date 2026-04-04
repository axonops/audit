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

package loki

import (
	"testing"

	audit "github.com/axonops/go-audit"
)

// Exported aliases for internal functions needed by black-box tests.
var (
	ValidateLokiConfig = validateLokiConfig
	BuildLokiTLSConfig = buildLokiTLSConfig
)

// TestEvent is a test-only event for building payloads.
type TestEvent struct { //nolint:govet // fieldalignment: readability preferred
	Data []byte
	Meta audit.EventMetadata
}

// TestPayloadInput configures a test payload build.
type TestPayloadInput struct { //nolint:govet // fieldalignment: readability preferred
	Events           []TestEvent
	StaticLabels     map[string]string
	AppName          string
	Host             string
	PID              int
	Compress         bool
	ExcludeEventType bool
	ExcludeSeverity  bool
}

// buildTestConfig creates a Config from test input parameters.
func buildTestConfig(input TestPayloadInput) *Config { //nolint:gocritic // hugeParam: test helper
	cfg := &Config{
		URL:                "http://localhost:3100/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1000,
		FlushInterval:      10 * 1000000000, // 10s in nanoseconds
		Timeout:            5 * 1000000000,  // 5s in nanoseconds
		MaxRetries:         1,
		BufferSize:         1000,
		Compress:           input.Compress,
	}
	if input.StaticLabels != nil {
		cfg.Labels.Static = input.StaticLabels
	}
	if input.ExcludeEventType {
		cfg.Labels.Dynamic.ExcludeEventType = true
	}
	if input.ExcludeSeverity {
		cfg.Labels.Dynamic.ExcludeSeverity = true
	}
	return cfg
}

// buildTestOutput creates an Output from test input and returns it
// along with a batch of lokiEntry values.
func buildTestOutput(t *testing.T, input TestPayloadInput) (*Output, []lokiEntry) { //nolint:gocritic // hugeParam: test helper
	t.Helper()

	cfg := buildTestConfig(input)
	o, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	o.SetFrameworkFields(input.AppName, input.Host, input.PID)

	batch := make([]lokiEntry, len(input.Events))
	for i, e := range input.Events {
		batch[i] = lokiEntry{data: e.Data, metadata: e.Meta}
	}
	return o, batch
}

// BuildTestPayload constructs a Loki push payload from test inputs.
// It creates a temporary Output, sets framework fields, groups events,
// builds the payload, and returns the raw (uncompressed) JSON bytes.
func BuildTestPayload(t *testing.T, input TestPayloadInput) []byte { //nolint:gocritic // hugeParam: test helper, readability preferred
	t.Helper()

	o, batch := buildTestOutput(t, input)
	defer func() { _ = o.Close() }()

	o.groupByStream(batch)
	o.buildPayload()
	return append([]byte(nil), o.payloadBuf.Bytes()...)
}

// BuildTestCompressedPayload is like BuildTestPayload but returns
// gzip-compressed bytes.
func BuildTestCompressedPayload(t *testing.T, input TestPayloadInput) []byte { //nolint:gocritic // hugeParam: test helper, readability preferred
	t.Helper()

	o, batch := buildTestOutput(t, input)
	defer func() { _ = o.Close() }()

	o.groupByStream(batch)
	o.buildPayload()
	compressed := o.maybeCompress()
	return append([]byte(nil), compressed...)
}
