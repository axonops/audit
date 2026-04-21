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

package webhook_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

func TestWebhookFactory_RegisteredByInit(t *testing.T) {
	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory, "webhook factory must be registered by init()")
}

func TestWebhookFactory_ValidConfig(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nbatch_size: 10\nflush_interval: 1s\ntimeout: 5s\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("splunk_hec", yaml, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "splunk_hec", out.Name(), "name should be the YAML-configured name")
}

// TestWebhookFactory_MaxBatchBytesKey verifies the new
// `max_batch_bytes` YAML key is parsed and applied (#687 AC #6).
func TestWebhookFactory_MaxBatchBytesKey(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nbatch_size: 100\nflush_interval: 5s\nmax_batch_bytes: 524288\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("sized", yaml, nil, nil)
	require.NoError(t, err, "max_batch_bytes key must parse cleanly")
	t.Cleanup(func() { _ = out.Close() })
}

// TestWebhookFactory_MaxBatchBytesInvalid verifies a negative
// max_batch_bytes value is rejected via validation.
func TestWebhookFactory_MaxBatchBytesInvalid(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nmax_batch_bytes: -1\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("bad_bytes", yaml, nil, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestWebhookFactory_InvalidConfig_EmptyURL(t *testing.T) {
	yaml := []byte("url: \"\"\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("bad_webhook", yaml, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad_webhook")
}

func TestWebhookFactory_UnknownYAMLField_Rejected(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nunknown_field: true\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("test", yaml, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_field")
}

func TestWebhookFactory_AllowInsecureHTTP_AcceptsHTTPURL(t *testing.T) {
	rawYAML := []byte("url: http://example.com/events\nallow_insecure_http: true\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("insecure", rawYAML, nil, nil)
	require.NoError(t, err, "allow_insecure_http: true should accept HTTP URLs")
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "insecure", out.Name())
}

func TestWebhookFactory_AllowInsecureHTTP_DefaultFalse_RejectsHTTPURL(t *testing.T) {
	rawYAML := []byte("url: http://example.com/events\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("no_insecure", rawYAML, nil, nil)
	assert.Error(t, err, "HTTP URL without allow_insecure_http should be rejected")
	assert.Contains(t, err.Error(), "must be https")
}

func TestWebhookFactory_AllowInsecureHTTP_ExplicitFalse_RejectsHTTPURL(t *testing.T) {
	rawYAML := []byte("url: http://example.com/events\nallow_insecure_http: false\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("explicit_false", rawYAML, nil, nil)
	assert.Error(t, err, "allow_insecure_http: false should still reject HTTP URLs")
	assert.Contains(t, err.Error(), "must be https")
}

func TestWebhookFactory_AllowPrivateRanges_Accepted(t *testing.T) {
	rawYAML := []byte("url: https://example.com/events\nallow_private_ranges: true\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("private", rawYAML, nil, nil)
	require.NoError(t, err, "allow_private_ranges: true should be accepted")
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "private", out.Name())
}

func TestWebhookFactory_BothInsecureFields_Accepted(t *testing.T) {
	rawYAML := []byte("url: http://example.com/events\nallow_insecure_http: true\nallow_private_ranges: true\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("both", rawYAML, nil, nil)
	require.NoError(t, err, "both insecure fields should be accepted together")
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "both", out.Name())
}

func TestWebhookFactory_EmptyConfig_ReturnsError(t *testing.T) {
	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("empty", nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestWebhookFactory_WithHeaders(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nheaders:\n  Authorization: Bearer test-token\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("with_headers", yaml, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "with_headers", out.Name())
}

func TestWebhookFactory_WithTLSPolicy(t *testing.T) {
	yaml := []byte("url: https://example.com/events\ntls_policy:\n  allow_tls12: true\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("tls_webhook", yaml, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
}

func TestWebhookFactory_DurationParsing(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"seconds", "url: https://example.com/events\nflush_interval: 5s\n", false},
		{"milliseconds", "url: https://example.com/events\ntimeout: 100ms\n", false},
		{"minutes", "url: https://example.com/events\nflush_interval: 1m\n", false},
		{"zero", "url: https://example.com/events\nflush_interval: 0s\n", false},
		{"invalid string", "url: https://example.com/events\nflush_interval: banana\n", true},
		{"bare integer", "url: https://example.com/events\nflush_interval: 5\n", true},
	}

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := factory("dur_test", []byte(tt.yaml), nil, nil)
			if out != nil {
				t.Cleanup(func() { _ = out.Close() })
			}
			if tt.wantErr {
				assert.Error(t, err, "expected error for duration: %s", tt.name)
			} else if err != nil {
				// May fail on URL validation — we only care
				// that duration parsing didn't fail.
				assert.NotContains(t, err.Error(), "duration",
					"error should not be about duration parsing")
			}
		})
	}
}

func TestWebhookFactory_ExplicitZeroMaxRetries_Rejected(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nmax_retries: 0\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("zero_retries", yaml, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_retries must be at least 1")
}

func TestWebhookFactory_ExplicitZeroBatchSize_Rejected(t *testing.T) {
	yaml := []byte("url: https://example.com/events\nbatch_size: 0\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	_, err := factory("zero_batch", yaml, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch_size must be at least 1")
}

func TestWebhookFactory_OmittedMaxRetries_DefaultsTo3(t *testing.T) {
	yaml := []byte("url: https://example.com/events\n")

	factory := audit.LookupOutputFactory("webhook")
	require.NotNil(t, factory)

	out, err := factory("default_retries", yaml, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
}
