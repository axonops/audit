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

package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Config validation (Commit 2)
// ---------------------------------------------------------------------------

func TestValidateWebhookConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     WebhookConfig
		wantErr string
	}{
		{
			name:    "empty URL",
			cfg:     WebhookConfig{},
			wantErr: "must not be empty",
		},
		{
			name: "HTTP without AllowInsecureHTTP",
			cfg: WebhookConfig{
				URL: "http://example.com/webhook",
			},
			wantErr: "must be https",
		},
		{
			name: "HTTP with AllowInsecureHTTP",
			cfg: WebhookConfig{
				URL:               "http://example.com/webhook",
				AllowInsecureHTTP: true,
			},
		},
		{
			name: "HTTPS valid",
			cfg: WebhookConfig{
				URL: "https://example.com/webhook",
			},
		},
		{
			name: "invalid URL scheme",
			cfg: WebhookConfig{
				URL: "ftp://example.com/data",
			},
			wantErr: "scheme must be http or https",
		},
		{
			name: "CRLF in header name",
			cfg: WebhookConfig{
				URL:     "https://example.com/webhook",
				Headers: map[string]string{"Bad\r\nHeader": "value"},
			},
			wantErr: "invalid characters",
		},
		{
			name: "cert without key",
			cfg: WebhookConfig{
				URL:     "https://example.com/webhook",
				TLSCert: "/tmp/cert.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: WebhookConfig{
				URL:    "https://example.com/webhook",
				TLSKey: "/tmp/key.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "batch size exceeds max",
			cfg: WebhookConfig{
				URL:       "https://example.com/webhook",
				BatchSize: MaxWebhookBatchSize + 1,
			},
			wantErr: "batch_size",
		},
		{
			name: "buffer size exceeds max",
			cfg: WebhookConfig{
				URL:        "https://example.com/webhook",
				BufferSize: MaxWebhookBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
		{
			name: "max retries exceeds max",
			cfg: WebhookConfig{
				URL:        "https://example.com/webhook",
				MaxRetries: MaxWebhookMaxRetries + 1,
			},
			wantErr: "max_retries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookConfig(&tt.cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateWebhookConfig_Defaults(t *testing.T) {
	cfg := WebhookConfig{URL: "https://example.com/webhook"}
	require.NoError(t, validateWebhookConfig(&cfg))

	assert.Equal(t, DefaultWebhookBatchSize, cfg.BatchSize)
	assert.Equal(t, DefaultWebhookFlushInterval, cfg.FlushInterval)
	assert.Equal(t, DefaultWebhookTimeout, cfg.Timeout)
	assert.Equal(t, DefaultWebhookMaxRetries, cfg.MaxRetries)
	assert.Equal(t, DefaultWebhookBufferSize, cfg.BufferSize)
}

func TestValidateWebhookConfig_BoundaryValues(t *testing.T) {
	cfg := WebhookConfig{
		URL:        "https://example.com/webhook",
		BatchSize:  MaxWebhookBatchSize,
		BufferSize: MaxWebhookBufferSize,
		MaxRetries: MaxWebhookMaxRetries,
	}
	require.NoError(t, validateWebhookConfig(&cfg))
}
