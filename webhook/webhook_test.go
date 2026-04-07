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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Config validation (Commit 2)
// ---------------------------------------------------------------------------

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     Config
	}{
		{
			name:    "empty URL",
			cfg:     Config{},
			wantErr: "must not be empty",
		},
		{
			name: "HTTP without AllowInsecureHTTP",
			cfg: Config{
				URL: "http://example.com/webhook",
			},
			wantErr: "must be https",
		},
		{
			name: "HTTP with AllowInsecureHTTP",
			cfg: Config{
				URL:               "http://example.com/webhook",
				AllowInsecureHTTP: true,
			},
		},
		{
			name: "HTTPS valid",
			cfg: Config{
				URL: "https://example.com/webhook",
			},
		},
		{
			name: "invalid URL scheme",
			cfg: Config{
				URL: "ftp://example.com/data",
			},
			wantErr: "scheme must be http or https",
		},
		{
			name: "CRLF in header name",
			cfg: Config{
				URL:     "https://example.com/webhook",
				Headers: map[string]string{"Bad\r\nHeader": "value"},
			},
			wantErr: "invalid characters",
		},
		{
			name: "cert without key",
			cfg: Config{
				URL:     "https://example.com/webhook",
				TLSCert: "/tmp/cert.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: Config{
				URL:    "https://example.com/webhook",
				TLSKey: "/tmp/key.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "batch size exceeds max",
			cfg: Config{
				URL:       "https://example.com/webhook",
				BatchSize: MaxBatchSize + 1,
			},
			wantErr: "batch_size",
		},
		{
			name: "buffer size exceeds max",
			cfg: Config{
				URL:        "https://example.com/webhook",
				BufferSize: MaxBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
		{
			name: "max retries exceeds max",
			cfg: Config{
				URL:        "https://example.com/webhook",
				MaxRetries: MaxMaxRetries + 1,
			},
			wantErr: "max_retries",
		},
		{
			name: "negative flush interval",
			cfg: Config{
				URL:           "https://example.com/webhook",
				FlushInterval: -1 * time.Second,
			},
			wantErr: "flush_interval must not be negative",
		},
		{
			name: "negative timeout",
			cfg: Config{
				URL:     "https://example.com/webhook",
				Timeout: -1 * time.Second,
			},
			wantErr: "timeout must not be negative",
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

func TestValidateConfig_Defaults(t *testing.T) {
	cfg := Config{URL: "https://example.com/webhook"}
	require.NoError(t, validateWebhookConfig(&cfg))

	assert.Equal(t, DefaultBatchSize, cfg.BatchSize)
	assert.Equal(t, DefaultFlushInterval, cfg.FlushInterval)
	assert.Equal(t, DefaultTimeout, cfg.Timeout)
	assert.Equal(t, DefaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, DefaultBufferSize, cfg.BufferSize)
}

func TestValidateConfig_BoundaryValues(t *testing.T) {
	cfg := Config{
		URL:        "https://example.com/webhook",
		BatchSize:  MaxBatchSize,
		BufferSize: MaxBufferSize,
		MaxRetries: MaxMaxRetries,
	}
	require.NoError(t, validateWebhookConfig(&cfg))
}

func TestValidateConfig_NonexistentTLSFiles(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     Config
	}{
		{
			name: "nonexistent CA",
			cfg: Config{
				URL:   "https://example.com/webhook",
				TLSCA: "/nonexistent/ca.pem",
			},
			wantErr: "ca",
		},
		{
			name: "nonexistent cert and key",
			cfg: Config{
				URL:     "https://example.com/webhook",
				TLSCert: "/nonexistent/cert.pem",
				TLSKey:  "/nonexistent/key.pem",
			},
			wantErr: "cert",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&tt.cfg, nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
