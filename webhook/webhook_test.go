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
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/webhook"
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
		cfg     webhook.Config
	}{
		{
			name:    "empty URL",
			cfg:     webhook.Config{},
			wantErr: "must not be empty",
		},
		{
			name: "HTTP without AllowInsecureHTTP",
			cfg: webhook.Config{
				URL: "http://example.com/webhook",
			},
			wantErr: "must be https",
		},
		{
			name: "HTTP with AllowInsecureHTTP",
			cfg: webhook.Config{
				URL:               "http://example.com/webhook",
				AllowInsecureHTTP: true,
			},
		},
		{
			name: "HTTPS valid",
			cfg: webhook.Config{
				URL: "https://example.com/webhook",
			},
		},
		{
			name: "invalid URL scheme",
			cfg: webhook.Config{
				URL: "ftp://example.com/data",
			},
			wantErr: "scheme must be http or https",
		},
		{
			name: "CRLF in header name",
			cfg: webhook.Config{
				URL:     "https://example.com/webhook",
				Headers: map[string]string{"Bad\r\nHeader": "value"},
			},
			wantErr: "invalid characters",
		},
		{
			name: "cert without key",
			cfg: webhook.Config{
				URL:     "https://example.com/webhook",
				TLSCert: "/tmp/cert.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: webhook.Config{
				URL:    "https://example.com/webhook",
				TLSKey: "/tmp/key.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "batch size exceeds max",
			cfg: webhook.Config{
				URL:       "https://example.com/webhook",
				BatchSize: webhook.MaxBatchSize + 1,
			},
			wantErr: "batch_size",
		},
		{
			name: "buffer size exceeds max",
			cfg: webhook.Config{
				URL:        "https://example.com/webhook",
				BufferSize: webhook.MaxBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
		{
			name: "max retries exceeds max",
			cfg: webhook.Config{
				URL:        "https://example.com/webhook",
				MaxRetries: webhook.MaxMaxRetries + 1,
			},
			wantErr: "max_retries",
		},
		{
			name: "negative flush interval",
			cfg: webhook.Config{
				URL:           "https://example.com/webhook",
				FlushInterval: -1 * time.Second,
			},
			wantErr: "flush_interval must not be negative",
		},
		{
			name: "negative timeout",
			cfg: webhook.Config{
				URL:     "https://example.com/webhook",
				Timeout: -1 * time.Second,
			},
			wantErr: "timeout must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := webhook.ValidateConfigForTest(&tt.cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.ErrorIs(t, err, audit.ErrConfigInvalid,
					"all webhook config validation errors must wrap audit.ErrConfigInvalid")
			}
		})
	}
}

func TestValidateConfig_Defaults(t *testing.T) {
	cfg := webhook.Config{URL: "https://example.com/webhook"}
	require.NoError(t, webhook.ValidateConfigForTest(&cfg))

	assert.Equal(t, webhook.DefaultBatchSize, cfg.BatchSize)
	assert.Equal(t, webhook.DefaultFlushInterval, cfg.FlushInterval)
	assert.Equal(t, webhook.DefaultTimeout, cfg.Timeout)
	assert.Equal(t, webhook.DefaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, webhook.DefaultBufferSize, cfg.BufferSize)
	assert.Equal(t, webhook.DefaultMaxBatchBytes, cfg.MaxBatchBytes)
}

func TestValidateConfig_BoundaryValues(t *testing.T) {
	cfg := webhook.Config{
		URL:           "https://example.com/webhook",
		BatchSize:     webhook.MaxBatchSize,
		BufferSize:    webhook.MaxBufferSize,
		MaxRetries:    webhook.MaxMaxRetries,
		MaxBatchBytes: webhook.MaxMaxBatchBytes,
	}
	require.NoError(t, webhook.ValidateConfigForTest(&cfg))
}

// TestValidateConfig_MaxBatchBytesDefaults verifies zero-value
// MaxBatchBytes is normalised to DefaultMaxBatchBytes (#687 AC #1).
func TestValidateConfig_MaxBatchBytesDefaults(t *testing.T) {
	cfg := webhook.Config{URL: "https://example.com/webhook"}
	require.NoError(t, webhook.ValidateConfigForTest(&cfg))
	assert.Equal(t, webhook.DefaultMaxBatchBytes, cfg.MaxBatchBytes,
		"zero MaxBatchBytes must normalise to DefaultMaxBatchBytes")
}

// TestValidateConfig_MaxBatchBytesNegative verifies a negative
// MaxBatchBytes value is rejected with ErrConfigInvalid (#687 AC #1).
func TestValidateConfig_MaxBatchBytesNegative(t *testing.T) {
	cfg := webhook.Config{
		URL:           "https://example.com/webhook",
		MaxBatchBytes: -1,
	}
	err := webhook.ValidateConfigForTest(&cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxBatchBytesBelowMin verifies a value below
// MinMaxBatchBytes is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxBatchBytesBelowMin(t *testing.T) {
	cfg := webhook.Config{
		URL:           "https://example.com/webhook",
		MaxBatchBytes: 512, // below 1 KiB minimum
	}
	err := webhook.ValidateConfigForTest(&cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxBatchBytesOverRange verifies a value above
// MaxMaxBatchBytes is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxBatchBytesOverRange(t *testing.T) {
	cfg := webhook.Config{
		URL:           "https://example.com/webhook",
		MaxBatchBytes: webhook.MaxMaxBatchBytes + 1,
	}
	err := webhook.ValidateConfigForTest(&cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestValidateConfig_NonexistentTLSFiles(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     webhook.Config
	}{
		{
			name: "nonexistent CA",
			cfg: webhook.Config{
				URL:   "https://example.com/webhook",
				TLSCA: "/nonexistent/ca.pem",
			},
			wantErr: "ca",
		},
		{
			name: "nonexistent cert and key",
			cfg: webhook.Config{
				URL:     "https://example.com/webhook",
				TLSCert: "/nonexistent/cert.pem",
				TLSKey:  "/nonexistent/key.pem",
			},
			wantErr: "cert",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := webhook.New(&tt.cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
