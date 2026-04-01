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
	"fmt"
	"time"

	"github.com/axonops/go-audit/webhook"
)

func ExampleConfig_basic() {
	// HTTPS webhook — the minimum production configuration.
	cfg := &webhook.Config{
		URL:       "https://ingest.example.com/audit",
		BatchSize: 50,
		Timeout:   15 * time.Second,
	}
	fmt.Printf("url=%s batch=%d timeout=%s\n", cfg.URL, cfg.BatchSize, cfg.Timeout)
	// Output: url=https://ingest.example.com/audit batch=50 timeout=15s
}

func ExampleConfig_tls() {
	// Webhook with mTLS client certificate and bearer token.
	// Header values are plain strings — use os.Getenv for secrets.
	cfg := &webhook.Config{
		URL:     "https://ingest.example.com/audit",
		TLSCert: "/etc/audit/client-cert.pem",
		TLSKey:  "/etc/audit/client-key.pem",
		TLSCA:   "/etc/audit/ca.pem",
		Headers: map[string]string{
			"Authorization": "Bearer my-token",
		},
	}
	fmt.Printf("url=%s cert=%s key=%s ca=%s headers=%d\n",
		cfg.URL, cfg.TLSCert, cfg.TLSKey, cfg.TLSCA, len(cfg.Headers))
	// Output: url=https://ingest.example.com/audit cert=/etc/audit/client-cert.pem key=/etc/audit/client-key.pem ca=/etc/audit/ca.pem headers=1
}

func ExampleConfig_retry() {
	// Webhook with custom retry and flush settings.
	cfg := &webhook.Config{
		URL:           "https://ingest.example.com/audit",
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		MaxRetries:    5,
		Timeout:       30 * time.Second,
	}
	fmt.Printf("url=%s batch=%d flush=%s retries=%d timeout=%s\n",
		cfg.URL, cfg.BatchSize, cfg.FlushInterval, cfg.MaxRetries, cfg.Timeout)
	// Output: url=https://ingest.example.com/audit batch=100 flush=10s retries=5 timeout=30s
}
