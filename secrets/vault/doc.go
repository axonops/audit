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

// Package vault provides a [secrets.Provider] that resolves secret
// references from a HashiCorp Vault KV v2 secret engine.
//
// The provider uses a thin HTTP client (no SDK dependency) and
// supports HTTPS-only connections with SSRF protection, custom CA
// certificates, and mTLS client authentication.
//
// # Usage
//
//	provider, err := vault.New(&vault.Config{
//	    Address: os.Getenv("VAULT_ADDR"),
//	    Token:   os.Getenv("VAULT_TOKEN"),
//	})
//	if err != nil {
//	    return err
//	}
//	defer provider.Close()
//
//	result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
//	    outputconfig.WithSecretProvider(provider),
//	)
//
// # KV v2 Path Convention
//
// Secret references use the raw API path, not the CLI logical path.
// The CLI command "vault kv get secret/audit/hmac" maps to the API
// path "secret/data/audit/hmac". Ref URIs use the API path:
//
//	ref+vault://secret/data/audit/hmac#salt
package vault
