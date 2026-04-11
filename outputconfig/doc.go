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

// Package outputconfig loads audit output configuration from a YAML
// document and returns ready-to-use [audit.Option] values for
// [audit.NewLogger].
//
// # Registry Pattern
//
// Output modules register factories via [audit.RegisterOutputFactory]
// in their init() functions. This package constructs outputs from YAML
// type strings without importing the output modules directly. The
// consumer controls which output types are available via blank imports:
//
//	import (
//	    "github.com/axonops/go-audit/outputconfig"
//	    _ "github.com/axonops/go-audit/file"
//	    _ "github.com/axonops/go-audit/syslog"
//	    _ "github.com/axonops/go-audit/webhook"
//	)
//
// If an output type's module is not blank-imported, [Load] returns an
// error for that output — no output is silently dropped.
//
// # YAML Schema
//
// The configuration document has the following top-level keys:
//
//	version: 1                      # required, must be 1
//	app_name: "my-service"          # required, application name (max 255 bytes)
//	host: "${HOSTNAME:-localhost}"   # required, hostname (max 255 bytes; env vars supported)
//	timezone: "UTC"                 # optional, overrides auto-detected timezone
//	logger:                         # optional, core logger settings
//	  enabled: true                 # default: true
//	  buffer_size: 10000            # default: 10,000 (max: 1,000,000)
//	  drain_timeout: "5s"           # default: "5s" (max: "60s")
//	  validation_mode: strict       # "strict" (default), "warn", "permissive"
//	  omit_empty: false             # default: false
//	tls_policy:                     # optional, global TLS policy
//	  allow_tls12: false            # default: false (TLS 1.3 only)
//	  allow_weak_ciphers: false     # default: false
//	outputs:                        # required, map of named outputs
//	  audit_log:
//	    type: file                  # registered output type
//	    enabled: true               # optional, default true
//	    file:                       # output-specific config block
//	      path: /var/log/audit.log
//	      max_size_mb: 100
//	    formatter:                  # optional per-output formatter
//	      type: cef
//	      vendor: MyCompany
//	      product: MyApp
//	    route:                      # optional per-output event filter
//	      include_categories: [security]
//	    exclude_labels: [pii]       # optional sensitivity label filter
//	    hmac:                       # optional per-output HMAC integrity
//	      enabled: true
//	      salt:
//	        version: "v1"
//	        value: "${HMAC_SALT}"
//	      hash: HMAC-SHA-256
//
// # Environment Variables
//
// Values support ${VAR} and ${VAR:-default} substitution. Expansion
// happens after YAML parsing for injection safety — the raw YAML
// structure is validated first, then string values are expanded.
//
// # Secret References
//
// String values in the YAML configuration can contain ref+SCHEME://PATH#KEY
// URIs that are resolved from external secret backends (OpenBao, Vault)
// at load time. Register providers with [WithSecretProvider]:
//
//	result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics,
//	    outputconfig.WithSecretProvider(provider),
//	    outputconfig.WithSecretTimeout(30*time.Second),
//	)
//
// [WithSecretTimeout] controls the overall timeout for all secret
// resolution network I/O. Default: [DefaultSecretTimeout] (10s).
// The caller's context deadline takes precedence when earlier.
//
// # Usage
//
//	result, err := outputconfig.Load(ctx, yamlData, &taxonomy, metrics)
//	if err != nil {
//	    return fmt.Errorf("audit config: %w", err)
//	}
//
//	opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
//	opts = append(opts, result.Options...)
//	logger, err := audit.NewLogger(opts...)
//
// [Load] fails hard on any configuration error — partial configurations
// are never returned. This ensures that a misconfigured output does not
// silently drop audit events.
package outputconfig
