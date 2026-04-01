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
// The configuration document has three top-level keys:
//
//	version: 1                      # required, must be 1
//	default_formatter:              # optional, applies to all outputs
//	  type: json                    # "json" or "cef"
//	  timestamp: rfc3339nano        # "rfc3339nano" or "unix_millis"
//	outputs:                        # required, map of named outputs
//	  audit_log:
//	    type: file                  # registered output type
//	    enabled: true               # optional, default true
//	    file:                       # output-specific config block
//	      path: /var/log/audit.log
//	      max_size_mb: 100
//	    formatter:                  # optional per-output override
//	      type: cef
//	      vendor: MyCompany
//	      product: MyApp
//	    route:                      # optional per-output event filter
//	      include_categories: [security]
//	    exclude_labels: [pii]       # optional sensitivity label filter
//
// # Environment Variables
//
// Values support ${VAR} and ${VAR:-default} substitution. Expansion
// happens after YAML parsing for injection safety — the raw YAML
// structure is validated first, then string values are expanded.
//
// # Usage
//
//	result, err := outputconfig.Load(yamlData, &taxonomy, metrics)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	logger, err := audit.NewLogger(
//	    audit.Config{Version: 1, Enabled: true},
//	    audit.WithTaxonomy(taxonomy),
//	    result.Options...,
//	)
//
// [Load] fails hard on any configuration error — partial configurations
// are never returned. This ensures that a misconfigured output does not
// silently drop audit events.
package outputconfig
