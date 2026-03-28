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

// Package taxonomy loads a YAML taxonomy definition and converts it
// into an [audit.Taxonomy] ready to pass to [audit.WithTaxonomy].
// Use this package when you want to define your audit taxonomy in a
// YAML file (or embedded asset) rather than constructing
// [audit.Taxonomy] in Go code.
//
// # Usage
//
// Embed a YAML taxonomy file and parse it at startup:
//
//	import (
//	    _ "embed"
//	    "log"
//	    "github.com/axonops/go-audit"
//	    "github.com/axonops/go-audit/taxonomy"
//	)
//
//	//go:embed taxonomy.yaml
//	var taxonomyYAML []byte
//
//	func main() {
//	    tax, err := taxonomy.ParseYAML(taxonomyYAML)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    logger, err := audit.NewLogger(
//	        audit.Config{Version: 1, Enabled: true},
//	        audit.WithTaxonomy(tax),
//	    )
//	    // ...
//	}
//
// # YAML Schema
//
// The YAML document MUST be a single document with the following
// top-level keys. Unknown keys at any level are rejected.
//
//	version: 1                     # REQUIRED. Schema version (currently only 1).
//	categories:                    # OPTIONAL. Map of category name → event type names.
//	                               # If omitted, only lifecycle events are available.
//	  write:
//	    - schema_register
//	    - schema_delete
//	  security:
//	    - auth_failure
//	default_enabled:               # OPTIONAL. Categories enabled at startup.
//	  - write
//	  - security
//	events:                        # OPTIONAL when categories is omitted; REQUIRED when
//	                               # categories lists event type names.
//	  schema_register:
//	    category: write            # REQUIRED. Must match a key in categories.
//	    required:                  # OPTIONAL. Fields that must be present.
//	      - outcome
//	      - actor_id
//	    optional:                  # OPTIONAL. Fields that may be present.
//	      - schema_type
//
// # Validation
//
// [ParseYAML] validates input in two stages.
//
// Structural errors (empty input, input exceeding [MaxInputSize],
// unknown YAML keys, YAML syntax errors, multi-document input) return
// an error wrapping [ErrInvalidInput]:
//
//	if errors.Is(err, taxonomy.ErrInvalidInput) { /* bad YAML */ }
//
// Semantic errors (invalid taxonomy version, unknown categories,
// duplicate event assignments) return an error wrapping
// [audit.ErrTaxonomyInvalid]:
//
//	if errors.Is(err, audit.ErrTaxonomyInvalid) { /* bad taxonomy */ }
//
// # Dependency Isolation
//
// This package is a separate Go module
// (github.com/axonops/go-audit/taxonomy) so that the core audit
// package remains free of YAML dependencies. Import it only if
// YAML-based taxonomy definition is required.
//
// Because it is a separate module, it is versioned independently of
// github.com/axonops/go-audit. When upgrading the core module, verify
// whether taxonomy requires a corresponding update:
//
//	go get github.com/axonops/go-audit/taxonomy@latest
package taxonomy
