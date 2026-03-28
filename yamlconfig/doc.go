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

// Package yamlconfig provides YAML-based taxonomy definition for the
// [github.com/axonops/go-audit] library. It converts a YAML document
// into an [audit.Taxonomy] value ready for use with [audit.WithTaxonomy].
//
// # Usage
//
// Embed a YAML taxonomy file and parse it at startup:
//
//	import (
//	    _ "embed"
//	    "github.com/axonops/go-audit"
//	    "github.com/axonops/go-audit/yamlconfig"
//	)
//
//	//go:embed taxonomy.yaml
//	var taxonomyYAML []byte
//
//	func main() {
//	    tax, err := yamlconfig.ParseTaxonomyYAML(taxonomyYAML)
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
// The YAML document MUST contain a single document with the following
// top-level keys. Unknown keys are rejected.
//
//	version: 1                     # REQUIRED. Schema version (currently only 1).
//	categories:                    # REQUIRED. Map of category name → event type names.
//	  write:
//	    - schema_register
//	    - schema_delete
//	  security:
//	    - auth_failure
//	default_enabled:               # OPTIONAL. Categories enabled at startup.
//	  - write
//	  - security
//	events:                        # REQUIRED. Map of event type name → definition.
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
// [ParseTaxonomyYAML] performs the same validation as [audit.WithTaxonomy]:
// lifecycle events are injected automatically, then the full taxonomy is
// validated. All validation errors wrap [audit.ErrTaxonomyInvalid].
//
// # Dependency Isolation
//
// This package is a separate Go module so that the core audit package
// remains free of YAML dependencies. Import only if you need YAML-based
// taxonomy definition.
package yamlconfig
