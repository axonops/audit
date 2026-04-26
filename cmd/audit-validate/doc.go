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

// Command audit-validate validates an outputs.yaml file against a
// taxonomy YAML — a pre-deploy CI gate for the github.com/axonops/audit
// library (#611).
//
// # Usage
//
//	audit-validate -taxonomy <file|-> -outputs <file|-> [flags]
//
//	-taxonomy <file>      Path to taxonomy YAML, or "-" for stdin.
//	-outputs <file>       Path to outputs YAML, or "-" for stdin.
//	-format text|json     Output format (default: text).
//	-quiet                Suppress all output; rely on exit code.
//	-resolve-secrets      Reserved. Default release builds reject this
//	                      flag because they have no secret providers
//	                      compiled in; offline ref+ pre-scanning is
//	                      always active.
//	-version              Print the audit-validate version and exit 0.
//
// # Exit codes
//
//	0  valid configuration
//	1  parse error (file not found, invalid YAML)
//	2  schema or usage error (missing required field, wrong type,
//	                          unknown field, missing/invalid CLI flag,
//	                          stdin double-use, -resolve-secrets in a
//	                          binary that does not support it)
//	3  semantic error (route references unknown taxonomy entries,
//	                   output type unknown, unresolved ref+ string)
//
// # Example: GitHub Actions pre-deploy gate
//
// Install the binary, then validate. See docs/validation.md for the
// complete workflow including caching:
//
//	go install github.com/axonops/audit/cmd/audit-validate@latest
//	audit-validate -taxonomy taxonomy.yaml -outputs outputs/prod.yaml
//
// # Example: stdin
//
//	cat taxonomy.yaml | audit-validate -taxonomy - -outputs prod.yaml
//
// audit-validate is a thin CLI wrapper around
// [github.com/axonops/audit/outputconfig.Load]; the validation logic
// is shared with the runtime path.
package main
