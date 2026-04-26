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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets"
)

// validationResult captures the outcome of one validate run.
type validationResult struct {
	code     string // "parse" | "schema" | "semantic" | "" (valid)
	message  string // human-readable summary
	exitCode int
}

// errResolveSecretsNotSupported is returned when a caller passes
// `-resolve-secrets` but the validator binary has no provider
// blank-imports compiled in. The default release binary cannot
// safely resolve `ref+` strings, so accepting the flag silently
// would let invalid configs pass an offline CI gate.
var errResolveSecretsNotSupported = errors.New(
	"-resolve-secrets is not supported by this build of audit-validate; " +
		"the default binary has no secret providers compiled in - " +
		"build a custom validator that blank-imports your providers, " +
		"or remove the flag to validate the configuration offline " +
		"(ref+ references will be flagged as semantic errors)")

// validate runs the audit-config pipeline:
//  1. Parse taxonomy YAML (errors → exit 1).
//  2. If resolveSecrets is false, pre-scan the outputs YAML bytes
//     for `ref+SCHEME://` sentinels and reject as a semantic error.
//     The pre-scan is necessary because outputconfig.Load's safety
//     net only fires when a resolver is registered; without it, an
//     unresolved ref+ string would pass through as a literal value.
//  3. Load outputs YAML against taxonomy (errors classified into 1 / 2 / 3).
func validate(taxonomyData, outputsData []byte, resolveSecrets bool) validationResult {
	if resolveSecrets {
		return validationResult{
			exitCode: exitSchema,
			code:     "schema",
			message:  errResolveSecretsNotSupported.Error(),
		}
	}

	tax, err := audit.ParseTaxonomyYAML(taxonomyData)
	if err != nil {
		return validationResult{
			exitCode: exitParse,
			code:     "parse",
			message:  fmt.Sprintf("taxonomy: %v", err),
		}
	}

	if secrets.ContainsRef(string(outputsData)) {
		return validationResult{
			exitCode: exitSemantic,
			code:     "semantic",
			message:  "outputs YAML contains a `ref+SCHEME://` secret reference; the default audit-validate binary cannot resolve secrets offline. Remove the reference for offline validation, or build a custom validator with the appropriate secret-provider sub-modules blank-imported.",
		}
	}

	_, err = outputconfig.Load(context.Background(), outputsData, tax)
	if err != nil {
		return classifyOutputconfigError(err)
	}

	return validationResult{exitCode: exitValid, code: "", message: "configuration is valid"}
}

// classifyOutputconfigError maps a Load error onto schema (exit 2)
// vs semantic (exit 3) vs parse (exit 1).
//
// outputconfig.Load wraps every config-time error in
// [outputconfig.ErrOutputConfigInvalid] (which itself wraps
// [audit.ErrConfigInvalid]). Sub-classification uses error-message
// inspection where granular sentinels are not yet available. The
// `errors.Is` checks against [secrets.ErrUnresolvedRef] /
// [secrets.ErrProviderNotRegistered] are exact; the remaining
// substring checks track the wording used by audit core today.
// Replacing them with proper sentinels in audit core is tracked as
// a follow-up item — file an issue if the substring drift bites a
// downstream consumer.
func classifyOutputconfigError(err error) validationResult {
	if errors.Is(err, secrets.ErrUnresolvedRef) ||
		errors.Is(err, secrets.ErrProviderNotRegistered) {
		return validationResult{exitCode: exitSemantic, code: "semantic", message: err.Error()}
	}

	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case errors.Is(err, audit.ErrConfigInvalid) && yamlParseError(low):
		return validationResult{exitCode: exitParse, code: "parse", message: msg}
	case strings.Contains(low, "references unknown taxonomy entries"),
		strings.Contains(low, "category") && strings.Contains(low, "not found"),
		strings.Contains(low, "unknown event type"),
		strings.Contains(low, "unknown output type"),
		strings.Contains(low, "no provider"),
		strings.Contains(low, "ref+"):
		return validationResult{exitCode: exitSemantic, code: "semantic", message: msg}
	default:
		return validationResult{exitCode: exitSchema, code: "schema", message: msg}
	}
}

// yamlParseError reports whether a lowercased error message looks
// like a YAML parse failure rather than a schema/semantic problem.
func yamlParseError(low string) bool {
	return strings.Contains(low, "yaml:") ||
		strings.Contains(low, "unmarshal") ||
		strings.Contains(low, "syntax")
}

// writeText emits the human-readable result to stdout (success) or
// stderr (failure).
func writeText(stdout, stderr io.Writer, res validationResult) {
	if res.exitCode == exitValid {
		_, _ = fmt.Fprintln(stdout, "audit-validate: configuration is valid")
		return
	}
	_, _ = fmt.Fprintf(stderr, "audit-validate: %s error: %s\n", res.code, res.message)
}

// jsonReport is the wire format emitted with -format=json.
type jsonReport struct {
	Errors []jsonError `json:"errors"`
	Valid  bool        `json:"valid"`
}

type jsonError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w io.Writer, res validationResult) {
	rep := jsonReport{Valid: res.exitCode == exitValid}
	if !rep.Valid {
		rep.Errors = []jsonError{{Code: res.code, Message: res.message}}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}
