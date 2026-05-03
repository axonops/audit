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

//go:build integration

package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/axonops/audit/tests/bdd/steps/genfixture"
)

// registerSchemaArtifactsSteps wires step definitions for the
// schema_artifacts.feature scenarios (#548). The scenarios verify
// that the JSON Schema emitted by audit-gen accurately describes the
// JSON shape produced by audit.JSONFormatter for the same taxonomy.
//
// Each scenario writes the fixture taxonomy to a temp file, invokes
// `go run ./cmd/audit-gen -format json-schema` to produce the schema
// (audit-gen lives in a separate Go module pinned to the published
// version of the audit library, so we cannot import its internals
// from the BDD package — we shell out instead), then compiles the
// schema with santhosh-tekuri/jsonschema/v5 and validates a
// representative event payload.
func registerSchemaArtifactsSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a JSON Schema generated from the fixture taxonomy$`, func() error {
		schema, err := compileFixtureSchema()
		if err != nil {
			return err
		}
		tc.GeneratedSchema = schema
		return nil
	})

	ctx.Step(`^I validate a user_create event with all required fields against the schema$`, func() error {
		tc.LastSchemaErr = validateAgainstSchema(tc, validUserCreateEvent())
		return nil
	})

	ctx.Step(`^I validate a user_create event missing the actor_id field against the schema$`, func() error {
		ev := validUserCreateEvent()
		delete(ev, "actor_id")
		tc.LastSchemaErr = validateAgainstSchema(tc, ev)
		return nil
	})

	ctx.Step(`^I validate a user_create event with extra unknown field "([^"]*)" against the schema$`, func(field string) error {
		ev := validUserCreateEvent()
		ev[field] = "anything"
		tc.LastSchemaErr = validateAgainstSchema(tc, ev)
		return nil
	})

	ctx.Step(`^I validate an event with event_type "([^"]*)" against the schema$`, func(et string) error {
		ev := validUserCreateEvent()
		ev["event_type"] = et
		tc.LastSchemaErr = validateAgainstSchema(tc, ev)
		return nil
	})

	ctx.Step(`^the schema validates the event$`, func() error {
		if tc.LastSchemaErr != nil {
			return fmt.Errorf("schema rejected event: %w", tc.LastSchemaErr)
		}
		return nil
	})

	ctx.Step(`^the schema rejects the event with a missing-required-property error$`, func() error {
		if tc.LastSchemaErr == nil {
			return fmt.Errorf("schema accepted event with missing required property")
		}
		msg := tc.LastSchemaErr.Error()
		if !strings.Contains(msg, "missing properties") && !strings.Contains(msg, "required") {
			return fmt.Errorf("expected missing-property error, got: %s", msg)
		}
		return nil
	})

	ctx.Step(`^the schema rejects the event with an additional-property error$`, func() error {
		if tc.LastSchemaErr == nil {
			return fmt.Errorf("schema accepted event with extra property")
		}
		msg := tc.LastSchemaErr.Error()
		// santhosh-tekuri/jsonschema reports the rejection under
		// either keyword name depending on which strict-mode keyword
		// is in use. The library's schema currently uses
		// unevaluatedProperties at the schema root (#548).
		if !strings.Contains(msg, "additionalProperties") && !strings.Contains(msg, "unevaluatedProperties") {
			return fmt.Errorf("expected additional-property error, got: %s", msg)
		}
		return nil
	})

	ctx.Step(`^the schema rejects the event with a oneOf-mismatch error$`, func() error {
		if tc.LastSchemaErr == nil {
			return fmt.Errorf("schema accepted event with unknown event_type")
		}
		msg := tc.LastSchemaErr.Error()
		if !strings.Contains(msg, "oneOf") && !strings.Contains(msg, "valid against") {
			return fmt.Errorf("expected oneOf-mismatch error, got: %s", msg)
		}
		return nil
	})
}

// compileFixtureSchema runs `go run ./cmd/audit-gen -format
// json-schema` against the embedded fixture taxonomy and compiles the
// emitted schema with santhosh-tekuri/jsonschema/v5 ready for
// validation.
func compileFixtureSchema() (*jsonschema.Schema, error) {
	dir, err := os.MkdirTemp("", "bdd-schema-*")
	if err != nil {
		return nil, fmt.Errorf("mkdir temp: %w", err)
	}
	taxPath := filepath.Join(dir, "taxonomy.yaml")
	if err := os.WriteFile(taxPath, genfixture.TaxonomyYAML(), 0o600); err != nil {
		return nil, fmt.Errorf("write fixture taxonomy: %w", err)
	}
	schemaPath := filepath.Join(dir, "schema.json")
	cmd := exec.CommandContext(context.Background(), //nolint:gosec // hard-coded args, no user input
		"go", "run", "./cmd/audit-gen",
		"-format", "json-schema",
		"-input", taxPath,
		"-output", schemaPath)
	cmd.Dir = repoRootForBDD()
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return nil, fmt.Errorf("audit-gen failed: %w (output: %s)", runErr, string(out))
	}
	return compileSchemaFile(schemaPath)
}

// compileSchemaFile compiles the JSON Schema at path into a runnable
// validator. The file is loaded as raw bytes and added to the
// compiler under a stable URL so error messages include a useful
// schema $id.
func compileSchemaFile(path string) (*jsonschema.Schema, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path is locally generated under os.MkdirTemp
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaURL = "audit-event.schema.json"
	if err := compiler.AddResource(schemaURL, strings.NewReader(string(raw))); err != nil {
		return nil, fmt.Errorf("compiler.AddResource: %w", err)
	}
	schema, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return schema, nil
}

// repoRootForBDD walks up from the BDD test package to the repo root
// (where ./cmd/audit-gen is rooted). We do not rely on a working
// directory inherited from `go test` because godog scenarios may
// run from arbitrary subdirectories.
func repoRootForBDD() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "cmd", "audit-gen", "main.go")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return wd
}

// validateAgainstSchema marshals the event map to JSON, decodes back
// to a generic value (the form jsonschema/v5 expects), then runs
// schema validation. Returns the validation error or nil on success.
func validateAgainstSchema(tc *AuditTestContext, event map[string]any) error {
	if tc.GeneratedSchema == nil {
		return fmt.Errorf("no generated schema in scenario context")
	}
	schema, ok := tc.GeneratedSchema.(*jsonschema.Schema)
	if !ok {
		return fmt.Errorf("GeneratedSchema is %T, want *jsonschema.Schema", tc.GeneratedSchema)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("unmarshal event: %w", err)
	}
	return schema.Validate(v) //nolint:wrapcheck // returning the validator error verbatim is the contract
}

// validUserCreateEvent returns a representative user_create event
// matching the fixture taxonomy's required + optional fields.
func validUserCreateEvent() map[string]any {
	return map[string]any{
		"timestamp":      "2026-05-03T08:00:00Z",
		"event_type":     "user_create",
		"severity":       3,
		"event_category": "write",
		"app_name":       "bdd-audit",
		"host":           "bdd-host",
		"timezone":       "UTC",
		"pid":            1234,
		"outcome":        "success",
		"actor_id":       "alice",
		"marker":         "scenario-marker",
		"session_count":  5,
		"retry_after":    "30s",
	}
}
