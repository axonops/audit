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

package steps

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// registerEventMetadataSteps wires the #597 BDD scenarios that
// assert the enriched [audit.Event] interface (Description,
// Categories, FieldInfoMap) and the parallel methods on
// [audit.EventHandle].
//
//nolint:gocognit,gocyclo,cyclop // step-registration block: flat list of ctx.Step closures, not branching logic
func registerEventMetadataSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// NewEvent path — taxonomy-agnostic.
	ctx.Step(`^I call NewEvent for "([^"]*)" with required fields$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastEvent = audit.NewEvent(eventType, fields)
		return nil
	})

	ctx.Step(`^the event Description should be empty$`, func() error {
		if tc.LastEvent == nil {
			return fmt.Errorf("no event captured")
		}
		if d := tc.LastEvent.Description(); d != "" {
			return fmt.Errorf("expected empty description, got %q", d)
		}
		return nil
	})

	ctx.Step(`^the event Categories should be empty$`, func() error {
		if tc.LastEvent == nil {
			return fmt.Errorf("no event captured")
		}
		if cs := tc.LastEvent.Categories(); len(cs) != 0 {
			return fmt.Errorf("expected nil/empty categories, got %v", cs)
		}
		return nil
	})

	ctx.Step(`^the event FieldInfoMap should be empty$`, func() error {
		if tc.LastEvent == nil {
			return fmt.Errorf("no event captured")
		}
		if fim := tc.LastEvent.FieldInfoMap(); len(fim) != 0 {
			return fmt.Errorf("expected nil/empty FieldInfoMap, got %v", fim)
		}
		return nil
	})

	// EventHandle path — taxonomy-resolved.
	ctx.Step(`^I obtain a handle for "([^"]*)"$`, func(eventType string) error {
		h, err := tc.Auditor.Handle(eventType)
		if err != nil {
			return fmt.Errorf("obtain handle: %w", err)
		}
		tc.EventHandle = h
		return nil
	})

	ctx.Step(`^the handle Description should equal "([^"]*)"$`, func(want string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		if got := tc.EventHandle.Description(); got != want {
			return fmt.Errorf("description: want %q, got %q", want, got)
		}
		return nil
	})

	ctx.Step(`^the handle Categories should contain exactly "([^"]*)"$`, func(want string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		cs := tc.EventHandle.Categories()
		if len(cs) != 1 {
			return fmt.Errorf("want exactly 1 category, got %d: %v", len(cs), cs)
		}
		if cs[0].Name != want {
			return fmt.Errorf("want category %q, got %q", want, cs[0].Name)
		}
		return nil
	})

	ctx.Step(`^the handle Categories "([^"]*)" should have severity (\d+)$`, func(name string, sev int) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		for _, ci := range tc.EventHandle.Categories() {
			if ci.Name == name {
				if ci.Severity == nil {
					return fmt.Errorf("category %q has nil severity, want %d", name, sev)
				}
				if *ci.Severity != sev {
					return fmt.Errorf("category %q severity: want %d, got %d", name, sev, *ci.Severity)
				}
				return nil
			}
		}
		return fmt.Errorf("category %q not found in handle", name)
	})

	ctx.Step(`^the handle Categories "([^"]*)" should have no severity$`, func(name string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		for _, ci := range tc.EventHandle.Categories() {
			if ci.Name == name {
				if ci.Severity != nil {
					return fmt.Errorf("category %q has severity %d, want nil", name, *ci.Severity)
				}
				return nil
			}
		}
		return fmt.Errorf("category %q not found in handle", name)
	})

	ctx.Step(`^the handle FieldInfoMap should mark "([^"]*)" as required$`, func(field string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		fim := tc.EventHandle.FieldInfoMap()
		fi, ok := fim[field]
		if !ok {
			return fmt.Errorf("field %q absent from FieldInfoMap", field)
		}
		if !fi.Required {
			return fmt.Errorf("field %q expected required, got optional", field)
		}
		return nil
	})

	ctx.Step(`^the handle FieldInfoMap should mark "([^"]*)" as optional$`, func(field string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		fim := tc.EventHandle.FieldInfoMap()
		fi, ok := fim[field]
		if !ok {
			return fmt.Errorf("field %q absent from FieldInfoMap", field)
		}
		if fi.Required {
			return fmt.Errorf("field %q expected optional, got required", field)
		}
		return nil
	})

	ctx.Step(`^the handle FieldInfoMap should include "([^"]*)"$`, func(field string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		if _, ok := tc.EventHandle.FieldInfoMap()[field]; !ok {
			return fmt.Errorf("field %q absent from FieldInfoMap", field)
		}
		return nil
	})

	ctx.Step(`^the handle FieldInfoMap entry for "([^"]*)" should carry label "([^"]*)"$`, func(field, label string) error {
		if tc.EventHandle == nil {
			return fmt.Errorf("no handle captured")
		}
		fi, ok := tc.EventHandle.FieldInfoMap()[field]
		if !ok {
			return fmt.Errorf("field %q absent from FieldInfoMap", field)
		}
		for _, l := range fi.Labels {
			if l.Name == label {
				return nil
			}
		}
		return fmt.Errorf("field %q labels %v do not contain %q", field, fi.Labels, label)
	})
}
