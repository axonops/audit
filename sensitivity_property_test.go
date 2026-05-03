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

package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit"
)

// TestSensitivity_Stripping_Invariants property-checks two
// invariants of sensitivity labelling, split per the test-analyst
// pre-coding consult (#558):
//
//	(b1) any taxonomy that LABELS a framework field is rejected at
//	     ValidateTaxonomy time — the runtime cannot strip framework
//	     fields because configurations that would name them never
//	     reach runtime.
//	(b2) for any VALID config, formatter output preserves every
//	     framework field regardless of which labels are excluded.
//
// (b1) and (b2) together prove "framework fields are never stripped"
// without the tautology of asserting that-which-validation-prevents
// at the runtime layer alone.
func TestSensitivity_Stripping_Invariants(t *testing.T) {
	t.Parallel()

	t.Run("framework_field_label_rejected_by_validator", func(t *testing.T) {
		t.Parallel()
		frameworkNames := []string{
			"timestamp", "event_type", "severity", "duration_ms", "event_category",
			"app_name", "host", "timezone", "pid",
		}
		labelNames := []string{"pii", "financial", "secret"}

		rapid.Check(t, func(rt *rapid.T) {
			fwField := rapid.SampledFrom(frameworkNames).Draw(rt, "framework_field")
			labelName := rapid.SampledFrom(labelNames).Draw(rt, "label")

			tax := audit.Taxonomy{
				Version: 1,
				Categories: map[string]*audit.CategoryDef{
					"write": {Events: []string{"user_create"}},
				},
				Events: map[string]*audit.EventDef{
					"user_create": {
						Categories: []string{"write"},
						Required:   []string{"outcome"},
					},
				},
				Sensitivity: &audit.SensitivityConfig{
					Labels: map[string]*audit.SensitivityLabel{
						labelName: {Fields: []string{fwField}},
					},
				},
			}

			err := audit.ValidateTaxonomy(tax)
			if err == nil {
				rt.Fatalf("validator accepted taxonomy with label %q targeting framework field %q", labelName, fwField)
			}
			// The error must wrap ErrTaxonomyInvalid and mention both
			// the label name and the framework field name so operators
			// can locate the misconfiguration.
			if !errors.Is(err, audit.ErrTaxonomyInvalid) {
				rt.Fatalf("expected ErrTaxonomyInvalid wrap, got: %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, labelName) {
				rt.Fatalf("validator error must mention the label name %q: %s", labelName, msg)
			}
			if !strings.Contains(msg, fwField) {
				rt.Fatalf("validator error must mention the framework field %q: %s", fwField, msg)
			}
		})
	})

	t.Run("non_labelled_field_preserved_through_format", func(t *testing.T) {
		t.Parallel()
		// Generate a label config that strips one of {custom_a, custom_b}.
		// The other custom field MUST survive formatting whether or not
		// the stripping label is excluded.
		stripFields := []string{"custom_a", "custom_b"}
		labelGen := rapid.SampledFrom([]string{"pii", "financial"})

		rapid.Check(t, func(rt *rapid.T) {
			labelName := labelGen.Draw(rt, "label")
			stripped := rapid.SampledFrom(stripFields).Draw(rt, "stripped")
			preserved := otherOf(stripFields, stripped)

			tax := audit.Taxonomy{
				Version: 1,
				Categories: map[string]*audit.CategoryDef{
					"write": {Events: []string{"user_create"}},
				},
				Events: map[string]*audit.EventDef{
					"user_create": {
						Categories: []string{"write"},
						Required:   []string{"outcome"},
						Optional:   stripFields,
					},
				},
				Sensitivity: &audit.SensitivityConfig{
					Labels: map[string]*audit.SensitivityLabel{
						labelName: {Fields: []string{stripped}},
					},
				},
			}
			require.NoError(t, audit.ValidateTaxonomy(tax))

			out := newCapturingOutput()
			auditor, err := audit.New(
				audit.WithTaxonomy(&tax),
				audit.WithAppName("sensitivity-property"),
				audit.WithHost("sensitivity-property-host"),
				audit.WithNamedOutput(out, audit.WithExcludeLabels(labelName)),
			)
			require.NoError(t, err)
			defer func() { _ = auditor.Close() }()

			err = auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
				"outcome": "success",
				stripped:  "stripped-value",
				preserved: "preserved-value",
			}))
			require.NoError(t, err)
			require.NoError(t, auditor.Close())

			data := out.bytes()
			if !strings.Contains(data, "preserved-value") {
				rt.Fatalf("non-labelled field %q was stripped — output: %s", preserved, data)
			}
			if strings.Contains(data, "stripped-value") {
				rt.Fatalf("labelled field %q was NOT stripped — output: %s", stripped, data)
			}
			// (b2): every framework field name must appear in the output
			// regardless of label exclusion. Most are unconditionally
			// present (timestamp, event_type, severity, app_name, host,
			// timezone, pid).
			for _, fw := range []string{"timestamp", "event_type", "severity", "app_name", "host", "timezone", "pid"} {
				if !strings.Contains(data, fw) {
					rt.Fatalf("framework field %q missing from output after label exclusion: %s", fw, data)
				}
			}
		})
	})
}

// otherOf returns the string in pair that is not "exclude". pair is
// expected to have exactly two elements.
func otherOf(pair []string, exclude string) string {
	for _, s := range pair {
		if s != exclude {
			return s
		}
	}
	return ""
}

// capturingOutput captures Format output so the property test can
// inspect what reached the wire.
type capturingOutput struct {
	buf strings.Builder
}

func newCapturingOutput() *capturingOutput { return &capturingOutput{} }

func (c *capturingOutput) Write(p []byte) error {
	c.buf.Write(p)
	return nil
}
func (c *capturingOutput) Close() error  { return nil }
func (c *capturingOutput) Name() string  { return "capture" }
func (c *capturingOutput) bytes() string { return c.buf.String() }

// Compile-time assertion that capturingOutput is a valid Output.
var _ audit.Output = (*capturingOutput)(nil)
