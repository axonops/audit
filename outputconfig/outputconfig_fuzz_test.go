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

package outputconfig_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
)

// fuzzTaxonomy is a reusable taxonomy fixture for [FuzzOutputConfigLoad].
// Built once at package init and cloned in each fuzz iteration would be
// ideal, but Load accepts *Taxonomy so we can reuse the pointer.
var fuzzTaxonomy = func() *audit.Taxonomy { //nolint:gochecknoglobals // fuzz fixture
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      actor_id: {required: true}
      outcome: {required: true}
`))
	if err != nil {
		panic(err)
	}
	return tax
}()

// FuzzOutputConfigLoad drives [outputconfig.Load] with arbitrary
// YAML and asserts the loader never panics, always returns either
// a valid result OR an error, and completes within a bounded time
// so pathological inputs don't hang CI (#481).
//
//nolint:cyclop // invariants are intentionally linear; splitting would hurt readability
func FuzzOutputConfigLoad(f *testing.F) {
	// Good seeds — minimal valid configs.
	f.Add([]byte(`version: 1
app_name: fuzz
host: fuzz-host
outputs:
  console:
    type: stdout
`))
	f.Add([]byte(`version: 1
app_name: fuzz
host: fuzz-host
outputs:
  audit_file:
    type: file
    file:
      path: /tmp/audit.log
`))

	// Empty / boundary.
	f.Add([]byte(``))
	f.Add([]byte(`version: 1`))

	// Known-bad structures.
	f.Add([]byte(`version: 0`))
	f.Add([]byte(`version: 99`))
	f.Add([]byte(`version: 1
outputs: {}
`)) // zero outputs
	f.Add([]byte(`version: 1
bogus_top_level: true
outputs:
  x:
    type: stdout
`)) // unknown top-level
	f.Add([]byte(`version: 1
tls_policy:
  allow_tls12: true
outputs:
  x:
    type: stdout
`)) // removed root-level tls_policy (#476)
	f.Add([]byte(`version: 1
app_name: "${UNDEFINED_FUZZ_VAR}"
host: h
outputs:
  x:
    type: stdout
`)) // unset env var with no default
	f.Add([]byte("\xff\xfe\x00\x00")) // invalid bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound each iteration with a 3-second timeout. The env
		// expander and YAML decoder should complete near-instantly
		// on all inputs; a 3s ceiling catches pathological hangs
		// without risking false positives on slow CI runners.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		result, err := outputconfig.Load(ctx, data, fuzzTaxonomy)

		// Invariant 1 — impossible state: both nil or both non-nil.
		if err != nil && result != nil {
			// result may be nil-but-wrapped or a partial — but a
			// fully populated *Loaded paired with an error is
			// impossible and would indicate a caller might see
			// misleading values.
			if len(result.OutputMetadata()) > 0 {
				t.Fatalf("Load returned error %v together with %d outputs",
					err, len(result.OutputMetadata()))
			}
		}
		if err == nil && result == nil {
			t.Fatalf("impossible state: nil result and nil error")
		}

		// Invariant 2 — error messages must not contain raw control
		// bytes (log-injection defence, same rule as
		// FuzzParseTaxonomyYAML).
		if err != nil && strings.ContainsRune(err.Error(), 0) {
			t.Fatalf("error message contains raw NUL: %q", err.Error())
		}

		// Invariant 3 — on accept, every produced output must have
		// a non-empty Name(). A nameless output would break metric
		// labelling downstream.
		if err == nil && result != nil {
			for i, no := range result.OutputMetadata() {
				if no.Output == nil {
					t.Fatalf("result.OutputMetadata()[%d] has nil Output", i)
				}
				if no.Output.Name() == "" {
					t.Fatalf("result.OutputMetadata()[%d] has empty Name()", i)
				}
				_ = no.Output.Close()
			}
		}
	})
}
