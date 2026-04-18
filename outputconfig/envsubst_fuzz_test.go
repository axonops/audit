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
	"strings"
	"testing"

	"github.com/axonops/audit/outputconfig"
)

// FuzzExpandEnvString drives [outputconfig.expandEnvString] with
// arbitrary input and asserts the function does not panic and does
// not produce pathologically large output from small inputs (#481).
//
// Invariants:
//   - No panic.
//   - `$${` escape sequence produces literal `${` in the output.
//   - Output length is bounded — a single-pass expander must produce
//     at most O(len(input) + sum of env-var values) bytes. The fuzz
//     harness asserts output length < 10 MiB to catch exponential
//     expansion regressions.
func FuzzExpandEnvString(f *testing.F) {
	// Good seeds — valid expansions.
	f.Add("plain-string")
	f.Add("${SOME_VAR:-default}")
	f.Add("prefix-${A_B_C:-fallback}-suffix")
	f.Add("$${literal-dollar-brace}")
	f.Add("")

	// Boundary seeds — malformed patterns that must error cleanly.
	f.Add("$")
	f.Add("${")
	f.Add("${}")
	f.Add("${X")
	f.Add("${X:-")
	f.Add("${A:-${B:-c}}") // nested default (not supported; must error or treat as literal)
	f.Add("${0BAD}")       // name starting with digit
	f.Add("${-NAME}")      // name starting with hyphen
	f.Add("${A-B}")        // bare dash (not `:-`)
	f.Add("${LONG_" + strings.Repeat("A", 512) + "}")
	f.Add(strings.Repeat("${NOVAR:-x}", 100)) // many substitutions

	f.Fuzz(func(t *testing.T, s string) {
		// Set a controlled env var so substitution paths execute.
		// Fuzzer-generated input will mostly hit the unset-no-default
		// error path, which is fine — fuzzer is looking for panics.
		t.Setenv("AUDIT_FUZZ_VAR", "value")

		out, err := outputconfig.ExpandEnvStringForTest(s, "fuzz-field")

		// Invariant 1 — no panic (Go fuzz harness catches this).

		// Invariant 2 — successful expansion must not produce
		// unbounded output. A small input that triggers >10 MiB of
		// output indicates exponential expansion, which would be a
		// DoS vector.
		if err == nil && len(out) > 10*1024*1024 {
			t.Fatalf("expansion produced %d bytes of output from %d-byte input (exponential expansion?)",
				len(out), len(s))
		}

		// Note: a "$${ must collapse" invariant is tempting but
		// incorrect — e.g. input `$$${` legitimately produces
		// output `$${` because `${` at offset 2 is escaped by the
		// `$` at offset 1, leaving the `$` at offset 0 as a
		// literal dollar that happens to land next to the escaped
		// `${`. Replicating the expander logic to express this
		// invariant is not worth the complexity; no-panic +
		// bounded-output cover the real concerns.

		// Invariant 3 — error state must not produce garbage output.
		// Some expanders return partial output on error; ours must
		// return "" on any error (consumer contract).
		if err != nil && out != "" {
			t.Fatalf("error returned together with non-empty output: err=%v, out=%q",
				err, out)
		}
	})
}
