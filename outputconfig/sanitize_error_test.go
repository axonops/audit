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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
)

// TestLoad_FactoryErrorWithControlBytes_Sanitized regression-locks
// the v0.2.1 fix that strips control bytes (NUL / C0 / C1 / DEL) from
// factory error messages before they enter the outputconfig error
// chain. goccy/go-yaml's parse errors embed offending source bytes
// verbatim in the "X: bad" diagnostic context — caught by
// [FuzzOutputConfigLoad] seed `8acc4c4aa19b65a1`. This test pins the
// contract from the black-box API so a future refactor of the
// sanitization helper cannot silently regress it.
//
// Additionally asserts the [errors.Is] chain is preserved through the
// sanitizing wrapper — the sanitizedError type implements Unwrap so
// sentinels embedded in the factory error are still reachable by
// callers.
func TestLoad_FactoryErrorWithControlBytes_Sanitized(t *testing.T) {
	tax, err := audit.ParseTaxonomyYAML([]byte(`
version: 1
categories:
  write: [user_create]
events:
  user_create:
    fields:
      actor_id: {required: true}
      outcome: {required: true}
`))
	require.NoError(t, err)

	// Input is the minimised crasher from FuzzOutputConfigLoad. The
	// `\x00:` inside `outputs.A.file:` makes the file factory's YAML
	// parser produce an error containing a raw NUL.
	data := []byte("version: 1\napp_name: 0\nhost: 0\noutputs:\n A:\n    type: file\n    file:\n     \x00:")

	_, err = outputconfig.Load(context.Background(), data, tax)
	require.Error(t, err, "expected a parse error")

	msg := err.Error()
	assert.Falsef(t, strings.ContainsRune(msg, 0),
		"error message must not contain raw NUL; got: %q", msg)
	for i, r := range msg {
		if r < 0x20 || r == 0x7F {
			// Standard whitespace (newline, tab, CR) is acceptable —
			// many YAML parse errors include a trailing newline in
			// the carat-pointing context line. Reject everything
			// else.
			if r == '\n' || r == '\t' || r == '\r' {
				continue
			}
			t.Errorf("control byte %#x at index %d in error message: %q", r, i, msg)
		}
	}

	// Sanitization preserves the errors.Is chain — the wrapped
	// factory error still satisfies audit.ErrConfigInvalid (the
	// outputconfig.Load entry point wraps with ErrOutputConfigInvalid
	// which has ErrConfigInvalid as its inner). This proves Unwrap
	// is implemented on the sanitizing wrapper.
	assert.ErrorIsf(t, err, audit.ErrConfigInvalid,
		"errors.Is must reach audit.ErrConfigInvalid through the sanitizing wrapper; got: %v", err)
}
