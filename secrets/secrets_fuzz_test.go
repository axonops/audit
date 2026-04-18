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

package secrets_test

import (
	"strings"
	"testing"

	"github.com/axonops/audit/secrets"
)

// FuzzParseRef drives [secrets.ParseRef] with arbitrary bytes and
// asserts the function never panics and never returns an
// impossible state (non-zero Ref paired with a non-nil error).
//
// The regular `go test ./...` invocation runs this function against
// the seeds below and any committed regression seeds under
// testdata/fuzz/FuzzParseRef/. The release workflow runs it in
// discovery mode with `-fuzz=FuzzParseRef -fuzztime=...` per #481.
//
//nolint:cyclop // invariants are intentionally linear; splitting would hurt readability
func FuzzParseRef(f *testing.F) {
	// Good seeds — valid refs across schemes, paths, and keys.
	f.Add("ref+openbao://secret/data/app#password")
	f.Add("ref+vault://secret/data/hmac#salt")
	f.Add("ref+openbao://a/b/c#k")

	// Not-a-ref — the function should return (zero, nil).
	f.Add("")
	f.Add("plain-string-value")
	f.Add("https://example.com/path")

	// Known malformed — function should return (zero, non-nil err).
	f.Add("ref+")
	f.Add("ref+://path#key")                                   // empty scheme
	f.Add("ref+vault://path")                                  // missing fragment
	f.Add("ref+vault://#key")                                  // empty path
	f.Add("ref+vault://path#")                                 // empty key
	f.Add("ref+vault://path#key1#key2")                        // multiple fragments
	f.Add("ref+vault://a//b#key")                              // empty segment
	f.Add("ref+vault://../secret#key")                         // path traversal
	f.Add("ref+vault://a/..#key")                              // traversal embedded
	f.Add("ref+vault://a/.#key")                               // current-dir segment
	f.Add("ref+vault://%2e%2e/x#key")                          // percent-encoded traversal
	f.Add("ref+vault://path%00key#k")                          // embedded null (percent form)
	f.Add("ref+vault://path\x00k#k")                           // raw null byte
	f.Add("ref+VAULT://path#key")                              // uppercase scheme
	f.Add("ref+1ab://path#key")                                // scheme starting with digit
	f.Add("ref+vault://p#\xc3\xa9")                            // non-ASCII in key
	f.Add("ref+vault://" + strings.Repeat("a/", 1000) + "x#k") // long path

	f.Fuzz(func(t *testing.T, s string) {
		ref, err := secrets.ParseRef(s)

		// Invariant 1 — impossible state.
		// Parser must NEVER return a non-zero Ref together with an
		// error; that would be a bug where a caller could think they
		// got a valid ref when the parser actually rejected it.
		if err != nil && !ref.IsZero() {
			t.Fatalf("impossible state: err=%q but ref is non-zero: %+v", err, ref)
		}

		// Invariant 2 — accepted refs must be internally consistent.
		// If ParseRef returns a non-zero Ref with nil error, Ref.Valid()
		// must also report it valid — the two contracts must agree.
		if err == nil && !ref.IsZero() {
			if valid := ref.Valid(); valid != nil {
				t.Fatalf("ParseRef accepted %q but Ref.Valid disagreed: %v",
					s, valid)
			}
			// Independent path-safety check: the segment-level
			// traversal rule and the no-control-byte rule are the
			// two most security-critical properties. Assert them
			// directly so a future weakening of Ref.Valid is caught.
			for _, seg := range strings.Split(ref.Path, "/") {
				if seg == ".." || seg == "." || seg == "" {
					t.Fatalf("accepted ref has unsafe path segment %q (full path %q, input %q)",
						seg, ref.Path, s)
				}
			}
			for i := 0; i < len(ref.Path); i++ {
				b := ref.Path[i]
				if b < 0x20 || b == 0x7f {
					t.Fatalf("accepted ref path contains control byte 0x%02x at %d (path %q, input %q)",
						b, i, ref.Path, s)
				}
			}
		}

		// Invariant 3 — String() must not panic on any state.
		// Exercising the round-trip even on rejected refs catches
		// zero-value String() regressions.
		_ = ref.String()
	})
}
