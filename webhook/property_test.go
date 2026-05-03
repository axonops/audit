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

package webhook_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit/webhook"
)

// TestNDJSON_BatchSerialise_RoundTrip property-checks that
// buildNDJSON's batch encoding is structurally lossless: N event
// payloads in → exactly N non-empty lines out, and each line's
// content equals the corresponding input (modulo the appended
// trailing newline that buildNDJSON inserts when the input lacks
// one).
//
// Per pre-coding test-analyst guidance: input payloads MUST exclude
// `\n` because production assumes formatter-emitted JSON has no
// embedded newlines. The TestNDJSON_BatchSerialise_EmbeddedNewline
// fixture below pins what happens when that contract is violated
// (the embedded newline corrupts the NDJSON line count) so a future
// formatter that accidentally emits multi-line JSON is caught.
func TestNDJSON_BatchSerialise_RoundTrip(t *testing.T) {
	t.Parallel()

	// Generator: 1..50 event payloads, each a non-empty byte slice
	// drawn from printable ASCII (and a deliberate trailing-newline
	// toggle to exercise the trailing-newline-aware concatenation).
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 50).Draw(rt, "n")
		events := make([][]byte, n)
		for i := 0; i < n; i++ {
			body := rapid.SliceOfN(
				rapid.ByteRange(0x20, 0x7E), // printable ASCII; no \n
				1, 64,
			).Draw(rt, "event_body")
			// Half the time, append a trailing newline to exercise
			// buildNDJSON's "preserve, don't double" branch.
			if rapid.Bool().Draw(rt, "trailing_newline") {
				body = append(body, '\n')
			}
			events[i] = body
		}

		out := webhook.BuildNDJSON(events)

		// Every event's body must end in exactly one newline.
		// Split, dropping the empty trailing element after the final \n.
		raw := bytes.TrimRight(out, "\n")
		lines := bytes.Split(raw, []byte("\n"))
		if len(lines) != n {
			rt.Fatalf("line count mismatch: in=%d, out=%d, raw=%q", n, len(lines), out)
		}
		for i, got := range lines {
			want := bytes.TrimRight(events[i], "\n")
			if !bytes.Equal(got, want) {
				rt.Fatalf("line %d mismatch:\n  in=  %q\n  out= %q", i, want, got)
			}
		}
	})
}

// TestNDJSON_BatchSerialise_EmbeddedNewline pins the contract that a
// formatter MUST NOT emit embedded newlines inside a single event's
// JSON body. If it ever does, NDJSON line counting goes wrong: one
// input event becomes two output lines. Pinned outside the rapid
// loop so the failure mode is preserved as documentation.
func TestNDJSON_BatchSerialise_EmbeddedNewline(t *testing.T) {
	t.Parallel()
	events := [][]byte{
		[]byte(`{"a":1}` + "\n"),
		[]byte("oops\nembedded\n"), // adversarial — formatter must not emit this
		[]byte(`{"c":3}` + "\n"),
	}
	out := webhook.BuildNDJSON(events)
	raw := bytes.TrimRight(out, "\n")
	lines := bytes.Split(raw, []byte("\n"))
	// Documents the real failure mode: 4 lines from 3 events.
	assert.Equal(t, 4, len(lines),
		"embedded newline corrupts NDJSON line count — formatter contract is no embedded newlines")
	require.Equal(t, []byte(`{"a":1}`), lines[0])
	require.Equal(t, []byte(`oops`), lines[1])
	require.Equal(t, []byte(`embedded`), lines[2])
	require.Equal(t, []byte(`{"c":3}`), lines[3])
}
