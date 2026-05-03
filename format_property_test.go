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
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit"
)

// --- CEF escape round-trip (#558 walkthrough decision #25) -----------------

// TestCEFEscape_RoundTrip property-checks that the test-only inverse
// of cefEscapeExtValue recovers any non-C0 input string.
//
// Known asymmetry: cefEscapeExtValue strips C0 control bytes (other
// than \n and \r, which become literal "\n" / "\r"), so generators
// avoid C0 to keep the round-trip clean. The lossy C0 contract is
// intentional and exercised by the lossy fixtures sub-test below.
func TestCEFEscape_RoundTrip(t *testing.T) {
	t.Parallel()

	// Generator: bytes >= 0x20 (printable + extended UTF-8 prefix
	// bytes), with deliberate injection of \n and \r so the shrinker
	// explores the metacharacter space rather than collapsing to the
	// empty string.
	gen := rapid.SliceOf(rapid.OneOf(
		rapid.ByteRange(0x20, 0x7E), // printable ASCII
		rapid.Just(byte('\n')),
		rapid.Just(byte('\r')),
		rapid.Just(byte('\\')),
		rapid.Just(byte('=')),
		// Extended UTF-8: a small range of non-ASCII high bytes that
		// represent valid multibyte runes when paired with a leading
		// byte. Constraining to 0xC0-0xDF + 0x80-0xBF would yield
		// well-formed UTF-8; for the round-trip property we only need
		// byte-level fidelity so we accept any byte >= 0x20.
		rapid.ByteRange(0x80, 0xFF),
	))

	rapid.Check(t, func(rt *rapid.T) {
		input := string(gen.Draw(rt, "input"))
		escaped := audit.CEFEscapeExtValueForTest(input)
		got := cefUnescapeExtForTest(escaped)
		if got != input {
			rt.Fatalf("round-trip mismatch:\n  input    = %q\n  escaped  = %q\n  recovered= %q", input, escaped, got)
		}
	})

	// Fixed seeds for shrink-resistant canary cases. The property
	// already covers these via rapid, but a named t.Run keeps them
	// in CI reports.
	for name, in := range map[string]string{
		"empty":     "",
		"single_eq": "=",
		"single_bs": `\`,
		"only_meta": `\=\=\\`,
		"newline":   "a\nb",
		"cr":        "a\rb",
		"high_byte": string([]byte{0xC2, 0xA9}), // © UTF-8
	} {
		t.Run("seed_"+name, func(t *testing.T) {
			t.Parallel()
			got := cefUnescapeExtForTest(audit.CEFEscapeExtValueForTest(in))
			assert.Equal(t, in, got, "seed %q failed round-trip", name)
		})
	}
}

// TestCEFEscape_LossyC0 documents the intentional one-way contract
// for C0 control bytes other than \n and \r — they are stripped and
// cannot be recovered. Pinning this here means a future change that
// makes the escaper preserve C0 (or strips \n/\r as well) flips the
// expected outcome and the test fails.
func TestCEFEscape_LossyC0(t *testing.T) {
	t.Parallel()
	in := string([]byte{0x01, 'a', 0x07, 'b', 0x1F, 'c'})
	escaped := audit.CEFEscapeExtValueForTest(in)
	got := cefUnescapeExtForTest(escaped)
	assert.Equal(t, "abc", got, "C0 bytes other than \\n / \\r are stripped on escape")
}

// cefUnescapeExtForTest is the inverse of cefEscapeExtValue for the
// non-C0-stripping portion of its contract. Mirrors the four escape
// sequences emitted by the production escaper:
//
//	\\  -> \
//	\=  -> =
//	\n  -> newline
//	\r  -> CR
//
// Any other byte passes through unchanged. Invalid escape sequences
// (a backslash followed by anything other than the four characters
// above) are passed through verbatim — the production escaper never
// emits them, so the property test would fail loudly if one appeared.
func cefUnescapeExtForTest(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b != '\\' || i+1 >= len(s) {
			buf.WriteByte(b)
			continue
		}
		next := s[i+1]
		switch next {
		case '\\':
			buf.WriteByte('\\')
		case '=':
			buf.WriteByte('=')
		case 'n':
			buf.WriteByte('\n')
		case 'r':
			buf.WriteByte('\r')
		default:
			// Pass-through: production escaper never emits this.
			buf.WriteByte(b)
			buf.WriteByte(next)
		}
		i++
	}
	return buf.String()
}

// --- Formatter round-trip on arbitrary Fields -------------------------------

// TestFormatters_RoundTrip_OnArbitraryFields property-checks that
// JSON and CEF formatters preserve every input key/value through
// format → parse. Generators constrain keys to the taxonomy name
// pattern ([a-z][a-z0-9_]*) and exclude framework field names so the
// formatter does not auto-rewrite them. CEF values exclude C0
// controls per the lossy contract documented in TestCEFEscape_LossyC0.
func TestFormatters_RoundTrip_OnArbitraryFields(t *testing.T) {
	t.Parallel()

	t.Run("json", func(t *testing.T) {
		t.Parallel()
		f := &audit.JSONFormatter{}
		ts := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
		opts := &audit.FormatOptions{}

		rapid.Check(t, func(rt *rapid.T) {
			fields := propertyFields(rt)
			if len(fields) == 0 {
				return
			}
			out, err := f.Format(ts, "user_create", fields, &audit.EventDef{}, opts)
			require.NoError(t, err)

			var got map[string]any
			require.NoError(t, json.Unmarshal(bytes.TrimRight(out, "\n"), &got))

			for k, v := range fields {
				gotV, ok := got[k]
				if !ok {
					rt.Fatalf("JSON output missing input key %q", k)
				}
				if !valuesEqualForJSON(v, gotV) {
					rt.Fatalf("JSON value mismatch for key %q: input=%v (%T), got=%v (%T)", k, v, v, gotV, gotV)
				}
			}
		})
	})

	t.Run("cef", func(t *testing.T) {
		t.Parallel()
		f := &audit.CEFFormatter{Vendor: "AxonOps", Product: "Audit", Version: "test"}
		ts := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
		opts := &audit.FormatOptions{}

		rapid.Check(t, func(rt *rapid.T) {
			fields := propertyFields(rt) // C0-clean by string regex
			if len(fields) == 0 {
				return
			}
			out, err := f.Format(ts, "user_create", fields, &audit.EventDef{}, opts)
			require.NoError(t, err)

			ext := extractCEFExtension(out)
			parsed := parseCEFExtension(ext)
			for k, v := range fields {
				gotV, ok := parsed[k]
				if !ok {
					rt.Fatalf("CEF extension missing input key %q (extension=%q)", k, ext)
				}
				want := cefValueAsString(v)
				if gotV != want {
					rt.Fatalf("CEF value mismatch for key %q: want=%q, got=%q", k, want, gotV)
				}
			}
		})
	})
}

// propertyFields generates an audit.Fields map with constrained keys
// (taxonomy name pattern, never a framework name, never a CEF
// reserved extension key) and a small mix of scalar value types. The
// string value regex is the same shape for both formatters —
// printable ASCII excluding the CEF/JSON metacharacters, sufficient
// for the round-trip property without chasing the lossy C0 contract
// documented in TestCEFEscape_LossyC0.
func propertyFields(rt *rapid.T) audit.Fields {
	// Framework-name set as documented in audit/format.go::isFrameworkField.
	// We test against this set directly because the package-level helper
	// requires a Fields argument (its `duration_ms` arm depends on the
	// concrete value type), which is awkward inside a key generator.
	frameworkNames := map[string]struct{}{
		"timestamp": {}, "event_type": {}, "severity": {}, "event_category": {},
		"app_name": {}, "host": {}, "timezone": {}, "pid": {}, "duration_ms": {},
	}
	// CEF formatter built-in extension keys (format_cef.go:338,341,343
	// + framework-key emission lines 517-530). The formatter emits
	// these unconditionally; if the generator picks a key that
	// collides, the parser sees the formatter's value instead of the
	// generated one.
	cefReserved := map[string]struct{}{
		"act": {}, "rt": {},
		"deviceProcessName": {}, "dvchost": {}, "dtz": {}, "dvcpid": {},
		"cn1": {}, "cn1Label": {},
	}
	// CEF mapping target keys: if the generator picks a name like
	// "actor_id", the formatter rewrites it to "suser", and the
	// parser finds "suser" not "actor_id". Reserved standard fields
	// are also filtered to avoid this remapping.
	cefMapping := audit.DefaultCEFFieldMapping()
	keyGen := rapid.StringMatching(`^[a-z][a-z0-9_]{0,15}$`).
		Filter(func(s string) bool {
			if _, isFramework := frameworkNames[s]; isFramework {
				return false
			}
			if _, isCEFReserved := cefReserved[s]; isCEFReserved {
				return false
			}
			if _, isMapped := cefMapping[s]; isMapped {
				return false
			}
			return true
		})

	const stringValRegex = `^[a-zA-Z0-9 _\-./@:]{0,32}$`
	valGen := rapid.OneOf(
		rapid.Map(rapid.StringMatching(stringValRegex), func(s string) any { return s }),
		rapid.Map(rapid.IntRange(-10000, 10000), func(n int) any { return n }),
		rapid.Map(rapid.Bool(), func(b bool) any { return b }),
	)

	n := rapid.IntRange(0, 5).Draw(rt, "field_count")
	out := make(audit.Fields, n)
	for i := 0; i < n; i++ {
		k := keyGen.Draw(rt, "k")
		if _, dup := out[k]; dup {
			continue
		}
		out[k] = valGen.Draw(rt, "v")
	}
	return out
}

// valuesEqualForJSON compares an input field value to the value
// re-extracted from JSON. JSON numerics arrive as float64; integer
// inputs round-trip through float64 without loss within the
// generator's IntRange(-10000, 10000).
func valuesEqualForJSON(want, got any) bool {
	switch wantV := want.(type) {
	case string:
		gotS, ok := got.(string)
		return ok && gotS == wantV
	case bool:
		gotB, ok := got.(bool)
		return ok && gotB == wantV
	case int:
		gotF, ok := got.(float64)
		return ok && int(gotF) == wantV
	}
	return false
}

// cefValueAsString renders a Go value the way CEFFormatter renders
// it into the extension slot. Mirrors the production string-coercion
// rules for the value types our generator produces.
func cefValueAsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	}
	return ""
}

// extractCEFExtension splits a CEF event line at the 7th `|` pipe
// (header has 7 segments) and returns the unescaped extension string.
// The CEF line is the body emitted by CEFFormatter.Format.
func extractCEFExtension(line []byte) string {
	// Find the 7th un-escaped pipe.
	pipes := 0
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && i+1 < len(line) {
			i++
			continue
		}
		if line[i] == '|' {
			pipes++
			if pipes == 7 {
				start = i + 1
				break
			}
		}
	}
	end := len(line)
	if line[end-1] == '\n' {
		end--
	}
	return string(line[start:end])
}

// parseCEFExtension splits a CEF extension section into key=value
// pairs using whitespace as the pair separator (not part of an
// escape sequence) and `=` as the within-pair separator. Handles the
// `\\`, `\=`, `\n`, `\r` escape sequences emitted by
// cefEscapeExtValue.
//
// CEF uses space-separated key=value pairs in its extension. Keys
// match `[a-zA-Z0-9_]+` (no escaping); values use the four escape
// sequences listed above. We split into pairs by scanning for the
// next ` key=` pattern.
func parseCEFExtension(ext string) map[string]string {
	out := make(map[string]string)
	i := 0
	for i < len(ext) {
		// Find the next `=`.
		eq := strings.IndexByte(ext[i:], '=')
		if eq < 0 {
			break
		}
		// Walk back to find the key start (after the previous space
		// that ISN'T inside an escape sequence — keys are unescaped).
		keyStart := i
		// Find the next ' k=' sequence to bound the value.
		// Value runs until the next bare `=` lookback finds a key.
		valStart := i + eq + 1
		valEnd := len(ext)
		// Scan forward for the next " <key>=" pattern.
		for j := valStart; j < len(ext); j++ {
			if ext[j] == '\\' && j+1 < len(ext) {
				j++
				continue
			}
			if ext[j] == ' ' && nextRunIsKey(ext, j+1) {
				valEnd = j
				break
			}
		}
		key := ext[keyStart : i+eq]
		val := cefUnescapeExtForTest(ext[valStart:valEnd])
		out[key] = val
		// Skip past the value and any trailing space.
		i = valEnd
		if i < len(ext) && ext[i] == ' ' {
			i++
		}
	}
	return out
}

// nextRunIsKey reports whether the bytes starting at i look like a
// CEF extension key followed by `=`. CEF keys match `[a-zA-Z0-9_]+`.
func nextRunIsKey(s string, i int) bool {
	j := i
	for j < len(s) && isCEFKeyByte(s[j]) {
		j++
	}
	return j > i && j < len(s) && s[j] == '='
}

// isCEFKeyByte reports whether b is a valid byte in a CEF extension
// key per the [a-zA-Z0-9_]+ character class.
func isCEFKeyByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_':
		return true
	}
	return false
}
