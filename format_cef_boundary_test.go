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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// The tests in this file pin contract boundaries that a coverage-only
// test suite can leave under-asserted. Each test pairs an at-boundary
// case with a just-past-boundary case so both directions of the strict
// comparison are covered. Mutation testing (#571) drives this discipline:
// without paired-boundary assertions, off-by-one mutations of the
// underlying `<` / `>` operators slip through unnoticed.

// TestCEFFormatter_HeaderFieldExactlyAtMaxLength proves that Vendor,
// Product, and Version values of exactly maxCEFHeaderField (255) bytes
// are accepted and that 256-byte values are rejected. The test asserts
// both sides of every boundary so that flipping `>` to `>=` (or
// vice-versa) at any of format_cef.go:279/282/285 is caught.
func TestCEFFormatter_HeaderFieldExactlyAtMaxLength(t *testing.T) {
	t.Parallel()
	const maxLen = 255 // mirrors maxCEFHeaderField in format_cef.go

	makeFmt := func() *audit.CEFFormatter {
		return &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	}
	fields := audit.Fields{"outcome": "success"}

	cases := []struct {
		name      string
		mutator   func(*audit.CEFFormatter, string)
		boundary  string
		acceptLen int
		rejectLen int
	}{
		{"vendor", func(cf *audit.CEFFormatter, s string) { cf.Vendor = s }, "vendor", maxLen, maxLen + 1},
		{"product", func(cf *audit.CEFFormatter, s string) { cf.Product = s }, "product", maxLen, maxLen + 1},
		{"version", func(cf *audit.CEFFormatter, s string) { cf.Version = s }, "version", maxLen, maxLen + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_at_max_accepted", func(t *testing.T) {
			t.Parallel()
			cf := makeFmt()
			tc.mutator(cf, strings.Repeat("a", tc.acceptLen))
			_, err := cf.Format(testTime, "ev", fields, testDef, nil)
			assert.NoError(t, err,
				"%s of exactly %d bytes must be accepted", tc.boundary, tc.acceptLen)
		})
		t.Run(tc.name+"_over_max_rejected", func(t *testing.T) {
			t.Parallel()
			cf := makeFmt()
			tc.mutator(cf, strings.Repeat("a", tc.rejectLen))
			_, err := cf.Format(testTime, "ev", fields, testDef, nil)
			require.Error(t, err,
				"%s of %d bytes must be rejected", tc.boundary, tc.rejectLen)
			assert.Contains(t, err.Error(), tc.boundary,
				"error must identify which header field exceeded the limit")
		})
	}
}

// TestCEFFormatter_PidZeroOmitsDvcpid proves that SetFrameworkFields
// with pid=0 yields no `dvcpid` extension and that pid=1 emits
// `dvcpid=1`. The pair pins the strict boundary at format_cef.go:508
// (`if pid > 0`) so that flipping `>` to `>=` is caught.
func TestCEFFormatter_PidZeroOmitsDvcpid(t *testing.T) {
	t.Parallel()
	fields := audit.Fields{"outcome": "success"}

	cfZero := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	cfZero.SetFrameworkFields("app", "host", "UTC", 0)
	out, err := cfZero.Format(testTime, "ev", fields, testDef, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "dvcpid=",
		"pid=0 must NOT emit a dvcpid extension; got: %s", out)

	cfOne := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	cfOne.SetFrameworkFields("app", "host", "UTC", 1)
	out, err = cfOne.Format(testTime, "ev", fields, testDef, nil)
	require.NoError(t, err)
	assert.Contains(t, string(out), "dvcpid=1",
		"pid=1 must emit dvcpid=1; got: %s", out)
}

// TestCEFExtKeyValidation_BoundaryCharacters extends the
// validateExtKey character-class coverage by exercising every
// at-boundary character of the [a-zA-Z0-9_] regex AND the
// just-past-boundary characters on either side. Each accept/reject
// pair pins one strict comparison at format_cef.go:614 so that
// flipping `<` to `<=` (or `>` to `>=`) for any of the six letter/
// digit boundaries is caught.
func TestCEFExtKeyValidation_BoundaryCharacters(t *testing.T) {
	t.Parallel()

	accept := []string{"a", "z", "A", "Z", "0", "9", "_"}
	for _, s := range accept {
		t.Run("accept_"+s, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, audit.ValidateExtKeyForTest(s),
				"boundary char %q must be accepted by validateExtKey", s)
		})
	}

	reject := []byte{'a' - 1, 'z' + 1, 'A' - 1, 'Z' + 1, '0' - 1, '9' + 1}
	for _, b := range reject {
		s := string(b)
		t.Run(fmt.Sprintf("reject_0x%02X", b), func(t *testing.T) {
			t.Parallel()
			assert.Error(t, audit.ValidateExtKeyForTest(s),
				"just-past-boundary char 0x%02X (%q) must be rejected", b, s)
		})
	}
}

// TestCEFFormatter_ExtensionFieldsSpaceSeparated proves that
// consecutive CEF extensions are separated by exactly one space
// character — so flipping the separator guard at format_cef.go:629
// from `b.Len() > extStart` to `b.Len() <= extStart` (which would
// emit "rt=12345act=user_create" with no separator) is caught.
//
// The test inspects the bytes immediately following the rt= field
// and asserts that the next extension starts with " <key>=" (leading
// space). Substring assertions like Contains("act=...") are not
// sufficient to kill this mutant: "act=..." remains a substring of
// "rt=12345act=...".
func TestCEFFormatter_ExtensionFieldsSpaceSeparated(t *testing.T) {
	t.Parallel()
	cf := &audit.CEFFormatter{Vendor: "V", Product: "P", Version: "1"}
	cf.SetFrameworkFields("myapp", "myhost", "UTC", 12345)

	out, err := cf.Format(testTime, "user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}, testDef, nil)
	require.NoError(t, err)
	s := string(out)

	// Skip the 7-pipe header. CEF format:
	// CEF:0|Vendor|Product|Version|EventType|Description|Severity|
	// extensions...
	idx := 0
	for i := 0; i < 7; i++ {
		next := strings.IndexByte(s[idx:], '|')
		require.GreaterOrEqual(t, next, 0,
			"malformed CEF header — only %d pipes found in %q", i, s)
		idx += next + 1
	}
	ext := s[idx:]

	// First extension is rt=<epoch ms>; must NOT start with a space.
	require.True(t, strings.HasPrefix(ext, "rt="),
		"extensions must start with rt= (no leading space); got %q",
		ext[:min(20, len(ext))])

	// Second extension (act=<eventType>) must be preceded by exactly
	// one space — pinning the writeExtField separator guard.
	rtEnd := strings.IndexByte(ext, ' ')
	require.GreaterOrEqual(t, rtEnd, 0,
		"no space found after rt= field; extension run was: %q", ext)
	require.True(t, strings.HasPrefix(ext[rtEnd+1:], "act="),
		"act= must immediately follow the space after rt=...; got %q",
		ext[rtEnd:min(rtEnd+30, len(ext))])

	// Sanity: every key=value pair beyond the first MUST be preceded
	// by EXACTLY one space (not zero, not two). If the writeExtField
	// guard mutates to skip the space, two extensions concatenate
	// (zero spaces); a hypothetical regression that doubled the
	// separator would fail the "no double space" check below.
	for _, key := range []string{"act", "dvchost", "dtz", "dvcpid"} {
		single := " " + key + "="
		double := "  " + key + "="
		assert.Contains(t, s, single,
			"extension %q must appear with exactly one leading space; full output: %s",
			single, s)
		assert.NotContains(t, s, double,
			"extension %q must NOT have a doubled separator; full output: %s",
			double, s)
	}
}
