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

package main

import (
	"testing"
	"unicode/utf8"
)

func TestValidateIdent_Accept(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"axonops",
		"audit",
		"release/v0.2.2",
		"v0.2.2",
		"feature/new-thing",
		"some.module-name",
	} {
		if err := validateIdent("--owner", value); err != nil {
			t.Errorf("validateIdent rejected legitimate value %q: %v", value, err)
		}
	}
}

func TestValidateIdent_Reject(t *testing.T) {
	t.Parallel()
	// W2 regression cases: newline injection, control chars,
	// shell metacharacters, spaces.
	for _, value := range []string{
		"",                       // empty
		"foo\ninjected-log-line", // log injection
		"foo bar",                // space
		"foo;rm -rf /",           // shell metacharacter
		"foo\x00bar",             // NUL byte
		"foo\x1b[31mred\x1b[0m",  // ANSI escape
		"foo\rcarriage-return",   // CR
		"axonops/audit?ref=evil", // URL query
	} {
		if err := validateIdent("--owner", value); err == nil {
			t.Errorf("validateIdent must reject %q (W2 log-injection regression)", value)
		}
	}
}

// TestValidateIdent_RejectStructurallyInvalid covers analyst I5:
// the regex on its own admits "..", "/", leading "-" (flag-looking),
// and "release/../main" (traversal-shaped). All are refused.
func TestValidateIdent_RejectStructurallyInvalid(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		".",               // literal dot — regex passes but structurally invalid
		"..",              // literal double-dot — traversal-shaped
		"/",               // literal slash
		"-pre-release",    // leading hyphen — looks like a CLI flag downstream
		"/abs",            // leading slash — looks like an absolute path
		".hidden",         // leading dot — looks like a hidden file
		"release/../main", // traversal segment
		"release/main/..", // trailing traversal
		"release//main",   // empty segment
	} {
		if err := validateIdent("--branch", value); err == nil {
			t.Errorf("validateIdent must reject structurally invalid %q (I5)", value)
		}
	}
}

func TestValidateMessage_Accept(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"chore: pin deps for v0.2.2",
		"Release v0.2.2",
		"Multi-word\ttab-separated message",
	} {
		if err := validateMessage("--message", value); err != nil {
			t.Errorf("validateMessage rejected legitimate value %q: %v", value, err)
		}
	}
}

// TestTruncateForDiag_UTF8Safe locks the rune-boundary trim for
// test-analyst N2. A naive byte-slice would emit invalid UTF-8 in
// stderr if the cut point landed mid-character. The helper trims
// back to the nearest rune boundary so every diagnostic stays valid.
func TestTruncateForDiag_UTF8Safe(t *testing.T) {
	t.Parallel()
	// "é" is 2 bytes (C3 A9). With n=7 we cut between "Hello é" at
	// byte 7, which is the trailing byte (A9) of "é" — the result
	// must trim back to byte 6 to drop the orphaned C3.
	const input = "Hello é world"
	const n = 7
	got := truncateForDiag(input, n)
	if !utf8.ValidString(got) {
		t.Errorf("truncateForDiag emitted invalid UTF-8: %q (bytes=%x)", got, []byte(got))
	}
	// Short input must pass through unchanged.
	if truncateForDiag("short", 80) != "short" {
		t.Errorf("short input must round-trip unchanged")
	}
	// Exact-length input must pass through unchanged.
	if truncateForDiag("hi", 2) != "hi" {
		t.Errorf("len(s)==n input must round-trip unchanged")
	}
}

func TestValidateMessage_Reject(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"line one\nline two", // newline — log injection
		"carriage\rreturn",   // CR
		"control\x01char",    // C0 control
		"bell\x07char",       // bell
	} {
		if err := validateMessage("--message", value); err == nil {
			t.Errorf("validateMessage must reject %q (W2 log-injection regression)", value)
		}
	}
}
