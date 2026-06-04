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

package sha_test

import (
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/sha"
)

func TestIsValid_Empty(t *testing.T) {
	t.Parallel()
	if sha.IsValid("") {
		t.Error("empty string must not be valid")
	}
}

func TestIsValid_39Chars(t *testing.T) {
	t.Parallel()
	if sha.IsValid("0123456789abcdef0123456789abcdef0123456") {
		t.Error("39-char input must not be valid")
	}
}

func TestIsValid_40Chars_Lowercase(t *testing.T) {
	t.Parallel()
	if !sha.IsValid("0123456789abcdef0123456789abcdef01234567") {
		t.Error("40-char lowercase hex must be valid")
	}
}

func TestIsValid_40Chars_Uppercase(t *testing.T) {
	t.Parallel()
	// Uppercase is intentionally rejected — GitHub API always returns
	// lowercase, so uppercase would mask an upstream encoding bug.
	if sha.IsValid("0123456789ABCDEF0123456789ABCDEF01234567") {
		t.Error("40-char uppercase hex must not be valid")
	}
}

func TestIsValid_40Chars_Mixed(t *testing.T) {
	t.Parallel()
	if sha.IsValid("0123456789AbCdEf0123456789aBcDeF01234567") {
		t.Error("40-char mixed-case must not be valid")
	}
}

func TestIsValid_41Chars(t *testing.T) {
	t.Parallel()
	if sha.IsValid("0123456789abcdef0123456789abcdef012345678") {
		t.Error("41-char input must not be valid")
	}
}

func TestIsValid_NonHex(t *testing.T) {
	t.Parallel()
	cases := []string{
		"0123456789abcdef0123456789abcdef0123456g", // 'g' at end
		"z123456789abcdef0123456789abcdef01234567", // 'z' at start
		"0123456789abcdef0123456789abcdef0123456 ", // trailing space inside 40 chars
	}
	for _, c := range cases {
		if sha.IsValid(c) {
			t.Errorf("non-hex input %q must not be valid", c)
		}
	}
}

func TestIsValid_LeadingTrailingWhitespace(t *testing.T) {
	t.Parallel()
	cases := []string{
		" 0123456789abcdef0123456789abcdef01234567",
		"0123456789abcdef0123456789abcdef01234567 ",
		"\t0123456789abcdef0123456789abcdef01234567",
		"0123456789abcdef0123456789abcdef01234567\n",
	}
	for _, c := range cases {
		if sha.IsValid(c) {
			t.Errorf("whitespace-padded input %q must not be valid", c)
		}
	}
}

func TestIsValid_GitHubErrorJSONIsRejected(t *testing.T) {
	t.Parallel()
	// Regression for #910 / #911. gh CLI on a 404 returns the raw
	// error JSON body to stdout; the bash script captured it verbatim
	// and forwarded it as a "SHA".
	errJSON := `{"message":"Not Found","documentation_url":"https://docs.github.com/rest","status":"404"}`
	if sha.IsValid(errJSON) {
		t.Error("GitHub error JSON body must not be accepted as a SHA")
	}
}
