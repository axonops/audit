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
	"fmt"
	"regexp"
	"strings"
)

// identPattern restricts owner/repo/branch/tag flag values to a
// conservative subset of ASCII. Justifies the no-validation
// behaviour of the underlying GitHub API by refusing anything that
// could carry a newline / control character / URL-encoded escape
// into the API URL or into the stderr log stream (security review
// W2 / log injection).
//
// Allowed: ASCII letters, digits, underscore, dot, hyphen, slash.
// GitHub owners/repos themselves only allow [A-Za-z0-9-_], but
// branches and tags permit slashes (release/v0.2.2) and dots
// (v0.2.2). One conservative regex covers all four.
var identPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// validateIdent enforces identPattern on a flag value. Used for
// --owner, --repo, --branch, --tag.
//
// In addition to the regex, structurally suspicious values are
// refused even though they technically match: the bare strings ".",
// "..", "/", any path segment that is ".." (so "release/../main"
// can not reach the API), and values that start with a leading
// character that breaks downstream tooling (a leading "-" looks
// like a CLI flag; a leading "/" looks like an absolute path).
// Test-analyst I5.
func validateIdent(flag, value string) error {
	if !identPattern.MatchString(value) {
		return fmt.Errorf("%s must match %s, got %q",
			flag, identPattern.String(), truncateForDiag(value, 80))
	}
	if err := refuseStructurallyBadIdent(flag, value); err != nil {
		return err
	}
	return nil
}

// refuseStructurallyBadIdent applies the post-regex guards
// described on validateIdent. Pulled out so the tests can exercise
// each refusal class independently.
func refuseStructurallyBadIdent(flag, value string) error {
	if value == "." || value == ".." || value == "/" {
		return fmt.Errorf("%s must not be the literal %q (structurally invalid)", flag, value)
	}
	if value[0] == '-' || value[0] == '/' || value[0] == '.' {
		return fmt.Errorf("%s must not start with %q (got %q)", flag, value[:1], truncateForDiag(value, 80))
	}
	for _, seg := range strings.Split(value, "/") {
		if seg == "" {
			return fmt.Errorf("%s must not contain empty path segments (got %q)", flag, truncateForDiag(value, 80))
		}
		if seg == ".." {
			return fmt.Errorf("%s must not contain %q path segments (got %q)", flag, "..", truncateForDiag(value, 80))
		}
	}
	return nil
}

// validateMessage refuses control characters and newlines in commit
// or tag messages. The downstream API accepts them, but they create
// log-injection opportunities in CI stderr capture and in any
// downstream tool that parses the message line-by-line.
//
// Tabs and printable Unicode are fine.
func validateMessage(flag, value string) error {
	for _, r := range value {
		if r == '\n' || r == '\r' {
			return fmt.Errorf("%s must not contain newlines (got line break in %q)",
				flag, truncateForDiag(value, 80))
		}
		// Refuse all C0 control characters except tab.
		if r < 0x20 && r != '\t' {
			return fmt.Errorf("%s must not contain control character U+%04X",
				flag, r)
		}
	}
	return nil
}
