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

// Package sha provides strict validation for git commit SHAs.
//
// The validator exists because gh CLI's `--jq` flag is silently
// bypassed on HTTP error responses: a 404 against
// `gh api .../git/ref/heads/<branch> --jq '.object.sha'` does not
// produce empty output — it dumps the raw error JSON body to stdout.
// Naïve callers (including the v0.2.1 bash commit helper)
// treated the error JSON as a SHA and forwarded it into the next
// API call, producing opaque silent failures. v0.2.1 release runs
// 26889155834 and 26894419954 tripped exactly this. Always pass any
// captured-as-SHA string through [IsValid] before using it.
package sha

import "regexp"

// shaPattern matches an exact-40-char lowercase hex git commit SHA.
// Uppercase and mixed-case are explicitly rejected — go-github and
// the GitHub REST API always return lowercase, and accepting other
// cases would mask upstream encoding bugs.
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsValid reports whether s is exactly 40 lowercase hexadecimal
// characters with no surrounding whitespace.
//
// Empty input, leading/trailing whitespace, uppercase letters,
// non-hex characters, and strings of the wrong length all return
// false.
func IsValid(s string) bool {
	return shaPattern.MatchString(s)
}
