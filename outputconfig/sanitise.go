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

package outputconfig

import "strings"

// sanitizeParserErrorMsg replaces C0/C1 control bytes and DEL in the
// third-party YAML parser's error message with a Unicode replacement
// character so downstream log consumers cannot be log-injected by an
// adversarial consumer submitting YAML with embedded NUL / CR / LF.
// Mirrors the helper of the same name in the core audit package.
// Surfaced by FuzzOutputConfigLoad (#481).
func sanitizeParserErrorMsg(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteRune('\uFFFD')
		case r >= 0x80 && r <= 0x9f:
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
