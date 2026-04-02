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

// This file exports unexported functions for black-box testing.
package audit

import (
	"bytes"
	"strings"
)

var (
	CEFEscapeHeaderForTest            = cefEscapeHeader
	CEFEscapeExtValueForTest          = cefEscapeExtValue
	ValidateExtKeyForTest             = validateExtKey
	IsReservedStandardFieldForTest    = isReservedStandardField
	ReservedStandardFieldNamesForTest = reservedStandardFieldNames
)

// CEFEscapeHeaderOldForTest is the original multi-pass implementation,
// used only for property-based output equivalence testing.
func CEFEscapeHeaderOldForTest(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// CEFEscapeExtValueOldForTest is the original multi-pass implementation,
// used only for property-based output equivalence testing.
func CEFEscapeExtValueOldForTest(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	return s
}

// WriteJSONStringForTest exposes writeJSONString for property-based
// testing against encoding/json.Marshal.
func WriteJSONStringForTest(buf *bytes.Buffer, s string) {
	writeJSONString(buf, s)
}

// PrecomputeEventDefForTest exposes precomputeEventDef so benchmarks
// can use precomputed EventDefs that match production conditions.
var PrecomputeEventDefForTest = precomputeEventDef
