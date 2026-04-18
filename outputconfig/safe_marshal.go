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

import (
	"fmt"

	yaml "github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// safeMarshal re-serialises a post-expansion value tree to YAML bytes
// while preserving the string semantics of every string leaf. It is a
// drop-in replacement for [yaml.Marshal] on post-envsubst / post-
// secrets-resolution trees that are about to be re-parsed into a
// factory-specific struct (#487).
//
// # Why this is load-bearing
//
// [expandEnvInValue] (and the secrets resolver) only replace string
// leaves; numbers, booleans, and nulls pass through untouched. After
// expansion a string value like `.inf`, `.NaN`, or (on older YAML 1.1
// parsers) `on`/`off` is a plain Go string — so a subsequent
// [yaml.Marshal] call emits it UNQUOTED if goccy/go-yaml does not
// consider it ambiguous, and the downstream [yaml.Unmarshal] re-reads
// it as `float64(+Inf)`, `bool(true)`, etc. This silently turns a
// string config value into the wrong Go type.
//
// safeMarshal wraps every string leaf in [quotedString], a type whose
// [MarshalYAML] returns an explicitly double-quoted [ast.StringNode].
// The emitted YAML therefore always quotes the scalar, and the
// downstream parser always reads it as a string. Numbers, booleans,
// and nulls are not wrapped and retain their Go types across the
// round-trip.
func safeMarshal(v any) ([]byte, error) {
	b, err := yaml.Marshal(wrapStringsForSafeMarshal(v))
	if err != nil {
		return nil, fmt.Errorf("outputconfig: safe marshal: %w", err)
	}
	return b, nil
}

// wrapStringsForSafeMarshal walks an arbitrary value tree rooted at v
// and returns a copy in which every string leaf is wrapped as a
// [quotedString]. Maps and slices are traversed recursively; other
// types pass through unchanged.
//
// The input tree is not mutated — a fresh map / slice is allocated so
// the caller can continue to use the original for further processing
// (for example, secrets-resolution passes after envsubst).
//
// # Invariant
//
// Inputs to this walker come exclusively from goccy/go-yaml's
// [yaml.Unmarshal] decoding into an untyped `any`, which produces
// only `string`, `map[string]any`, `[]any`, and scalar primitives
// (int, float64, bool, nil). If a future change introduces
// `yaml.MapSlice` or any other container shape post-decode, the
// `default` branch below would pass it through un-wrapped and re-
// open the #487 vulnerability. Extend the switch before merging any
// such change.
func wrapStringsForSafeMarshal(v any) any {
	switch val := v.(type) {
	case string:
		return quotedString(val)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			out[k] = wrapStringsForSafeMarshal(child)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			out[i] = wrapStringsForSafeMarshal(child)
		}
		return out
	default:
		// Scalars (int, float64, bool, nil) are not subject to the
		// YAML 1.1 magic-value coercion attack on round-trip because
		// their Go type is preserved by the underlying [yaml.Marshal]
		// call. See the invariant note above for the container-shape
		// risk.
		return v
	}
}

// quotedString is a string that, when marshalled to YAML, is always
// emitted as a double-quoted scalar — regardless of whether the value
// would otherwise be ambiguous under YAML 1.1 / 1.2 implicit typing.
//
// Implements [yaml.InterfaceMarshaler] by returning an [ast.StringNode]
// with an explicit [token.DoubleQuoteType] so goccy/go-yaml's encoder
// emits the scalar with quotes verbatim.
type quotedString string

// MarshalYAML emits q as a double-quoted YAML scalar. See the
// package-level safeMarshal godoc for the threat model.
func (q quotedString) MarshalYAML() (any, error) {
	return &ast.StringNode{
		BaseNode: &ast.BaseNode{},
		Token:    token.DoubleQuote("", string(q), nil),
		Value:    string(q),
	}, nil
}
