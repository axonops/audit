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

package audit

import (
	"bytes"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// TestAppendPostFieldJSONInto_PropertyEqualsAppendPostFields is the
// rigorous byte-equality proof that the W2 in-place JSON post-field
// append produces output byte-identical to the legacy copy-out
// implementation. Per test-analyst prescription for #497.
//
// Rapid generates random JSON-formatted base events and random
// sequences of PostField values; the property asserts that applying
// appendPostFieldJSONInto N times to a buffer pre-loaded with base
// bytes produces byte-identical output to appendPostFieldsJSON.
//
// Failure mode if regressed: the in-place truncate/append/restore
// sequence subtly diverges from the copy-path's append-string ordering,
// causing JSON malformation that breaks every downstream verifier
// (HMAC, JSON parser).
func TestAppendPostFieldJSONInto_PropertyEqualsAppendPostFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidJSONBase(t)
		fields := generatePostFields(t)

		// Reference: legacy copy-path (allocates fresh).
		want := appendPostFieldsJSON(base, fields)

		// Subject: W2 in-place path applied sequentially.
		buf := new(bytes.Buffer)
		buf.Write(base)
		var got []byte
		for _, f := range fields {
			got = appendPostFieldJSONInto(buf, f)
		}
		if len(fields) == 0 {
			got = buf.Bytes()
		}

		if !bytes.Equal(want, got) {
			t.Fatalf("in-place output diverges from copy-path output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// TestAppendPostFieldCEFInto_PropertyEqualsAppendPostFields is the
// CEF analogue of the JSON property. CEF terminates with \n only (no
// brace), so the truncate-and-restore semantics differ — both
// implementations must agree byte-for-byte on every base + field combo.
func TestAppendPostFieldCEFInto_PropertyEqualsAppendPostFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base := generateValidCEFBase(t)
		fields := generatePostFields(t)

		want := appendPostFieldsCEF(base, fields)

		buf := new(bytes.Buffer)
		buf.Write(base)
		var got []byte
		for _, f := range fields {
			got = appendPostFieldCEFInto(buf, f)
		}
		if len(fields) == 0 {
			got = buf.Bytes()
		}

		if !bytes.Equal(want, got) {
			t.Fatalf("in-place CEF output diverges from copy-path output\nbase  = %q\nfields= %#v\nwant  = %q\ngot   = %q",
				base, fields, want, got)
		}
	})
}

// generateValidJSONBase produces a JSON-formatted event terminated
// with "}\n", matching the contract appendPostFieldJSONInto / Json
// expects. Generated via the actual JSONFormatter so the bytes are
// guaranteed valid.
func generateValidJSONBase(t *rapid.T) []byte {
	jf := &JSONFormatter{}
	def := &EventDef{
		Required: []string{"outcome"},
		Optional: []string{"actor_id", "marker"},
	}
	def.knownFields = make(map[string]struct{}, 3)
	for _, k := range def.Required {
		def.knownFields[k] = struct{}{}
	}
	for _, k := range def.Optional {
		def.knownFields[k] = struct{}{}
	}
	def.sortedRequired = append([]string{}, def.Required...)
	def.sortedOptional = append([]string{}, def.Optional...)
	def.sortedAllKeys = []string{"actor_id", "marker", "outcome"}

	fields := Fields{
		"outcome": rapid.SampledFrom([]string{"success", "failure", "error"}).Draw(t, "outcome"),
	}
	if rapid.Bool().Draw(t, "withActor") {
		fields["actor_id"] = rapid.StringMatching("[a-zA-Z][a-zA-Z0-9_]{0,15}").Draw(t, "actor_id")
	}
	if rapid.Bool().Draw(t, "withMarker") {
		fields["marker"] = rapid.StringN(1, 32, 32).Draw(t, "marker")
	}

	out, err := jf.Format(time.Unix(1700000000, 0).UTC(), "test_event", fields, def, nil)
	if err != nil {
		t.Fatalf("JSON base generation: %v", err)
	}
	return out
}

// generateValidCEFBase produces a CEF-formatted event terminated with
// "\n" via the actual CEFFormatter.
func generateValidCEFBase(t *rapid.T) []byte {
	cf := &CEFFormatter{
		Vendor:  "axonops",
		Product: "audit",
		Version: "1.0",
	}
	def := &EventDef{
		Required: []string{"outcome"},
		Optional: []string{"actor_id", "marker"},
	}
	def.knownFields = make(map[string]struct{}, 3)
	for _, k := range def.Required {
		def.knownFields[k] = struct{}{}
	}
	for _, k := range def.Optional {
		def.knownFields[k] = struct{}{}
	}
	def.sortedRequired = append([]string{}, def.Required...)
	def.sortedOptional = append([]string{}, def.Optional...)
	def.sortedAllKeys = []string{"actor_id", "marker", "outcome"}

	fields := Fields{
		"outcome": rapid.SampledFrom([]string{"success", "failure", "error"}).Draw(t, "outcome"),
	}
	if rapid.Bool().Draw(t, "withActor") {
		fields["actor_id"] = rapid.StringMatching("[a-zA-Z][a-zA-Z0-9_]{0,15}").Draw(t, "actor_id")
	}
	if rapid.Bool().Draw(t, "withMarker") {
		fields["marker"] = rapid.StringN(1, 32, 32).Draw(t, "marker")
	}

	out, err := cf.Format(time.Unix(1700000000, 0).UTC(), "test_event", fields, def, nil)
	if err != nil {
		t.Fatalf("CEF base generation: %v", err)
	}
	return out
}

// generatePostFields produces 0..5 PostField values with keys drawn
// from a safe charset (matching SaltVersion validation: alphanumeric
// + ._:-) and values that are valid UTF-8 strings.
func generatePostFields(t *rapid.T) []PostField {
	n := rapid.IntRange(0, 5).Draw(t, "fieldCount")
	fields := make([]PostField, n)
	keyGen := rapid.StringMatching(`[A-Za-z][A-Za-z0-9._:\-]{0,15}`)
	valGen := rapid.StringN(0, 64, 64)
	for i := range fields {
		fields[i] = PostField{
			JSONKey: keyGen.Draw(t, "jsonKey"),
			CEFKey:  keyGen.Draw(t, "cefKey"),
			Value:   valGen.Draw(t, "value"),
		}
	}
	return fields
}
