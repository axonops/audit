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

// Internal-package hot-path micro-benchmarks (#502). Live in this
// file — not audit_test.go — because they target unexported
// helpers. Every benchmark calls b.ReportAllocs() and is added to
// bench-baseline.txt so future regressions surface through
// make bench-compare.

package audit

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------
// Small taxonomy / event definition used by the field-path benches.
// Kept local (no internal/testhelper import because that package
// uses the public API and would create a cycle from this internal
// _test file).
// ---------------------------------------------------------------

func benchTaxonomy() *Taxonomy {
	return &Taxonomy{
		Categories: map[string]*CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*EventDef{
			"user_create": {
				Required: []string{"outcome", "actor_id", "subject"},
				Optional: []string{"reason", "request_id"},
			},
		},
	}
}

func benchAuditor(b *testing.B) *Auditor {
	b.Helper()
	tax := benchTaxonomy()
	a := &Auditor{taxonomy: tax}
	a.cfg.ValidationMode = ValidationPermissive
	return a
}

func benchAuditorStrict(b *testing.B) *Auditor {
	b.Helper()
	a := &Auditor{taxonomy: benchTaxonomy()}
	a.cfg.ValidationMode = ValidationStrict
	return a
}

func benchEventDef() *EventDef {
	return benchTaxonomy().Events["user_create"]
}

// ---------------------------------------------------------------
// validateFields benchmarks
// ---------------------------------------------------------------

// BenchmarkValidateFields_Success measures the happy path —
// all required fields present, no unknowns.
func BenchmarkValidateFields_Success(b *testing.B) {
	a := benchAuditor(b)
	def := benchEventDef()
	fields := Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "schema-topic",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := a.validateFields("user_create", def, fields); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateFields_MissingRequired measures the early-
// error path — caller forgot a required field.
func BenchmarkValidateFields_MissingRequired(b *testing.B) {
	a := benchAuditor(b)
	def := benchEventDef()
	fields := Fields{
		"outcome":  "success",
		"actor_id": "alice",
		// "subject" intentionally missing
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := a.validateFields("user_create", def, fields); err == nil {
			b.Fatal("expected missing-required error")
		}
	}
}

// BenchmarkCheckUnknownFields_Strict measures the unknown-field
// path in strict mode (where unknowns are errors).
func BenchmarkCheckUnknownFields_Strict(b *testing.B) {
	a := benchAuditorStrict(b)
	def := benchEventDef()
	fields := Fields{
		"outcome":      "success",
		"actor_id":     "alice",
		"subject":      "schema-topic",
		"unknown_key1": "v1",
		"unknown_key2": "v2",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := a.checkUnknownFields("user_create", def, fields); err == nil {
			b.Fatal("expected unknown-field error in strict mode")
		}
	}
}

// BenchmarkCheckUnknownFields_Permissive measures the permissive
// path (default) where unknowns are ignored.
func BenchmarkCheckUnknownFields_Permissive(b *testing.B) {
	a := benchAuditor(b) // strictValidation: false
	def := benchEventDef()
	fields := Fields{
		"outcome":      "success",
		"actor_id":     "alice",
		"subject":      "schema-topic",
		"unknown_key1": "v1",
		"unknown_key2": "v2",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := a.checkUnknownFields("user_create", def, fields); err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------
// copyFieldsWithDefaults — sub-benchmarks across field counts
// ---------------------------------------------------------------

// BenchmarkCopyFieldsWithDefaults runs the defensive-copy helper
// over progressively larger field maps. Allocations here scale
// with field count because each value is boxed through `any`.
func BenchmarkCopyFieldsWithDefaults(b *testing.B) {
	a := benchAuditor(b)

	for _, n := range []int{3, 10, 20} {
		b.Run("Fields_"+itoa(n), func(b *testing.B) {
			fields := make(Fields, n)
			for i := 0; i < n; i++ {
				fields["f"+itoa(i)] = strings.Repeat("x", 8)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = a.copyFieldsWithDefaults(fields)
			}
		})
	}
}

// itoa is a tiny local replacement for strconv.Itoa so this file
// does not pull strconv into the internal test package just for
// sub-benchmark names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ---------------------------------------------------------------
// HMAC fast-path benchmark
// ---------------------------------------------------------------

// BenchmarkComputeHMACFast measures the pre-allocated drain-loop
// HMAC path with a 32-byte salt and a realistic event payload.
// No per-call allocation by construction (state pre-allocated).
func BenchmarkComputeHMACFast(b *testing.B) {
	cfg := &HMACConfig{
		Enabled:     true,
		Algorithm:   "HMAC-SHA-256",
		SaltVersion: "v1",
		SaltValue:   []byte("benchmark-salt-32-bytes-00000000"),
	}
	s := newHMACState(cfg)
	payload := []byte(`{"event_type":"user_create","outcome":"success","actor_id":"alice","subject":"schema-topic"}`)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		_ = s.computeHMACFast(payload)
	}
}
