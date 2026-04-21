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

// Benchmarks for the outputconfig package (#504 AC #2 / AC #3;
// master tracker C-19). Isolated from outputconfig_test.go so the
// ~2800-line test file does not gain a benchmarks section.

package outputconfig_test

import (
	"context"
	_ "embed"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/file" // register "file" output type
	"github.com/axonops/audit/outputconfig"
)

//go:embed testdata/bench_config.yaml
var benchConfigYAML []byte

// BenchmarkOutputConfigLoad baselines the full startup cost of
// [outputconfig.Load] on a realistic 4-output fixture: stdout plus
// three file outputs with routing (category/event-type/severity),
// HMAC, sensitivity labels, envsubst, standard-field defaults, and
// an auditor block (#504 AC #2/#3).
//
// Load is a startup-only cost for most consumers (one call at boot)
// but some operators reload config dynamically — the absolute number
// is therefore a useful baseline, not a hot-path figure. The loop
// body calls Load, asserts the expected output count, then releases
// the result (via explicit output Close below). The final Close is
// batched outside the timer so HTTP/TCP dialer teardown noise does
// not contaminate the measured Load cost.
//
// Fixture deliberately uses only output types whose factory is
// already in this module's go.mod (audit + audit/file). Adding
// syslog/loki/webhook here would pull extra dependencies into
// outputconfig for a single benchmark.
func BenchmarkOutputConfigLoad(b *testing.B) {
	tax := benchTaxonomy(b)
	// b.Setenv auto-cleans after the benchmark; no leak into
	// subsequent benchmarks in the same test binary.
	b.Setenv("AUDIT_TEST_DIR", b.TempDir())

	ctx := context.Background()
	// Retain only the closers per iteration, not the full
	// *LoadResult graph. Holding the full result would inflate
	// heap retention by ~1.23 MiB × b.N and contaminate the
	// measurement with GC pressure that does not exist in real
	// callers. 4 closers per iter sized against a 4-output fixture.
	closers := make([]audit.Output, 0, 4*1024)
	var lastOutputCount int
	// Silence diagnostic warnings from Load (construction-time
	// permission checks on 0640 mode, etc.) so the bench output
	// stays clean.
	silent := slog.New(slog.NewTextHandler(io.Discard, nil))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := outputconfig.Load(ctx, benchConfigYAML, tax,
			outputconfig.WithDiagnosticLogger(silent))
		if err != nil {
			b.Fatal(err)
		}
		lastOutputCount = len(res.Outputs)
		for _, no := range res.Outputs {
			closers = append(closers, no.Output)
		}
	}
	b.StopTimer()

	// Safety assertion: prove Load actually constructed all four
	// outputs, guarding against a silent-empty-return regression
	// that could read as a free perf win.
	require.Equal(b, 4, lastOutputCount,
		"expected 4 outputs from bench_config.yaml; got %d", lastOutputCount)

	// Release every constructed output outside the timer. File
	// outputs hold OS file handles; without Close the bench would
	// exhaust the Linux per-process fd limit on long runs.
	for _, o := range closers {
		_ = o.Close()
	}
}

// benchTaxonomy constructs a taxonomy covering every category and
// event_type referenced by bench_config.yaml's route blocks.
// Constructed programmatically (not via ParseTaxonomyYAML) to keep
// the benchmark setup cost out of the measured critical path.
func benchTaxonomy(b *testing.B) *audit.Taxonomy {
	b.Helper()
	required := []string{"outcome", "actor_id"}
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":      {Events: []string{"user_create", "user_update", "user_delete"}},
			"security":   {Events: []string{"auth_failure", "auth_success"}},
			"compliance": {Events: []string{"data_export", "bulk_delete"}},
			"read":       {Events: []string{"user_read"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":  {Required: required},
			"user_update":  {Required: required},
			"user_delete":  {Required: required},
			"auth_failure": {Required: required},
			"auth_success": {Required: required},
			"data_export":  {Required: required},
			"bulk_delete":  {Required: required},
			"user_read":    {Required: required},
		},
	}
}
