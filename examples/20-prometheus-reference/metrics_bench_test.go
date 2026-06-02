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
	"time"

	"github.com/axonops/audit"
)

// benchMetricsOnce caches a single auditMetrics instance across
// benchmarks. The Prometheus default registry rejects duplicate
// collector registrations, so the second invocation of newMetrics
// would panic. Sharing one instance is safe because each benchmark
// only exercises read+increment on its own scoped OutputMetrics.
var (
	benchMetrics        *auditMetrics
	benchMetricsFactory audit.OutputMetricsFactory
)

func setupBenchMetrics() audit.OutputMetricsFactory {
	if benchMetrics == nil {
		benchMetrics = newMetrics()
		benchMetricsFactory = benchMetrics.newOutputMetricsFactory()
	}
	return benchMetricsFactory
}

// BenchmarkPrometheus_RecordFlush measures the per-batch RecordFlush
// dispatch overhead on the Prometheus reference adapter. RecordFlush
// is the canonical "delivered events" signal post-#894 — its cost
// determines the per-batch metric overhead operators incur on the
// hot path.
func BenchmarkPrometheus_RecordFlush(b *testing.B) {
	factory := setupBenchMetrics()
	om := factory("file", "bench-output-flush")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		om.RecordFlush(500, 100*time.Microsecond)
	}
}

// BenchmarkPrometheus_RecordError_Count measures the per-batch
// RecordError(count) dispatch overhead. The post-#894 signature
// carries the per-batch event count as a single argument; the
// Prometheus adapter forwards it as Add(float64(count)). The
// benchmark proves the float64 conversion is allocation-free and
// the dispatch is dominated by the underlying Prometheus counter
// vector lookup.
func BenchmarkPrometheus_RecordError_Count(b *testing.B) {
	factory := setupBenchMetrics()
	var om audit.OutputMetrics = factory("file", "bench-output-error")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		om.RecordError(1000)
	}
}
