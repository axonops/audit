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

package splunk

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
)

// benchOutputMetrics is a minimal OutputMetrics implementation for
// benchmarking the recordSuccess / recordDrop paths.
type benchOutputMetrics struct {
	audit.NoOpOutputMetrics
	flushes  atomic.Int64
	flushSum atomic.Int64
	drops    atomic.Int64
}

func (b *benchOutputMetrics) RecordFlush(batchSize int, _ time.Duration) {
	b.flushes.Add(1)
	b.flushSum.Add(int64(batchSize))
}

func (b *benchOutputMetrics) RecordDrop(count int) {
	b.drops.Add(int64(count))
}

// BenchmarkSplunk_RecordSuccess_5000 measures the per-batch
// recordSuccess overhead at the default BatchSize ceiling. Before
// #894 the call walked a per-event loop calling
// audit.Metrics.RecordDelivery 5000 times; after #894 it makes a
// single OutputMetrics.RecordFlush call with batchSize=5000. This
// benchmark locks the new behaviour and provides a baseline for
// future regressions.
//
// Compare against the previous implementation by running this
// benchmark at the HEAD before #894's commit `0ad7003` and using
// `benchstat`.
func BenchmarkSplunk_RecordSuccess_5000(b *testing.B) {
	om := &benchOutputMetrics{}
	out := &Output{
		name:          "bench-output",
		outputMetrics: om,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out.recordSuccess(5000, 100*time.Microsecond)
	}
}

// BenchmarkSplunk_RecordSuccess_500 measures the per-batch
// recordSuccess overhead at the conservative BatchSize=500 used by
// the example outputs.yaml. Companion to _5000.
func BenchmarkSplunk_RecordSuccess_500(b *testing.B) {
	om := &benchOutputMetrics{}
	out := &Output{
		name:          "bench-output",
		outputMetrics: om,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out.recordSuccess(500, 100*time.Microsecond)
	}
}

// BenchmarkSplunk_RecordDrop_5000 measures the recordDrop path for
// a worst-case batch drop at the BatchSize ceiling. Before #894 the
// call walked a per-event loop calling OutputMetrics.RecordDrop
// 5000 times; after #894 it makes a single
// OutputMetrics.RecordDrop(5000) call.
func BenchmarkSplunk_RecordDrop_5000(b *testing.B) {
	om := &benchOutputMetrics{}
	out := &Output{
		name:          "bench-output",
		outputMetrics: om,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out.recordDrop(5000)
	}
}
