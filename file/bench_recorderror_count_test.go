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

package file_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
)

// benchFileMetrics is a minimal OutputMetrics for benchmarking the
// per-batch RecordError(count) dispatch.
type benchFileMetrics struct {
	audit.NoOpOutputMetrics
	errors atomic.Int64
	drops  atomic.Int64
}

func (b *benchFileMetrics) RecordError(count int)              { b.errors.Add(int64(count)) }
func (b *benchFileMetrics) RecordDrop(count int)               { b.drops.Add(int64(count)) }
func (b *benchFileMetrics) RecordFlush(_ int, _ time.Duration) {}

// BenchmarkFile_WriteBatch_10000 measures the per-batch
// OutputMetrics.RecordError(count) dispatch overhead at the worst-
// case batch size for the file output. Before #894 the writeLoop
// failure path called om.RecordError() once and the dropped events
// were never accounted; after #894 the single RecordError(10000)
// call carries the event-accurate failure count for the entire
// batch. This benchmark locks the per-batch dispatch overhead.
func BenchmarkFile_WriteBatch_10000(b *testing.B) {
	var om audit.OutputMetrics = &benchFileMetrics{}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		om.RecordError(10000)
	}
}
