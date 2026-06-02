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

package webhook

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
)

// benchOutputMetricsWebhook is a minimal OutputMetrics for benching
// the per-batch dispatch helpers.
type benchOutputMetricsWebhook struct {
	audit.NoOpOutputMetrics
	flushes  atomic.Int64
	flushSum atomic.Int64
	drops    atomic.Int64
}

func (b *benchOutputMetricsWebhook) RecordFlush(batchSize int, _ time.Duration) {
	b.flushes.Add(1)
	b.flushSum.Add(int64(batchSize))
}

func (b *benchOutputMetricsWebhook) RecordDrop(count int) {
	b.drops.Add(int64(count))
}

// BenchmarkWebhook_BatchPOST_50 measures the per-batch recordSuccess
// dispatch overhead at the typical batchSize=50 used by the example
// outputs.yaml. Before #894 this walked a 50-event RecordDelivery
// loop; after #894 it makes a single RecordFlush call.
func BenchmarkWebhook_BatchPOST_50(b *testing.B) {
	om := &benchOutputMetricsWebhook{}
	out := &Output{
		name:          "bench-output",
		outputMetrics: om,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out.recordSuccess(50, 100*time.Microsecond)
	}
}
