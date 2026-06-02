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

package audit_test

import (
	"reflect"
	"testing"

	"github.com/axonops/audit"
)

// Note: TestEventStatus_WireFormat_Stable, TestEventStatus_TypeCompatibility,
// and TestNoOpMetrics_RecordDelivery_AcceptsTypedStatus removed in #894
// alongside audit.EventStatus / audit.EventSuccess / audit.EventError /
// audit.Metrics.RecordDelivery. Per-output delivery counts now flow
// through OutputMetrics.RecordFlush (batchSize sum) and OutputMetrics
// .RecordError (event count), which have their own coverage in
// audittest/output_metrics_test.go and per-output integration tests.

// TestNoOpMetrics_AllMethodsArePresent reflects over the
// [audit.Metrics] interface method set and asserts that
// [audit.NoOpMetrics] has a method for every entry. The test guards
// the forward-compatibility promise in the Metrics godoc: consumers
// who embed [audit.NoOpMetrics] must retain a working no-op
// implementation of every base-interface method without writing any
// code themselves. If a future PR adds a method to [audit.Metrics]
// without adding the matching NoOpMetrics method, this test fails.
// See ADR 0005 (docs/adr/0005-metrics-interface-shape.md).
func TestNoOpMetrics_AllMethodsArePresent(t *testing.T) {
	t.Parallel()

	metricsType := reflect.TypeOf((*audit.Metrics)(nil)).Elem()
	noOpType := reflect.TypeOf(audit.NoOpMetrics{})

	for i := 0; i < metricsType.NumMethod(); i++ {
		name := metricsType.Method(i).Name
		if _, ok := noOpType.MethodByName(name); !ok {
			t.Errorf("NoOpMetrics is missing method %q required by audit.Metrics — "+
				"add a no-op implementation in metrics.go to preserve the forward-"+
				"compatibility embed pattern (ADR 0005)", name)
		}
	}
}
