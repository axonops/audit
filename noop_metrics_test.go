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
	"sync/atomic"
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoOpMetrics_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	// Compile-time check (also verified by var _ in metrics.go).
	var m audit.Metrics = audit.NoOpMetrics{}
	_ = m
}

func TestNoOpMetrics_Embedding_OverrideSingleMethod(t *testing.T) {
	t.Parallel()

	type myMetrics struct {
		audit.NoOpMetrics
		drops atomic.Int64
	}
	m := &myMetrics{}

	// Verify it satisfies the interface.
	var _ audit.Metrics = m

	// Use it in a real logger.
	out := testhelper.NewMockOutput("test")
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithOutputs(out),
		audit.WithMetrics(m),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	// The embedded NoOpMetrics handles all other methods silently.
	assert.Equal(t, int64(0), m.drops.Load())
}

func TestNoOpOutputMetrics_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	// Compile-time check (also verified by var _ in metrics.go).
	var m audit.OutputMetrics = audit.NoOpOutputMetrics{}
	_ = m
}

func TestNoOpOutputMetrics_AllMethodsCallable(t *testing.T) {
	t.Parallel()

	var m audit.OutputMetrics = audit.NoOpOutputMetrics{}

	// All methods are callable without panic.
	m.RecordDrop()
	m.RecordFlush(10, 0)
	m.RecordError()
	m.RecordRetry(1)
	m.RecordQueueDepth(50, 100)
}

func TestNoOpMetrics_WithMetrics_Accepted(t *testing.T) {
	t.Parallel()
	logger, err := audit.NewLogger(
		audit.WithTaxonomy(testhelper.ValidTaxonomy()),
		audit.WithMetrics(audit.NoOpMetrics{}),
	)
	require.NoError(t, err)
	require.NoError(t, logger.Close())
}
