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

package audittest_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

func TestOutputMetricsRecorder_Implements(t *testing.T) {
	t.Parallel()
	var _ audit.OutputMetrics = (*audittest.OutputMetricsRecorder)(nil)
}

func TestOutputMetricsRecorder_AllMethods(t *testing.T) {
	t.Parallel()
	m := audittest.NewOutputMetricsRecorder()

	m.RecordDrop()
	m.RecordDrop()
	m.RecordFlush(10, 5*time.Millisecond)
	m.RecordError()
	m.RecordRetry(1)
	m.RecordRetry(2)
	m.RecordQueueDepth(5, 100) // no-op, should not panic

	assert.Equal(t, 2, m.DropCount())
	assert.Equal(t, 1, m.FlushCount())
	assert.Equal(t, 1, m.ErrorCount())
	assert.Equal(t, 2, m.RetryCount())
}

func TestOutputMetricsRecorder_Reset(t *testing.T) {
	t.Parallel()
	m := audittest.NewOutputMetricsRecorder()

	m.RecordDrop()
	m.RecordFlush(5, time.Millisecond)
	m.RecordError()
	m.RecordRetry(1)

	m.Reset()

	assert.Equal(t, 0, m.DropCount())
	assert.Equal(t, 0, m.FlushCount())
	assert.Equal(t, 0, m.ErrorCount())
	assert.Equal(t, 0, m.RetryCount())
}
