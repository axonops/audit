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
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// auditMetrics implements all three audit metrics interfaces using
// Prometheus client_golang. A single struct satisfies everything via
// Go's structural duck-typing:
//
//   - audit.Metrics (7 methods)
//   - file.Metrics  (RecordFileRotation)
//   - loki.Metrics  (RecordLokiDrop, RecordLokiFlush, RecordLokiRetry, RecordLokiError)
type auditMetrics struct {
	events              *prometheus.CounterVec
	outputErrors        *prometheus.CounterVec
	validationErrors    *prometheus.CounterVec
	filtered            *prometheus.CounterVec
	outputFiltered      *prometheus.CounterVec
	serializationErrors *prometheus.CounterVec
	bufferDrops         prometheus.Counter
	fileRotations       *prometheus.CounterVec
	lokiDrops           prometheus.Counter
	lokiFlushDur        prometheus.Histogram
	lokiFlushBatch      prometheus.Histogram
	lokiRetries         *prometheus.CounterVec
	lokiErrors          *prometheus.CounterVec
}

func newMetrics() *auditMetrics {
	return &auditMetrics{
		events: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_events_total",
			Help: "Total audit events by output and status.",
		}, []string{"output", "status"}),

		outputErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_output_errors_total",
			Help: "Output write errors by output name.",
		}, []string{"output"}),

		validationErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_validation_errors_total",
			Help: "Validation errors by event type.",
		}, []string{"event_type"}),

		filtered: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_filtered_total",
			Help: "Events filtered globally by event type.",
		}, []string{"event_type"}),

		outputFiltered: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_output_filtered_total",
			Help: "Events filtered per output.",
		}, []string{"output"}),

		serializationErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_serialization_errors_total",
			Help: "Serialization errors by event type.",
		}, []string{"event_type"}),

		bufferDrops: promauto.NewCounter(prometheus.CounterOpts{
			Name: "audit_buffer_drops_total",
			Help: "Events dropped due to full buffer.",
		}),

		fileRotations: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_file_rotations_total",
			Help: "File rotations by path.",
		}, []string{"path"}),

		lokiDrops: promauto.NewCounter(prometheus.CounterOpts{
			Name: "audit_loki_drops_total",
			Help: "Loki events dropped due to full buffer or retries exhausted.",
		}),

		lokiFlushDur: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "audit_loki_flush_duration_seconds",
			Help:    "Loki batch flush duration.",
			Buckets: prometheus.DefBuckets,
		}),

		lokiFlushBatch: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "audit_loki_flush_batch_size",
			Help:    "Number of events per Loki batch flush.",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250},
		}),

		lokiRetries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_loki_retries_total",
			Help: "Loki push retries by status code.",
		}, []string{"status_code", "attempt"}),

		lokiErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_loki_errors_total",
			Help: "Loki non-retryable errors by status code.",
		}, []string{"status_code"}),
	}
}

// --- audit.Metrics ---

func (m *auditMetrics) RecordEvent(output, status string) {
	m.events.WithLabelValues(output, status).Inc()
}

func (m *auditMetrics) RecordOutputError(output string) {
	m.outputErrors.WithLabelValues(output).Inc()
}

func (m *auditMetrics) RecordValidationError(eventType string) {
	m.validationErrors.WithLabelValues(eventType).Inc()
}

func (m *auditMetrics) RecordFiltered(eventType string) {
	m.filtered.WithLabelValues(eventType).Inc()
}

func (m *auditMetrics) RecordOutputFiltered(output string) {
	m.outputFiltered.WithLabelValues(output).Inc()
}

func (m *auditMetrics) RecordSerializationError(eventType string) {
	m.serializationErrors.WithLabelValues(eventType).Inc()
}

func (m *auditMetrics) RecordBufferDrop() {
	m.bufferDrops.Inc()
}

// --- file.Metrics ---

func (m *auditMetrics) RecordFileRotation(path string) {
	m.fileRotations.WithLabelValues(path).Inc()
}

// --- loki.Metrics ---

func (m *auditMetrics) RecordLokiDrop() {
	m.lokiDrops.Inc()
}

func (m *auditMetrics) RecordLokiFlush(batchSize int, dur time.Duration) {
	m.lokiFlushBatch.Observe(float64(batchSize))
	m.lokiFlushDur.Observe(dur.Seconds())
}

func (m *auditMetrics) RecordLokiRetry(statusCode, attempt int) {
	m.lokiRetries.WithLabelValues(
		strconv.Itoa(statusCode),
		strconv.Itoa(attempt),
	).Inc()
}

func (m *auditMetrics) RecordLokiError(statusCode int) {
	m.lokiErrors.WithLabelValues(strconv.Itoa(statusCode)).Inc()
}
