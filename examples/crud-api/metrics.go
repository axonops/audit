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
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// auditMetrics implements all four go-audit metrics interfaces using
// Prometheus client_golang. A single struct satisfies everything via
// Go's structural duck-typing:
//
//   - audit.Metrics (7 methods)
//   - file.Metrics  (RecordFileRotation)
//   - syslog.Metrics (RecordSyslogReconnect)
//   - webhook.Metrics (RecordWebhookDrop, RecordWebhookFlush)
type auditMetrics struct {
	events              *prometheus.CounterVec
	outputErrors        *prometheus.CounterVec
	validationErrors    *prometheus.CounterVec
	filtered            *prometheus.CounterVec
	outputFiltered      *prometheus.CounterVec
	serializationErrors *prometheus.CounterVec
	bufferDrops         prometheus.Counter
	fileRotations       *prometheus.CounterVec
	syslogReconnects    *prometheus.CounterVec
	webhookDrops        prometheus.Counter
	webhookFlushDur     prometheus.Histogram
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

		syslogReconnects: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "audit_syslog_reconnects_total",
			Help: "Syslog reconnection attempts by address and success.",
		}, []string{"address", "success"}),

		webhookDrops: promauto.NewCounter(prometheus.CounterOpts{
			Name: "audit_webhook_drops_total",
			Help: "Webhook events dropped due to full buffer.",
		}),

		webhookFlushDur: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "audit_webhook_flush_duration_seconds",
			Help:    "Webhook batch flush duration.",
			Buckets: prometheus.DefBuckets,
		}),
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

// --- syslog.Metrics ---

func (m *auditMetrics) RecordSyslogReconnect(address string, success bool) {
	m.syslogReconnects.WithLabelValues(address, fmt.Sprintf("%t", success)).Inc()
}

// --- webhook.Metrics ---

func (m *auditMetrics) RecordWebhookDrop() {
	m.webhookDrops.Inc()
}

func (m *auditMetrics) RecordWebhookFlush(batchSize int, dur time.Duration) {
	_ = batchSize // could record as a separate metric
	m.webhookFlushDur.Observe(dur.Seconds())
}
