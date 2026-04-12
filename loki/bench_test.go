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

package loki_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

func BenchmarkWriteWithMetadata(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = 100000 // large buffer to avoid drops during bench
	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	data := []byte(`{"actor_id":"alice","action":"login","resource":"session"}`)
	meta := audit.EventMetadata{
		EventType: "user_login",
		Severity:  6,
		Category:  "authentication",
		Timestamp: time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = out.WriteWithMetadata(data, meta)
	}
}

// BenchmarkLokiOutput_BatchBuild benchmarks the stream grouping and
// JSON payload construction path. 100 events across 5 event types
// exercises the stream map, key builder, and JSON serialiser.
func BenchmarkLokiOutput_BatchBuild(b *testing.B) {
	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	events := make([]loki.TestEvent, 100)
	eventTypes := []string{"user_create", "auth_failure", "config_update", "user_delete", "permission_denied"}
	for i := range events {
		events[i] = loki.TestEvent{
			Data: []byte(fmt.Sprintf(`{"actor_id":"actor-%d","outcome":"success","resource":"res-%d"}`, i, i)),
			Meta: audit.EventMetadata{
				EventType: eventTypes[i%len(eventTypes)],
				Severity:  6,
				Category:  "security",
				Timestamp: ts.Add(time.Duration(i) * time.Millisecond),
			},
		}
	}

	input := loki.TestPayloadInput{
		Events:  events,
		AppName: "bench-app",
		Host:    "bench-host",
		PID:     12345,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = loki.BuildTestPayload(b, input)
	}
}

// BenchmarkLokiOutput_Gzip benchmarks gzip compression of a realistic
// push payload. Compared with BenchmarkLokiOutput_BatchBuild, the
// difference isolates the gzip overhead.
func BenchmarkLokiOutput_Gzip(b *testing.B) {
	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	events := make([]loki.TestEvent, 100)
	for i := range events {
		events[i] = loki.TestEvent{
			Data: []byte(fmt.Sprintf(`{"actor_id":"actor-%d","outcome":"success","target_id":"resource-%d"}`, i, i)),
			Meta: audit.EventMetadata{
				EventType: "user_create",
				Severity:  6,
				Category:  "write",
				Timestamp: ts.Add(time.Duration(i) * time.Millisecond),
			},
		}
	}

	input := loki.TestPayloadInput{
		Events:   events,
		Compress: true,
		AppName:  "bench-app",
		Host:     "bench-host",
		PID:      12345,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = loki.BuildTestCompressedPayload(b, input)
	}
}

// BenchmarkLokiOutput_MetadataWriter benchmarks the full
// WriteWithMetadata path including data copy and channel enqueue.
// This represents the per-event cost on the drain goroutine.
func BenchmarkLokiOutput_MetadataWriter(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = 100000
	cfg.BatchSize = 1000
	cfg.FlushInterval = 60 * time.Second // don't flush by timer during bench
	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	out.SetFrameworkFields("bench-app", "bench-host", "UTC", 12345)
	defer func() { _ = out.Close() }()

	// Realistic audit event payload (~200 bytes).
	data := []byte(`{"event_type":"user_create","outcome":"success","actor_id":"alice","target_id":"user-42","resource":"users","description":"Created user account"}`)
	meta := audit.EventMetadata{
		EventType: "user_create",
		Severity:  6,
		Category:  "write",
		Timestamp: time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_ = out.WriteWithMetadata(data, meta)
	}
}

func BenchmarkLokiBackoff(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = loki.LokiBackoff(3)
	}
}

func BenchmarkParseRetryAfter(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = loki.ParseRetryAfter("5")
	}
}
