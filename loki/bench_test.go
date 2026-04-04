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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
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
