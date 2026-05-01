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

//go:build soak

package soak_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
)

// soakConfig is captured once at the start of BenchmarkSoak_MixedOutputs
// from environment variables; defaults reflect the AC-mandated 12 hour
// run with sustainable resource usage on a stable host.
type soakConfig struct {
	duration       time.Duration // total run time; SOAK_DURATION
	producers      int           // concurrent goroutines feeding the auditor; SOAK_PRODUCERS
	rate           int           // target events/sec across all producers; SOAK_RATE
	sampleInterval time.Duration // monitor sampler period; SOAK_SAMPLE_INTERVAL
	outputDir      string        // where samples + summary land; SOAK_OUTPUT_DIR
}

// loadSoakConfig parses environment variables. Each value carries a
// production-safe default so `make soak` runs with no env wiring.
func loadSoakConfig() soakConfig {
	c := soakConfig{
		duration:       12 * time.Hour,
		producers:      8,
		rate:           5000,
		sampleInterval: 1 * time.Minute,
		outputDir:      "./soak-output",
	}
	if v := os.Getenv("SOAK_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.duration = d
		}
	}
	if v := os.Getenv("SOAK_PRODUCERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.producers = n
		}
	}
	if v := os.Getenv("SOAK_RATE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.rate = n
		}
	}
	if v := os.Getenv("SOAK_SAMPLE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.sampleInterval = d
		}
	}
	if v := os.Getenv("SOAK_OUTPUT_DIR"); v != "" {
		c.outputDir = v
	}
	return c
}

// soakSample is one row in the CSV — one snapshot of runtime state at
// SOAK_SAMPLE_INTERVAL into the run.
type soakSample struct {
	elapsed       time.Duration
	heapAllocMB   float64
	heapSysMB     float64
	numGoroutine  int
	numGC         uint32
	pauseTotalMS  float64
	auditQueueLen int
	auditQueueCap int
	totalEvents   int64
	totalDrops    int64
}

// soakSummary is the JSON written at the end of the run; the maintainer
// pastes the start/end values into BENCHMARKS.md.
type soakSummary struct {
	StartedAt        time.Time     `json:"started_at"`
	EndedAt          time.Time     `json:"ended_at"`
	Duration         time.Duration `json:"duration"`
	Producers        int           `json:"producers"`
	TargetRate       int           `json:"target_rate_per_sec"`
	TotalEvents      int64         `json:"total_events"`
	TotalDrops       int64         `json:"total_drops"`
	StartHeapAllocMB float64       `json:"start_heap_alloc_mb"`
	EndHeapAllocMB   float64       `json:"end_heap_alloc_mb"`
	PeakHeapAllocMB  float64       `json:"peak_heap_alloc_mb"`
	StartGoroutines  int           `json:"start_goroutines"`
	EndGoroutines    int           `json:"end_goroutines"`
	PeakGoroutines   int           `json:"peak_goroutines"`
	SampleFile       string        `json:"sample_file"`
}

// BenchmarkSoak_MixedOutputs is the long-running soak driver (#573).
// It exercises the audit hot path with file + syslog (in-process TCP
// mock) + webhook (httptest.Server) outputs simultaneously, paces
// production via a token-bucket ticker to SOAK_RATE events/sec, and
// samples runtime memory + goroutine counts every SOAK_SAMPLE_INTERVAL.
//
// Drives via `-benchtime=<duration>` rather than the Go bench loop,
// because we want wall-clock not iteration-count semantics. The
// benchmark body runs ONE wall-clock-bounded inner pass per b.N
// iteration; b.N=1 is enforced via b.ResetTimer + early return after
// the first pass.
//
// On exit the harness writes:
//   - $SOAK_OUTPUT_DIR/soak-samples-<timestamp>.csv (per-sample state)
//   - $SOAK_OUTPUT_DIR/soak-summary-<timestamp>.json (start/end/peak)
//
// The maintainer runs this via `make soak` before tagging a release
// and pastes the summary into BENCHMARKS.md "Release Soak-Test Summary".
func BenchmarkSoak_MixedOutputs(b *testing.B) {
	cfg := loadSoakConfig()

	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		b.Fatalf("create output dir %q: %v", cfg.outputDir, err)
	}

	// Multi-output rigging — all in-process, no Docker dependence.
	mockSyslog := newMockSyslogServer(b)
	b.Cleanup(mockSyslog.close)

	mockWebhook := newMockWebhookServer(b)
	b.Cleanup(mockWebhook.close)

	dir := b.TempDir()
	filePath := filepath.Join(dir, "soak.log")
	fileOut, err := file.New(&file.Config{
		Path:       filePath,
		BufferSize: 10000,
	})
	if err != nil {
		b.Fatalf("file output: %v", err)
	}
	syslogOut, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       mockSyslog.addr(),
		Facility:      "local0",
		AppName:       "soak",
		BufferSize:    10000,
		FlushInterval: 100 * time.Millisecond,
	})
	if err != nil {
		b.Fatalf("syslog output: %v", err)
	}
	webhookOut, err := webhook.New(&webhook.Config{
		URL:                mockWebhook.url() + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          100,
		BufferSize:         10000,
		FlushInterval:      500 * time.Millisecond,
		Timeout:            5 * time.Second,
	}, nil)
	if err != nil {
		b.Fatalf("webhook output: %v", err)
	}

	auditor, err := audit.New(
		audit.WithTaxonomy(soakTaxonomy()),
		audit.WithAppName("soak-driver"),
		audit.WithHost("soak-host"),
		audit.WithQueueSize(50000),
		audit.WithValidationMode(audit.ValidationPermissive),
		audit.WithNamedOutput(fileOut),
		audit.WithNamedOutput(syslogOut),
		audit.WithNamedOutput(webhookOut),
	)
	if err != nil {
		b.Fatalf("auditor: %v", err)
	}
	b.Cleanup(func() { _ = auditor.Close() })

	// Bench-loop semantics — we want one wall-clock pass; the framework
	// re-invokes for b.N>1 on `-benchtime=Nx`, but we drive with
	// `-benchtime=<duration>` so b.N stays 1 in practice. The early
	// return here is defence-in-depth.
	b.ResetTimer()
	if b.N > 1 {
		// One pass total even if -benchtime is iteration-count.
		return
	}

	// Run lifecycle.
	timestamp := time.Now().Format("20060102-150405")
	csvPath := filepath.Join(cfg.outputDir, "soak-samples-"+timestamp+".csv")
	summaryPath := filepath.Join(cfg.outputDir, "soak-summary-"+timestamp+".json")

	b.Logf("soak run starting: duration=%s producers=%d rate=%d/sec output_dir=%s",
		cfg.duration, cfg.producers, cfg.rate, cfg.outputDir)
	b.Logf("samples: %s", csvPath)
	b.Logf("summary: %s", summaryPath)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.duration)
	defer cancel()

	startedAt := time.Now()
	startSample := captureSample(0, auditor, 0, 0)
	peak := startSample

	// Producers feed events at a paced rate.
	var totalEvents, totalDrops atomic.Int64
	var producerWG sync.WaitGroup
	producerWG.Add(cfg.producers)
	for p := 0; p < cfg.producers; p++ {
		go produceEvents(ctx, &producerWG, auditor, cfg, &totalEvents, &totalDrops)
	}

	// Sampler runs every SOAK_SAMPLE_INTERVAL and writes one CSV row.
	csvFile, err := os.Create(csvPath)
	if err != nil {
		b.Fatalf("create csv: %v", err)
	}
	defer func() { _ = csvFile.Close() }()
	csvWriter := csv.NewWriter(csvFile)
	if err := csvWriter.Write([]string{
		"elapsed_seconds", "heap_alloc_mb", "heap_sys_mb",
		"num_goroutine", "num_gc", "pause_total_ms",
		"audit_queue_len", "audit_queue_cap",
		"total_events", "total_drops",
	}); err != nil {
		b.Fatalf("write csv header: %v", err)
	}
	csvWriter.Flush()

	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		ticker := time.NewTicker(cfg.sampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := captureSample(time.Since(startedAt), auditor,
					totalEvents.Load(), totalDrops.Load())
				if err := writeSample(csvWriter, s); err != nil {
					b.Logf("sample write failed: %v", err)
				}
				csvWriter.Flush()
				peak = mergePeak(peak, s)
			}
		}
	}()

	// Wait for soak duration to elapse via ctx.
	<-ctx.Done()

	// Stop producers and sampler.
	producerWG.Wait()
	samplerWG.Wait()

	endedAt := time.Now()
	endSample := captureSample(endedAt.Sub(startedAt), auditor,
		totalEvents.Load(), totalDrops.Load())
	peak = mergePeak(peak, endSample)

	// Write final summary.
	summary := soakSummary{
		StartedAt:        startedAt,
		EndedAt:          endedAt,
		Duration:         endedAt.Sub(startedAt),
		Producers:        cfg.producers,
		TargetRate:       cfg.rate,
		TotalEvents:      totalEvents.Load(),
		TotalDrops:       totalDrops.Load(),
		StartHeapAllocMB: startSample.heapAllocMB,
		EndHeapAllocMB:   endSample.heapAllocMB,
		PeakHeapAllocMB:  peak.heapAllocMB,
		StartGoroutines:  startSample.numGoroutine,
		EndGoroutines:    endSample.numGoroutine,
		PeakGoroutines:   peak.numGoroutine,
		SampleFile:       csvPath,
	}
	if err := writeSummary(summaryPath, summary); err != nil {
		b.Fatalf("write summary: %v", err)
	}
	b.Logf("soak run complete: events=%d drops=%d "+
		"heap_alloc_mb start=%.1f end=%.1f peak=%.1f "+
		"goroutines start=%d end=%d peak=%d",
		summary.TotalEvents, summary.TotalDrops,
		summary.StartHeapAllocMB, summary.EndHeapAllocMB, summary.PeakHeapAllocMB,
		summary.StartGoroutines, summary.EndGoroutines, summary.PeakGoroutines)

	// AC #2: end-of-run heap and goroutine counts MUST be bounded
	// against 2× start. Real bounds vary with workload; the
	// maintainer reviews the full CSV before relying on this gate.
	if startSample.heapAllocMB > 0 && endSample.heapAllocMB > 2*startSample.heapAllocMB {
		b.Errorf("heap_alloc_mb grew unbounded: start=%.1f end=%.1f peak=%.1f (CSV: %s)",
			startSample.heapAllocMB, endSample.heapAllocMB, peak.heapAllocMB, csvPath)
	}
	if startSample.numGoroutine > 0 && endSample.numGoroutine > 2*startSample.numGoroutine {
		b.Errorf("numGoroutine grew unbounded: start=%d end=%d peak=%d (CSV: %s)",
			startSample.numGoroutine, endSample.numGoroutine, peak.numGoroutine, csvPath)
	}
}

// produceEvents drives one producer goroutine. Paces events to
// approximately cfg.rate / cfg.producers per second so the aggregate
// rate matches SOAK_RATE.
func produceEvents(
	ctx context.Context,
	wg *sync.WaitGroup,
	auditor *audit.Auditor,
	cfg soakConfig,
	totalEvents, totalDrops *atomic.Int64,
) {
	defer wg.Done()

	perProducerInterval := time.Second * time.Duration(cfg.producers) / time.Duration(cfg.rate)
	if perProducerInterval < time.Microsecond {
		perProducerInterval = time.Microsecond
	}
	ticker := time.NewTicker(perProducerInterval)
	defer ticker.Stop()

	rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			evt := mixedEvent(rng)
			if err := auditor.AuditEvent(evt); err != nil {
				totalDrops.Add(1)
			} else {
				totalEvents.Add(1)
			}
		}
	}
}

// mixedEvent returns one of three event templates, weighted to
// approximate a realistic audit workload — most events are routine,
// some are medium-complexity, and a tail are large multi-field events.
func mixedEvent(rng *rand.Rand) audit.Event {
	r := rng.IntN(100)
	switch {
	case r < 60:
		return audit.NewEvent("user_action", audit.Fields{
			"outcome":  "success",
			"actor_id": "soak-actor",
		})
	case r < 90:
		return audit.NewEvent("data_access", audit.Fields{
			"outcome":     "success",
			"actor_id":    "soak-actor",
			"resource_id": "res-1234",
			"action":      "read",
			"client_ip":   "10.0.0.1",
			"session_id":  "sess-soak",
			"latency_ms":  42,
			"bytes_read":  4096,
			"cache_hit":   true,
			"trace_id":    "trace-soak",
		})
	default:
		fields := audit.Fields{
			"outcome":  "success",
			"actor_id": "soak-actor",
		}
		// Large event: 50 mixed fields to stress allocation behaviour.
		for i := 0; i < 50; i++ {
			key := fmt.Sprintf("attr_%02d", i)
			fields[key] = fmt.Sprintf("value-%d-%d", i, rng.Int())
		}
		return audit.NewEvent("audit_record", fields)
	}
}

// soakTaxonomy declares the three event types used by mixedEvent.
func soakTaxonomy() *audit.Taxonomy {
	return &audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"routine":    {Events: []string{"user_action"}},
			"data":       {Events: []string{"data_access"}},
			"compliance": {Events: []string{"audit_record"}},
		},
		Events: map[string]*audit.EventDef{
			"user_action":  {Required: []string{"outcome", "actor_id"}},
			"data_access":  {Required: []string{"outcome", "actor_id"}},
			"audit_record": {Required: []string{"outcome", "actor_id"}},
		},
	}
}

// captureSample reads runtime + auditor state into a soakSample.
func captureSample(elapsed time.Duration, a *audit.Auditor, events, drops int64) soakSample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return soakSample{
		elapsed:       elapsed,
		heapAllocMB:   float64(ms.HeapAlloc) / (1024 * 1024),
		heapSysMB:     float64(ms.HeapSys) / (1024 * 1024),
		numGoroutine:  runtime.NumGoroutine(),
		numGC:         ms.NumGC,
		pauseTotalMS:  float64(ms.PauseTotalNs) / 1e6,
		auditQueueLen: a.QueueLen(),
		auditQueueCap: a.QueueCap(),
		totalEvents:   events,
		totalDrops:    drops,
	}
}

func writeSample(w *csv.Writer, s soakSample) error {
	return w.Write([]string{
		fmt.Sprintf("%.0f", s.elapsed.Seconds()),
		fmt.Sprintf("%.2f", s.heapAllocMB),
		fmt.Sprintf("%.2f", s.heapSysMB),
		strconv.Itoa(s.numGoroutine),
		strconv.FormatUint(uint64(s.numGC), 10),
		fmt.Sprintf("%.2f", s.pauseTotalMS),
		strconv.Itoa(s.auditQueueLen),
		strconv.Itoa(s.auditQueueCap),
		strconv.FormatInt(s.totalEvents, 10),
		strconv.FormatInt(s.totalDrops, 10),
	})
}

func mergePeak(peak, s soakSample) soakSample {
	if s.heapAllocMB > peak.heapAllocMB {
		peak.heapAllocMB = s.heapAllocMB
	}
	if s.numGoroutine > peak.numGoroutine {
		peak.numGoroutine = s.numGoroutine
	}
	return peak
}

func writeSummary(path string, s soakSummary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// --- in-process syslog mock (TCP, drains and discards) ---

type mockSyslogServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	stopCh   chan struct{}
}

func newMockSyslogServer(b *testing.B) *mockSyslogServer {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("syslog listener: %v", err)
	}
	s := &mockSyslogServer{listener: ln, stopCh: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *mockSyslogServer) addr() string { return s.listener.Addr().String() }

func (s *mockSyslogServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *mockSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := conn.Read(buf)
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
			}
			var netErr net.Error
			if !(err.Error() == "EOF" ||
				(netErrAs(err, &netErr) && netErr.Timeout())) {
				return
			}
		}
	}
}

func (s *mockSyslogServer) close() {
	close(s.stopCh)
	_ = s.listener.Close()
	s.wg.Wait()
}

// netErrAs is a tiny errors.As wrapper that avoids importing errors at
// the top of the file — the caller already has it via go's errors pkg.
func netErrAs(err error, target *net.Error) bool {
	if e, ok := err.(net.Error); ok {
		*target = e
		return true
	}
	return false
}

// --- in-process webhook receiver (drain-and-discard) ---

type mockWebhookServer struct {
	server *httptest.Server
}

func newMockWebhookServer(b *testing.B) *mockWebhookServer {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
	}))
	return &mockWebhookServer{server: srv}
}

func (s *mockWebhookServer) url() string { return s.server.URL }
func (s *mockWebhookServer) close()      { s.server.Close() }
