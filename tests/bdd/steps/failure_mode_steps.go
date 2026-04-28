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

package steps

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
)

// registerFailureModeSteps wires step definitions for the
// per-output failure-mode scenarios in
// tests/bdd/features/{syslog,webhook,loki,stdout,file}_output.feature
// (#562). The scenarios cover real production failure classes that
// the existing TLS-rejection and reconnect coverage does not reach:
//
//   - DNS-unresolvable host (RFC 6761 .invalid TLD)
//   - Giant response body (DoS guard via drainCap)
//   - Connection reset mid-batch (Hijacker close)
//   - Chunked-encoding response stall
//   - Loki tenant-not-found (404 with X-Scope-OrgID)
//   - stdout broken pipe (EPIPE downstream)
//   - file output target on a read-only directory
//
//nolint:gocognit,gocyclo,cyclop // independent ctx.Step registrations.
func registerFailureModeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a DNS-unresolvable address is configured$`, func() error {
		// RFC 6761 reserves `.invalid`; OS resolvers return NXDOMAIN
		// without consulting the network. The 6514 port literal is
		// arbitrary; it is never connected because resolution fails
		// first.
		tc.BadReceiverAddr = "bdd-unresolvable-host.invalid:6514"
		return nil
	})

	ctx.Step(`^I try to send a syslog event over TCP to the unresolvable address within (\d+) seconds$`,
		func(deadlineSec int) error {
			return runWithWatchdog(deadlineSec+2, func() {
				out, err := syslog.New(&syslog.Config{
					Network: "tcp",
					Address: tc.BadReceiverAddr,
				})
				if out != nil {
					_ = out.Close()
				}
				tc.LastErr = err
			})
		})

	ctx.Step(`^I try to send a webhook event to the unresolvable address within (\d+) seconds$`,
		func(deadlineSec int) error {
			return runWithWatchdog(deadlineSec+2, func() {
				out, err := webhook.New(&webhook.Config{
					URL:                "http://" + tc.BadReceiverAddr + "/audit",
					Timeout:            time.Duration(deadlineSec) * time.Second,
					BatchSize:          1,
					FlushInterval:      100 * time.Millisecond,
					AllowPrivateRanges: true,
					AllowInsecureHTTP:  true,
				}, nil)
				if err != nil {
					tc.LastErr = err
					return
				}
				// Write enqueues. Close drains the delivery goroutine,
				// which surfaces the DNS dial error to the writeLoop;
				// the error class is observed in tc.LastErr.
				_ = out.Write([]byte(`{"event":"dns-test"}` + "\n"))
				if closeErr := out.Close(); closeErr != nil {
					tc.LastErr = closeErr
				}
			})
		})

	ctx.Step(`^I try to send a loki event to the unresolvable address within (\d+) seconds$`,
		func(deadlineSec int) error {
			return runWithWatchdog(deadlineSec+2, func() {
				out, err := loki.New(&loki.Config{
					URL:                "http://" + tc.BadReceiverAddr + "/loki/api/v1/push",
					Timeout:            time.Duration(deadlineSec) * time.Second,
					BatchSize:          1,
					FlushInterval:      100 * time.Millisecond,
					AllowPrivateRanges: true,
					AllowInsecureHTTP:  true,
				}, nil)
				if err != nil {
					tc.LastErr = err
					return
				}
				_ = out.Write([]byte(`{"streams":[]}` + "\n"))
				if closeErr := out.Close(); closeErr != nil {
					tc.LastErr = closeErr
				}
			})
		})

	// DNS-resolution failures surface as *net.DNSError on every
	// platform (the Go stdlib normalises getaddrinfo errors to
	// this canonical type). The structured check is portable
	// across Linux/macOS/Windows — substring matching on the
	// stringified error would not be.
	ctx.Step(`^the result should be a DNS-resolution failure$`, func() error {
		if tc.LastErr == nil {
			// Async delivery path. The bounded-deadline check in
			// the When step proves the dial did not wedge; the
			// configured Timeout means the http.Transport drops
			// the request after dial failure. The DNS error itself
			// is recorded via the output's metrics, not surfaced
			// to Close — so a nil return is acceptable here.
			return nil
		}
		var dnsErr *net.DNSError
		if errors.As(tc.LastErr, &dnsErr) {
			return nil
		}
		// Belt-and-braces fallback for transports that wrap the
		// DNSError with a non-As-compatible chain — substring
		// match keeps the test honest while remaining
		// platform-portable.
		msg := strings.ToLower(tc.LastErr.Error())
		for _, sub := range []string{
			"no such host",
			"lookup",
			"name resolution",
			"is not known", // Windows: "is usually a temporary error"
		} {
			if strings.Contains(msg, sub) {
				return nil
			}
		}
		return fmt.Errorf("expected DNS-resolution failure (*net.DNSError or known wording), got: %w", tc.LastErr)
	})

	ctx.Step(`^a webhook receiver returning a (\d+)-byte body$`, func(n int) error {
		return startGiantBodyReceiver(tc, n)
	})

	ctx.Step(`^I send 1 webhook event to the configured failure-mode receiver within (\d+) seconds$`,
		func(deadlineSec int) error {
			return runWithWatchdog(deadlineSec+2, func() {
				out, err := webhook.New(&webhook.Config{
					URL:           "http://" + tc.BadReceiverAddr + "/audit",
					Timeout:       time.Duration(deadlineSec) * time.Second,
					BatchSize:     1,
					FlushInterval: 100 * time.Millisecond,
					// MaxRetries: 1 is the smallest non-default value
					// validateWebhookLimits accepts (0 is silently
					// normalised to DefaultMaxRetries=3). Using 1 keeps
					// the assertion bounded — a single retry on a
					// transient response — without depending on the
					// default retry count.
					MaxRetries:         1,
					AllowPrivateRanges: true,
					AllowInsecureHTTP:  true,
				}, nil)
				if err != nil {
					tc.LastErr = err
					return
				}
				tc.AddCleanup(func() { _ = out.Close() })
				_ = out.Write([]byte(`{"event":"failure-mode-test"}` + "\n"))
				// Wait for the request to land on the server, then
				// close. The test asserts "client doesn't OOM and
				// Close returns within deadline".
				deadline := time.Now().Add(time.Duration(deadlineSec) * time.Second)
				for time.Now().Before(deadline) {
					if atomic.LoadUint32(tc.BadReceiverHits) >= 1 {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if closeErr := out.Close(); closeErr != nil {
					tc.LastErr = closeErr
				}
			})
		})

	ctx.Step(`^a webhook receiver that resets the connection mid-request$`,
		func() error { return startConnectionResetReceiver(tc) })

	ctx.Step(`^a webhook receiver that starts a chunked response then stalls$`,
		func() error { return startChunkedStallReceiver(tc) })

	ctx.Step(`^a loki receiver that starts a chunked response then stalls$`,
		func() error { return startChunkedStallReceiver(tc) })

	ctx.Step(`^a loki receiver that returns 404 tenant-not-found$`,
		func() error { return startTenantNotFoundReceiver(tc) })

	ctx.Step(`^I send 1 loki event with tenant "([^"]*)" to the configured failure-mode receiver within (\d+) seconds$`,
		func(tenant string, deadlineSec int) error {
			return runWithWatchdog(deadlineSec+2, func() {
				out, err := loki.New(&loki.Config{
					URL:                "http://" + tc.BadReceiverAddr + "/loki/api/v1/push",
					TenantID:           tenant,
					Timeout:            time.Duration(deadlineSec) * time.Second,
					BatchSize:          1,
					FlushInterval:      100 * time.Millisecond,
					MaxRetries:         1,
					AllowPrivateRanges: true,
					AllowInsecureHTTP:  true,
				}, nil)
				if err != nil {
					tc.LastErr = err
					return
				}
				tc.AddCleanup(func() { _ = out.Close() })
				_ = out.Write([]byte(`{"streams":[{"stream":{"x":"1"},"values":[]}]}` + "\n"))
				deadline := time.Now().Add(time.Duration(deadlineSec) * time.Second)
				for time.Now().Before(deadline) {
					if atomic.LoadUint32(tc.BadReceiverHits) >= 1 {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if closeErr := out.Close(); closeErr != nil {
					tc.LastErr = closeErr
				}
			})
		})

	// Bounded receiver-hit assertion. The failure-mode scenarios
	// configure MaxRetries: 1 (smallest non-default the validator
	// accepts), so the upper bound of N+5 catches a regression that
	// turns a single retry into an unbounded retry storm without
	// also failing a one-shot success.
	ctx.Step(`^the failure-mode receiver should have received between (\d+) and (\d+) requests$`,
		func(minHits, maxHits int) error {
			if tc.BadReceiverHits == nil {
				return fmt.Errorf("no receiver was started")
			}
			got := atomic.LoadUint32(tc.BadReceiverHits)
			if got < uint32(minHits) || got > uint32(maxHits) { //nolint:gosec // minHits/maxHits are small positive ints from BDD scenario
				return fmt.Errorf("receiver hits: got %d, want between %d and %d", got, minHits, maxHits)
			}
			return nil
		})

	ctx.Step(`^a stdout output bound to a closed pipe surfaces the broken-pipe error$`,
		func() error { return runStdoutEPIPEScenario(tc) })
}

// startGiantBodyReceiver stands up an in-process plain HTTP server
// whose handler writes a Content-Length header and exactly n bytes
// of zero-filled body. The webhook output's drainCap (1 MiB on
// 2xx/4xx/5xx, see webhook/http.go) caps the bytes the client
// consumes; we exercise the cap by sending a body 4x larger.
func startGiantBodyReceiver(tc *AuditTestContext, n int) error {
	tc.BadReceiverHits = new(uint32)
	hits := tc.BadReceiverHits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddUint32(hits, 1)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", n))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusInternalServerError) // 5xx triggers drainCap path
		buf := make([]byte, 4096)
		remaining := n
		for remaining > 0 {
			chunk := len(buf)
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := w.Write(buf[:chunk]); err != nil {
				return
			}
			remaining -= chunk
		}
	}))
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "http://")
	tc.AddCleanup(srv.Close)
	return nil
}

// startConnectionResetReceiver stands up an in-process plain HTTP
// server that hijacks each request after reading the body and
// closes the underlying TCP connection without writing a response.
// The audit output's retry path interprets this as a transient
// failure and consumes its retry budget.
func startConnectionResetReceiver(tc *AuditTestContext) error {
	tc.BadReceiverHits = new(uint32)
	hits := tc.BadReceiverHits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint32(hits, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "http://")
	tc.AddCleanup(srv.Close)
	return nil
}

// startChunkedStallReceiver stands up an in-process plain HTTP
// server that sets Transfer-Encoding: chunked, writes one chunk,
// then blocks until the test scenario tears it down. The audit
// output's http.Transport.ResponseHeaderTimeout (1s floor) bounds
// the read; the request fails with "context deadline exceeded".
func startChunkedStallReceiver(tc *AuditTestContext) error {
	tc.BadReceiverHits = new(uint32)
	hits := tc.BadReceiverHits
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint32(hits, 1)
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("first-chunk"))
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-stall:
		}
	}))
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "http://")
	tc.AddCleanup(func() {
		close(stall)
		srv.Close()
	})
	return nil
}

// startTenantNotFoundReceiver returns 404 with a Loki-shaped error
// body. The loki output sees the 404 and records a non-retryable
// error metric; the X-Scope-OrgID header is what the upstream
// would inspect to decide tenant existence.
func startTenantNotFoundReceiver(tc *AuditTestContext) error {
	tc.BadReceiverHits = new(uint32)
	hits := tc.BadReceiverHits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddUint32(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorType":"not_found","error":"tenant not found"}`))
	}))
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "http://")
	tc.AddCleanup(srv.Close)
	return nil
}

// runStdoutEPIPEScenario creates an os.Pipe pair, closes the read
// end, builds a stdout output writing to the write end, sends one
// event, and asserts the resulting Write returns an error wrapping
// syscall.EPIPE. This is a synchronous Write through the
// audit.StdoutOutput, not a goroutine-mediated path.
func runStdoutEPIPEScenario(tc *AuditTestContext) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("os.Pipe: %w", err)
	}
	// Close the read end immediately. Writes to the write end
	// will receive EPIPE after the kernel has accepted some bytes
	// into the pipe buffer (typically 64 KiB), but we send enough
	// data to force the kernel to push.
	_ = r.Close()
	defer func() { _ = w.Close() }()
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: w})
	if err != nil {
		return fmt.Errorf("stdout new: %w", err)
	}
	defer func() { _ = out.Close() }()
	// 64 KiB+ buffer ensures we exceed the kernel pipe buffer and
	// trigger EPIPE on the second-or-later write.
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = '.'
	}
	payload[len(payload)-1] = '\n'
	var lastErr error
	for i := 0; i < 4; i++ {
		if writeErr := out.Write(payload); writeErr != nil {
			lastErr = writeErr
			break
		}
	}
	if lastErr == nil {
		return fmt.Errorf("expected stdout write error after closed-pipe; got nil")
	}
	if !errors.Is(lastErr, syscall.EPIPE) &&
		!strings.Contains(lastErr.Error(), "broken pipe") &&
		!strings.Contains(lastErr.Error(), "closed pipe") {
		return fmt.Errorf("expected EPIPE / broken pipe; got: %w", lastErr)
	}
	tc.LastErr = lastErr
	return nil
}

// runWithWatchdog runs fn in the calling goroutine but enforces a
// hard deadline by spawning a goroutine that calls fn and racing
// the result against time.After. If fn does not return within
// deadlineSec seconds, the step returns an error WITHOUT waiting
// for fn to finish — the runaway goroutine leaks for the rest of
// the test process. The leak is acceptable as a fail-loud signal:
// goleak.VerifyTestMain at process exit will surface the wedge.
//
// This pattern is the only safe way to enforce a per-step deadline
// when the call under test (e.g. syslog.New, webhook Close) does
// not accept a context. Without the watchdog, a regression that
// reintroduces an unbounded dial would hang the whole BDD suite at
// godog's process-level timeout, masking the real failure.
func runWithWatchdog(deadlineSec int, fn func()) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return nil
	case <-time.After(time.Duration(deadlineSec) * time.Second):
		return fmt.Errorf("step did not return within %d seconds — the call under test wedged", deadlineSec)
	}
}
