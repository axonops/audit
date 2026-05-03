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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit/loki"
	"github.com/axonops/audit/webhook"
)

// registerTLSHandshakeSteps wires step definitions for the TLS
// handshake-timeout and rapid-restart scenarios in
// tests/bdd/features/{syslog,webhook,loki}_output.feature (#552).
//
// Two failure modes are modelled:
//
//   - Handshake-timeout: a TCP listener that completes the kernel
//     accept but never participates in TLS hello. The audit output
//     should not crash, leak goroutines, or hang Close beyond a
//     bounded window — the contract is that a pathologically slow
//     server cannot wedge the writer.
//
//   - Rapid restart: an HTTPS receiver whose first N requests
//     hijack and close the connection (simulating server restart
//     mid-request), and subsequent requests succeed. The audit
//     output's retry path must recover without crashing or losing
//     accounting.
//
//nolint:gocognit,gocyclo,cyclop // independent ctx.Step registrations.
func registerTLSHandshakeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a stalling TCP listener is started$`, func() error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("stalling listener: %w", err)
		}
		tc.BadReceiverAddr = ln.Addr().String()
		// Hits counter intentionally NOT incremented per accept —
		// TCP-level accepts happen unavoidably even though no
		// HTTP/syslog request is ever delivered through the stalled
		// TLS handshake. The bound this scenario verifies is "Close
		// returned without wedging", not "no TCP connection was
		// accepted".
		tc.BadReceiverHits = new(uint32)
		var (
			wg      sync.WaitGroup
			connsMu sync.Mutex
			conns   []net.Conn
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}
				connsMu.Lock()
				conns = append(conns, conn)
				connsMu.Unlock()
				wg.Add(1)
				go func(c net.Conn) {
					defer wg.Done()
					defer func() { _ = c.Close() }()
					// Drain bytes until the cleanup hook closes c
					// from the outside; io.Copy then returns with
					// "use of closed network connection". Without
					// the explicit close, the audit-side wedged TLS
					// handshake holds the conn open indefinitely.
					_, _ = io.Copy(io.Discard, c)
				}(conn)
			}
		}()
		tc.AddCleanup(func() {
			_ = ln.Close()
			connsMu.Lock()
			for _, c := range conns {
				_ = c.Close()
			}
			connsMu.Unlock()
			wg.Wait()
		})
		return nil
	})

	ctx.Step(`^I close the webhook output to that stalling listener within (\d+) seconds$`,
		func(deadlineSec int) error {
			out, err := webhook.New(&webhook.Config{
				URL:                "https://" + tc.BadReceiverAddr + "/audit",
				TLSCA:              tc.BadCerts.caPath,
				Timeout:            1 * time.Second,
				AllowPrivateRanges: true,
			}, nil)
			if out == nil {
				tc.LastErr = err
				return nil
			}
			tc.AddCleanup(func() { _ = out.Close() })
			start := time.Now()
			// Write is expected to fail or queue; the assertion is on
			// Close timing, not Write.
			_ = out.Write([]byte(`{"event":"stall"}` + "\n"))
			closeErr := out.Close()
			elapsed := time.Since(start)
			if elapsed > time.Duration(deadlineSec)*time.Second {
				return fmt.Errorf(
					"webhook Close took %v; expected within %d s — "+
						"a stalled TLS handshake should not wedge the writer",
					elapsed, deadlineSec)
			}
			tc.LastErr = closeErr
			return nil
		})

	ctx.Step(`^I close the loki output to that stalling listener within (\d+) seconds$`,
		func(deadlineSec int) error {
			out, err := loki.New(&loki.Config{
				URL:                "https://" + tc.BadReceiverAddr + "/loki/api/v1/push",
				TLSCA:              tc.BadCerts.caPath,
				Timeout:            1 * time.Second,
				AllowPrivateRanges: true,
			}, nil)
			if out == nil {
				tc.LastErr = err
				return nil
			}
			tc.AddCleanup(func() { _ = out.Close() })
			start := time.Now()
			// Write is expected to fail or queue; the assertion is on
			// Close timing, not Write.
			_ = out.Write([]byte(`{"streams":[]}` + "\n"))
			closeErr := out.Close()
			elapsed := time.Since(start)
			if elapsed > time.Duration(deadlineSec)*time.Second {
				return fmt.Errorf(
					"loki Close took %v; expected within %d s — "+
						"a stalled TLS handshake should not wedge the writer",
					elapsed, deadlineSec)
			}
			tc.LastErr = closeErr
			return nil
		})

	ctx.Step(`^a flapping HTTPS receiver that drops the first (\d+) connections$`,
		func(n int) error {
			if n < 0 {
				return fmt.Errorf("connection-drop count must be >= 0, got %d", n)
			}
			return startFlappingReceiver(tc, n)
		})

	ctx.Step(`^I send (\d+) (webhook|loki) events to the flapping receiver$`,
		func(events int, kind string) error {
			return sendFlappingEvents(tc, events, kind)
		})

	ctx.Step(`^the flapping receiver should eventually receive at least one successful request$`,
		func() error {
			if pollUntil(5*time.Second, 50*time.Millisecond, func() bool {
				return atomic.LoadUint32(tc.BadReceiverHits) >= 1
			}) {
				return nil
			}
			return fmt.Errorf(
				"flapping receiver got 0 successful requests after 5 s — "+
					"the audit output's retry path failed to recover; "+
					"connection drops: %d", atomic.LoadUint32(tc.flappingDrops))
		})
}

// startFlappingReceiver starts an HTTPS server using the runtime test
// CA's valid TLS config (so the audit client trusts it). The first n
// requests hijack the underlying TCP connection and close it without
// responding, simulating a server that flaps mid-request. Subsequent
// requests are answered with 204. The audit output's retry path must
// recover.
func startFlappingReceiver(tc *AuditTestContext, n int) error {
	if tc.BadCerts == nil {
		return fmt.Errorf("call 'bad TLS certs are generated' first")
	}
	tc.BadReceiverHits = new(uint32)
	tc.flappingDrops = new(uint32)
	hits := tc.BadReceiverHits
	drops := tc.flappingDrops

	// Build a valid server TLS config from the same CA so the audit
	// client's handshake succeeds and the connection-drop happens at
	// the HTTP layer.
	validTLS, err := makeServerTLSConfig(tc.BadCerts.caCert, tc.BadCerts.caKey, validLocalhostTemplate())
	if err != nil {
		return fmt.Errorf("flapping cert: %w", err)
	}

	// httptest exemption (#559): rotates between valid/expired certs and
	// hijacks the TCP connection mid-batch to test connection-flapping
	// retry semantics. The per-connection serial handler model lets the
	// scenario script exact failure timing — no real container offers
	// this mid-batch certificate-flip.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain to keep the request body fully consumed before we
		// hijack — avoids a premature TCP RST that masks the drop as
		// a different error class.
		_, _ = io.Copy(io.Discard, r.Body)
		// httptest.Server runs handlers serially per connection, so
		// the LoadUint32 + AddUint32 sequence is safe even though
		// they are not a single atomic operation. The step
		// registration above guards against a negative n, so the
		// uint32 conversion never wraps.
		droppedSoFar := atomic.LoadUint32(drops)
		if droppedSoFar < uint32(n) { //nolint:gosec // n was guarded >= 0 at step entry
			atomic.AddUint32(drops, 1)
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, hjErr := hj.Hijack()
				if hjErr == nil {
					_ = conn.Close()
					return
				}
			}
			http.Error(w, "flap", http.StatusInternalServerError)
			return
		}
		atomic.AddUint32(hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = validTLS
	srv.StartTLS()
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "https://")
	tc.AddCleanup(func() { srv.Close() })
	return nil
}

// sendFlappingEvents writes events to a single-shot webhook or loki
// output pointed at the flapping receiver. We construct a fresh
// output per scenario and Close it after the send window so the
// retry/backoff state is fully exercised before the assertion.
func sendFlappingEvents(tc *AuditTestContext, events int, kind string) error {
	if tc.BadCerts == nil {
		return fmt.Errorf("bad-cert generation step missing")
	}
	url := "https://" + tc.BadReceiverAddr
	switch kind {
	case "webhook":
		out, err := webhook.New(&webhook.Config{
			URL:                url + "/audit",
			TLSCA:              tc.BadCerts.caPath,
			Timeout:            2 * time.Second,
			MaxRetries:         5,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
		}, nil)
		if err != nil {
			return fmt.Errorf("webhook new: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		for i := 0; i < events; i++ {
			_ = out.Write([]byte(fmt.Sprintf(`{"event":"%d"}`+"\n", i)))
		}
	case "loki":
		out, err := loki.New(&loki.Config{
			URL:                url + "/loki/api/v1/push",
			TLSCA:              tc.BadCerts.caPath,
			Timeout:            2 * time.Second,
			MaxRetries:         5,
			AllowPrivateRanges: true,
			BatchSize:          1,
			FlushInterval:      100 * time.Millisecond,
		}, nil)
		if err != nil {
			return fmt.Errorf("loki new: %w", err)
		}
		tc.AddCleanup(func() { _ = out.Close() })
		for i := 0; i < events; i++ {
			_ = out.Write([]byte(fmt.Sprintf(`{"streams":[{"stream":{"x":"%d"},"values":[]}]}`+"\n", i)))
		}
	default:
		return fmt.Errorf("unknown flapping target %q", kind)
	}
	return nil
}
