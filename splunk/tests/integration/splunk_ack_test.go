//go:build integration

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

// Integration tests for the ACK state machine against a real Splunk
// Enterprise container with indexer acknowledgement enabled on the
// HEC token. The library-side state machine is exhaustively
// unit-tested in splunk/ack_test.go; these tests verify the
// end-to-end behaviour against Splunk's real /services/collector/ack
// endpoint.
//
// Requires: make test-infra-splunk-up
//
// The test container's HEC token MUST have indexer acknowledgement
// enabled (set in tests/bdd/docker-compose.splunk.yml's
// SPLUNK_HEC_ACKNOWLEDGEMENTS environment variable). If ACK is
// disabled on the test token, the construction-time feature-detect
// probe returns ErrAckDisabled and these tests are skipped via the
// skipIfAckDisabled helper.

package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// skipIfAckDisabled attempts construction against the configured
// AckMode. If the test container's token doesn't have ACK enabled,
// the feature-detect probe returns ErrAckDisabled — the test
// skips cleanly so CI doesn't fail on infrastructure setup.
func skipIfAckDisabled(t *testing.T, mode splunk.AckMode) {
	t.Helper()
	cfg := &splunk.Config{
		URL:                        splunkURL,
		Token:                      splunkToken,
		Sourcetype:                 "audit:event",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              819200,
		MaxEventBytes:              1024 * 1024,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 100,
		MaxRetries:                 1,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
		AckMode:                    mode,
		AckPollInterval:            500 * time.Millisecond,
		AckResendWindow:            30 * time.Second,
	}
	out, err := splunk.New(cfg, nil)
	if errors.Is(err, splunk.ErrAckDisabled) {
		t.Skipf("test container's HEC token does not have ACK enabled: %v", err)
	}
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// newSplunkOutputWithACK is the ACK-test analogue of newSplunkOutput.
func newSplunkOutputWithACK(t *testing.T, mode splunk.AckMode, mutate func(*splunk.Config)) *splunk.Output {
	t.Helper()
	gz := false
	cfg := &splunk.Config{
		URL:                        splunkURL,
		Token:                      splunkToken,
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              819200,
		MaxEventBytes:              1024 * 1024,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 100,
		MaxRetries:                 1,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
		AckMode:                    mode,
		AckPollInterval:            500 * time.Millisecond,
		AckResendWindow:            30 * time.Second,
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	return out
}

// TestSplunkIntegration_AckRequired_PositiveAck — AckModeRequired
// against a real Splunk container. After Write+Close, every event
// should have received a positive ack and the snapshot's Pending
// counter should be zero.
func TestSplunkIntegration_AckRequired_PositiveAck(t *testing.T) {
	skipIfArm64(t)
	skipIfAckDisabled(t, splunk.AckModeRequired)
	out := newSplunkOutputWithACK(t, splunk.AckModeRequired, nil)

	m := marker(t)
	const n = 5
	for i := 0; i < n; i++ {
		event := []byte(fmt.Sprintf(
			`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success","seq":%d}`,
			time.Now().UTC().Format(time.RFC3339Nano), m, i))
		require.NoError(t, out.Write(event))
	}

	// Close drains the in-flight buffer up to 2*Timeout. All events
	// should be confirmed by then.
	require.NoError(t, out.Close())

	snap := out.AckMetricsSnapshot()
	assert.Equal(t, 0, snap.Pending,
		"all events should be confirmed before Close returns; pending=%d", snap.Pending)
	assert.GreaterOrEqual(t, snap.Confirmed, int64(n),
		"confirmed count should equal sent count; confirmed=%d, sent=%d", snap.Confirmed, n)

	// Verify the events landed in Splunk searchable form.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="audit:event" actor_id=%q`, m), n)
	require.GreaterOrEqual(t, len(hits), n,
		"all %d events should be searchable in Splunk after ack confirmation", n)
}

// TestSplunkIntegration_AckRequired_ResendOnTimeout_Deterministic —
// pin the resend-on-timeout code path with deterministic timing by
// running an in-process HTTP reverse-proxy between the output and the
// real Splunk container. The proxy forwards /event and /health to
// Splunk unchanged (so events actually land and the startup probe
// succeeds) but intercepts /ack with a controllable response: events
// are NOT confirmed until the test explicitly flips the proxy to
// "confirm" mode. This drives the library through the exact resend
// path the racy real-Splunk test could not pin.
//
// What this proves:
//
//  1. With ack responses stuck at `acked:false`, AckResendWindow
//     expiration increments TimedOut at least once and triggers a
//     resend of the original entries.
//  2. After the test flips the proxy to confirm, the resent batch's
//     ack is positive, Confirmed increments, and the event lands in
//     real Splunk's index (visible to the search REST API).
//
// Why an in-process reverse-proxy rather than toxiproxy:
//   - Toxiproxy is a TCP-level proxy — a latency/timeout toxic on
//     the listener slows BOTH /event and /ack on the same port,
//     which breaks the test (events would never reach Splunk before
//     the request timeout fires). Surgically slowing only /ack would
//     require either two proxy listeners + a production API change
//     to override the ack URL, or an HTTP-aware proxy. The latter is
//     what this test provides, written in 60 lines of stdlib Go with
//     no extra container dependency.
func TestSplunkIntegration_AckRequired_ResendOnTimeout_Deterministic(t *testing.T) {
	skipIfArm64(t)
	// Deliberately NOT calling skipIfAckDisabled: the proxy
	// synthesises ackIds in /event responses (see ackResendProxy),
	// so the test exercises the library's ACK code path even when
	// the test container's HEC token has ACK disabled. The real-Splunk
	// ACK protocol (positive-ack, best-effort metrics) is covered by
	// TestSplunkIntegration_AckRequired_PositiveAck and
	// TestSplunkIntegration_AckBestEffort_MetricsExposed, which DO
	// require container-side ACK enablement and skip otherwise.

	proxy := newAckResendProxy(t, splunkURL)
	t.Cleanup(proxy.close)

	out := newSplunkOutputWithACK(t, splunk.AckModeRequired, func(c *splunk.Config) {
		c.URL = proxy.URL
		c.AckPollInterval = 100 * time.Millisecond
		c.AckResendWindow = 500 * time.Millisecond
		// Generous request timeout — the /event forward through the
		// proxy itself is fast; the /ack DELAY is implemented by the
		// proxy returning acked:false, not by holding the request
		// open. The output's own timeout never expires for /ack.
		c.Timeout = 5 * time.Second
		// MaxRetries bounds the HTTP request retry count inside
		// doPost (per-attempt resilience). The ack-resend loop
		// itself is unbounded by design — every AckResendWindow
		// elapsed without confirmation triggers another resend. The
		// blast radius (event duplication count) is bounded by how
		// quickly phase 2 calls confirmAll, not by any retry cap.
		c.MaxRetries = 1
		// Override the sourcetype the synthetic startup probe uses so
		// its `_ack_probe:1` event doesn't pollute the canonical
		// `audit:event` namespace in Splunk's main index when other
		// tests count events there.
		c.Sourcetype = "audit:event:ackproxy"
	})

	m := marker(t)
	event := []byte(fmt.Sprintf(
		`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success"}`,
		time.Now().UTC().Format(time.RFC3339Nano), m))
	require.NoError(t, out.Write(event))

	// Phase 1: with the proxy holding all acks at `false`, the resend
	// window MUST elapse and TimedOut MUST increment. Poll until we
	// see it (or fail after a generous deadline relative to the
	// configured window).
	require.Eventually(t, func() bool {
		return out.AckMetricsSnapshot().TimedOut >= 1
	}, 10*time.Second, 100*time.Millisecond,
		"TimedOut must increment when ack responses stay negative beyond AckResendWindow")

	// Phase 2: flip the proxy to confirm — the next /ack poll should
	// return acked:true for every requested ackID, the resend batch
	// resolves, Confirmed increments, and the in-flight pending count
	// drains to zero. Close drains the in-flight buffer up to
	// 2*Timeout (10s) which is comfortably above the 100ms poll
	// interval.
	proxy.confirmAll()
	require.NoError(t, out.Close())

	snap := out.AckMetricsSnapshot()
	assert.GreaterOrEqual(t, snap.TimedOut, int64(1),
		"first phase must observe a resend timeout; TimedOut=%d", snap.TimedOut)
	assert.GreaterOrEqual(t, snap.Confirmed, int64(1),
		"second phase must observe the resent batch confirmed; Confirmed=%d", snap.Confirmed)
	assert.Zero(t, snap.Pending,
		"all in-flight batches must drain before Close returns; Pending=%d", snap.Pending)

	// Verify the event actually landed in real Splunk via the
	// indexed-event search REST. The original + resend both forward
	// through the proxy to real Splunk, so the event count is at
	// least 1 (duplicates allowed; we don't pin the exact count
	// because the resend path is an at-least-once guarantee).
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="audit:event:ackproxy" %q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"resent event must reach Splunk's index after ack confirmation")
}

// ackResendProxy is an in-process HTTP reverse-proxy used by
// TestSplunkIntegration_AckRequired_ResendOnTimeout_Deterministic.
// /event and /health are forwarded transparently to the real Splunk
// container; /ack is served from controllable state (initially all
// acks return false; after confirmAll the state flips to true).
type ackResendProxy struct {
	URL     string
	server  *httptest.Server
	confirm atomic.Bool
	// nextAck is a monotonically-increasing ackId injected into every
	// /event response. The library uses these to drive its ack
	// tracker; the value is opaque to it.
	nextAck atomic.Int64
}

// newAckResendProxy constructs an httptest reverse-proxy that
// forwards /event and /health to the given upstream Splunk URL and
// intercepts /ack with controllable state. Cleanup is the caller's
// responsibility (the returned proxy's close method must be called).
func newAckResendProxy(t *testing.T, upstream string) *ackResendProxy {
	t.Helper()
	upURL, err := url.Parse(upstream)
	require.NoError(t, err)

	p := &ackResendProxy{}

	rp := httputil.NewSingleHostReverseProxy(upURL)
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, fmt.Sprintf("upstream forward failed: %v", err), http.StatusBadGateway)
	}
	// Inject a synthetic ackId into /event responses so the library
	// enters its ACK tracking code path regardless of whether the
	// test container's HEC token has ACK enabled. Splunk's real
	// response shape with ACK enabled is `{"text":"Success","code":0,
	// "ackId":<int>}` — we mirror it.
	rp.ModifyResponse = func(resp *http.Response) error {
		if !strings.HasSuffix(resp.Request.URL.Path, "/services/collector/event") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		// ModifyResponse takes ownership of the body; the close error
		// is non-actionable (we are about to replace the body).
		_ = resp.Body.Close()
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			// Real Splunk returned a non-JSON body — leave it alone
			// and pass through. The library will surface the error.
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			return nil
		}
		parsed["ackId"] = p.nextAck.Add(1)
		newBody, err := json.Marshal(parsed)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(newBody))
		resp.ContentLength = int64(len(newBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		return nil
	}

	mux := http.NewServeMux()
	// Forward /event + /health + /raw to real Splunk. Match any
	// trailing path/query (HasPrefix via the trailing-slash pattern)
	// so a future library change that appends a path segment doesn't
	// silently fall through to the 404 handler.
	for _, path := range []string{
		"/services/collector/event",
		"/services/collector/health",
		"/services/collector/raw",
	} {
		mux.Handle(path, rp)
		mux.Handle(path+"/", rp)
	}

	// /ack — controllable. Decode the request body, record every
	// requested ackID, and return `acks: {id: <state>}` for each. The
	// state is read from p.confirm at every request, so a mid-test
	// flip takes effect on the next poll. Both exact and prefix
	// patterns are registered for the same reason as /event above.
	ackHandler := func(w http.ResponseWriter, r *http.Request) {
		// Read error → empty body → empty acks map below: same
		// "no-progress" fallback as a JSON decode failure.
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		var req struct {
			Acks []int64 `json:"acks"`
		}
		// On decode failure return Splunk-shaped 200 + empty acks map
		// rather than 4xx — the library treats this as "no progress"
		// and the test still drives the timeout path.
		_ = json.Unmarshal(body, &req)

		state := p.confirm.Load()
		out := make(map[string]bool, len(req.Acks))
		for _, id := range req.Acks {
			out[strconv.FormatInt(id, 10)] = state
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"acks": out})
	}
	mux.HandleFunc("/services/collector/ack", ackHandler)
	mux.HandleFunc("/services/collector/ack/", ackHandler)

	// Anything else: 404 — the splunk output should never hit a path
	// not listed above. Surfacing a 404 makes any new path immediately
	// obvious in the test failure.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, fmt.Sprintf("ackResendProxy: unhandled path %s", r.URL.Path), http.StatusNotFound)
	})

	p.server = httptest.NewServer(mux)
	// The splunk output expects the URL to NOT include any path
	// component — it appends /services/collector/{event,ack,health}
	// itself via joinEventURL / joinAckURL / joinHealthURL.
	p.URL = strings.TrimRight(p.server.URL, "/")
	return p
}

// confirmAll flips the proxy into "confirm" mode: subsequent /ack
// responses return true for every requested ackID. The flip is
// observed by the very next /ack poll (no goroutine to coordinate
// because confirm is an atomic bool).
func (p *ackResendProxy) confirmAll() { p.confirm.Store(true) }

// close shuts down the httptest.Server. Caller wires this via t.Cleanup.
func (p *ackResendProxy) close() { p.server.Close() }

// TestSplunkIntegration_AckBestEffort_MetricsExposed — verify
// AckModeBestEffort produces metric updates (confirmed > 0) against
// a real Splunk without gating the producer.
func TestSplunkIntegration_AckBestEffort_MetricsExposed(t *testing.T) {
	skipIfArm64(t)
	skipIfAckDisabled(t, splunk.AckModeBestEffort)
	out := newSplunkOutputWithACK(t, splunk.AckModeBestEffort, nil)

	m := marker(t)
	const n = 3
	for i := 0; i < n; i++ {
		event := []byte(fmt.Sprintf(
			`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success","seq":%d}`,
			time.Now().UTC().Format(time.RFC3339Nano), m, i))
		require.NoError(t, out.Write(event))
	}
	require.NoError(t, out.Close())

	snap := out.AckMetricsSnapshot()
	assert.GreaterOrEqual(t, snap.Confirmed, int64(1),
		"best-effort mode must record at least 1 confirmed ack; confirmed=%d", snap.Confirmed)
	assert.Zero(t, snap.BufferFullDrops,
		"best-effort mode never gates the buffer; buffer-full drops must be 0")
}
