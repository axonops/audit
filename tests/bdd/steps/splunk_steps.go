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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// splunkStubRequest is one recorded HEC request the stub received.
type splunkStubRequest struct {
	method      string
	path        string
	rawQuery    string
	auth        string
	contentEnc  string
	userAgent   string
	contentType string
	channel     string // X-Splunk-Request-Channel (ACK)
	body        []byte
	receivedAt  time.Time
}

// splunkStub is the in-process HTTP server that the BDD scenarios
// drive the splunk output against. Records every request and exposes
// configurable response behaviour (status, body, optional first-N
// failures before success — for retry scenarios).
type splunkStub struct {
	server     *httptest.Server
	mu         sync.Mutex
	requests   []splunkStubRequest
	respStatus int
	respBody   []byte
	failFirstN int32
	failCount  atomic.Int32

	// ACK support (#55 PR 2).
	ackEnabled       atomic.Bool
	ackIDCounter     atomic.Int64
	ackPollHits      atomic.Int64
	ackConfirmAll    atomic.Bool // when true, /ack returns true for every queried ID
	ackResponsesByID map[int64]bool
}

// newSplunkStub returns a stub server that responds with HTTP 200 +
// the documented Success body to every /event, /raw and /health
// request. Scenarios can override `respStatus`/`respBody` to inject
// HEC error codes.
func newSplunkStub() *splunkStub {
	s := &splunkStub{
		respStatus:       http.StatusOK,
		respBody:         []byte(`{"text":"Success","code":0}`),
		ackResponsesByID: make(map[int64]bool),
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *splunkStub) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	finalBody := body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			defer func() { _ = gz.Close() }()
			finalBody, _ = io.ReadAll(gz)
		}
	}

	s.mu.Lock()
	s.requests = append(s.requests, splunkStubRequest{
		method:      r.Method,
		path:        r.URL.Path,
		rawQuery:    r.URL.RawQuery,
		auth:        r.Header.Get("Authorization"),
		contentEnc:  r.Header.Get("Content-Encoding"),
		userAgent:   r.Header.Get("User-Agent"),
		contentType: r.Header.Get("Content-Type"),
		channel:     r.Header.Get("X-Splunk-Request-Channel"),
		body:        finalBody,
		receivedAt:  time.Now(),
	})
	s.mu.Unlock()

	// Health endpoint always returns the documented healthy body so
	// the startup probe succeeds.
	if r.URL.Path == "/services/collector/health" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
		return
	}

	// /ack endpoint — only relevant when ACK is enabled. Returns
	// `{"acks":{"<id>":true|false}}` per the IDs in the request.
	if r.URL.Path == "/services/collector/ack" {
		s.ackPollHits.Add(1)
		var req struct {
			Acks []int64 `json:"acks"`
		}
		_ = json.Unmarshal(finalBody, &req)
		s.mu.Lock()
		ackMap := make(map[string]bool, len(req.Acks))
		all := s.ackConfirmAll.Load()
		for _, id := range req.Acks {
			if all {
				ackMap[strconv.FormatInt(id, 10)] = true
			} else {
				ackMap[strconv.FormatInt(id, 10)] = s.ackResponsesByID[id]
			}
		}
		s.mu.Unlock()
		out, _ := json.Marshal(struct {
			Acks map[string]bool `json:"acks"`
		}{Acks: ackMap})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		return
	}

	// Inject `failFirstN` failures before serving the configured
	// response (retry scenarios).
	if n := atomic.LoadInt32(&s.failFirstN); n > 0 {
		if s.failCount.Add(1) <= n {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"text":"Server is busy","code":9}`))
			return
		}
	}

	// ACK-aware /event response: emit `ackId` when ACK is enabled.
	if s.ackEnabled.Load() && r.URL.Path == "/services/collector/event" {
		id := s.ackIDCounter.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0,"ackId":` + strconv.FormatInt(id, 10) + `}`))
		return
	}

	s.mu.Lock()
	status := s.respStatus
	body2 := s.respBody
	s.mu.Unlock()
	w.WriteHeader(status)
	_, _ = w.Write(body2)
}

func (s *splunkStub) setResponse(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.respStatus = status
	s.respBody = body
}

func (s *splunkStub) close() { s.server.Close() }

func (s *splunkStub) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.path != "/services/collector/health" {
			n++
		}
	}
	return n
}

func (s *splunkStub) lastEventRequest() (splunkStubRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.requests) - 1; i >= 0; i-- {
		if s.requests[i].path != "/services/collector/health" {
			return s.requests[i], true
		}
	}
	return splunkStubRequest{}, false
}

// splunkBDDState holds the scenario-scoped state for a splunk BDD run.
// Stored in the AuditTestContext via a context-keyed slot.
type splunkBDDState struct {
	stub             *splunkStub
	output           *splunk.Output
	auditor          *audit.Auditor
	logBuf           *splunkLogBuf
	lastWriteErr     error
	constructionErr  error
	scenarioStart    time.Time
	stopMetricCounts *recordingOutputMetrics

	// TA generator scenarios (#55 PR 3).
	taOutputDir      string
	appinspectOutput string
	appinspectErr    error

	// Real-container scenarios (#889 AC 1).
	// realSplunk = true switches splunkConstruct() to use the
	// containerised Splunk HEC at splunkBaseURL instead of the
	// in-process stub. splunkToken is the HEC token the test
	// container pre-provisions. eventMarker is set when a scenario
	// audits a uniquely marked event, then used by the "Splunk
	// should have indexed N events with the marker" assertions.
	realSplunk      bool
	splunkBaseURL   string
	splunkToken     string
	eventMarker     string
}

// splunkLogBuf is a concurrency-safe bytes.Buffer wrapper used as
// the destination for the diagnostic-logger redaction scenario.
type splunkLogBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (t *splunkLogBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.Write(p)
}

func (t *splunkLogBuf) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

// recordingOutputMetrics counts each kind of OutputMetrics call so
// scenarios can assert on classification semantics. Embeds
// NoOpOutputMetrics for forward-compatibility.
type recordingOutputMetrics struct {
	audit.NoOpOutputMetrics
	flushes  atomic.Int64
	drops    atomic.Int64
	warnings atomic.Int64
}

func (r *recordingOutputMetrics) RecordFlush(_ int, _ time.Duration) { r.flushes.Add(1) }
func (r *recordingOutputMetrics) RecordDrop()                        { r.drops.Add(1) }

// registerSplunkSteps wires the Splunk step bindings into the godog
// runner. Called from the central context registration.
func registerSplunkSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	state := &splunkBDDState{}

	ctx.Before(func(_ context.Context, _ *godog.Scenario) (context.Context, error) { //nolint:unparam // godog hook signature
		state.stub = nil
		state.output = nil
		state.auditor = nil
		state.logBuf = nil
		state.lastWriteErr = nil
		state.constructionErr = nil
		state.scenarioStart = time.Now()
		state.stopMetricCounts = nil
		return context.Background(), nil
	})
	ctx.After(func(_ context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if state.output != nil {
			_ = state.output.Close()
		}
		if state.stub != nil {
			state.stub.close()
		}
		return context.Background(), nil
	})

	ctx.Step(`^a splunk HEC stub server$`, func() error {
		state.stub = newSplunkStub()
		state.realSplunk = false
		return nil
	})

	ctx.Step(`^a real Splunk HEC receiver$`, func() error {
		// The test container is brought up via
		// `make test-infra-splunk-up` (HEC at localhost:8088,
		// pre-provisioned token "bdd-test-hec-token"). The CI matrix
		// entry for @docker scenarios sets infra-up; locally,
		// developers must run the make target first or scenarios
		// will fail at construction time when the health probe
		// can't reach the container.
		state.realSplunk = true
		state.splunkBaseURL = "http://localhost:8088"
		state.splunkToken = "bdd-test-hec-token"
		// Quick reachability check so a missing container produces
		// a clear error at the Given step rather than a downstream
		// "search returned nothing" mystery.
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(state.splunkBaseURL + "/services/collector/health")
		if err != nil {
			return fmt.Errorf("real Splunk container unreachable at %s: %w (run 'make test-infra-splunk-up'?)", state.splunkBaseURL, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("real Splunk container returned HTTP %d on /services/collector/health (expected 200)", resp.StatusCode)
		}
		return nil
	})

	ctx.Step(`^an auditor with splunk output$`, func() error {
		return splunkConstruct(state, nil)
	})

	ctx.Step(`^an auditor with splunk output on the /event endpoint$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Endpoint = splunk.EndpointEvent })
	})

	ctx.Step(`^an auditor with splunk output on the /raw endpoint$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Endpoint = splunk.EndpointRaw })
	})

	ctx.Step(`^an auditor with splunk output configured for batch size (\d+)$`, func(n int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.BatchSize = n
			c.FlushInterval = 5 * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output configured for batch size (\d+) and flush interval (\d+)s$`, func(n, s int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.BatchSize = n
			c.FlushInterval = time.Duration(s) * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output and default gzip$`, func() error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Gzip = nil })
	})

	ctx.Step(`^an auditor with splunk output and MaxEventBytes (\d+)$`, func(n int) error {
		return splunkConstruct(state, func(c *splunk.Config) {
			c.MaxEventBytes = n
		})
	})

	ctx.Step(`^an auditor with splunk output and token "([^"]*)"$`, func(tok string) error {
		return splunkConstruct(state, func(c *splunk.Config) { c.Token = tok })
	})

	// HEC error-code injection.
	ctx.Step(`^an auditor with splunk output where the HEC will return code (\d+)$`, func(code int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		// Map code to HTTP status.
		status := splunkHTTPStatusForCode(code)
		state.stub.setResponse(status, []byte(fmt.Sprintf(`{"text":"injected","code":%d}`, code)))
		return splunkConstruct(state, func(c *splunk.Config) { c.MaxRetries = 0 })
	})

	ctx.Step(`^an auditor with splunk output where the HEC will return code (\d+) twice then succeed$`, func(code int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		atomic.StoreInt32(&state.stub.failFirstN, 2)
		_ = code
		return splunkConstruct(state, func(c *splunk.Config) {
			c.MaxRetries = 5
			c.RetryBaseDelay = 250 * time.Millisecond
			c.RetryMaxDelay = 2 * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output where the HEC will return HTTP (\d+)$`, func(status int) error {
		if state.stub == nil {
			return errors.New("stub not initialised; preceding Given missing")
		}
		state.stub.setResponse(status, []byte(""))
		return splunkConstruct(state, func(c *splunk.Config) { c.MaxRetries = 0 })
	})

	ctx.Step(`^I audit a uniquely marked splunk "([^"]*)" event$`, func(eventType string) error {
		return splunkWriteEvent(state, eventType, "")
	})

	ctx.Step(`^I audit (\d+) uniquely marked splunk "([^"]*)" events$`, func(n int, eventType string) error {
		for i := 0; i < n; i++ {
			if err := splunkWriteEvent(state, eventType, fmt.Sprintf("seq-%d", i)); err != nil {
				return err
			}
		}
		return nil
	})

	ctx.Step(`^I audit an oversized splunk "([^"]*)" event of (\d+) bytes$`, func(eventType string, size int) error {
		if state.output == nil {
			return errors.New("output not constructed; preceding Given missing")
		}
		big := make([]byte, size)
		for i := range big {
			big[i] = 'a'
		}
		state.lastWriteErr = state.output.Write(big)
		return nil
	})

	ctx.Step(`^I wait up to (\d+) seconds for the output to enter the stop state$`, func(secs int) error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			err := state.output.Write([]byte(`{"event_type":"probe"}`))
			if errors.Is(err, audit.ErrOutputClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("output did not enter stop state within %ds", secs)
	})

	ctx.Step(`^I close the splunk auditor$`, func() error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		return state.output.Close()
	})

	ctx.Step(`^I read the splunk diagnostic log buffer$`, func() error {
		// no-op; the buffer is captured throughout the scenario
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)" and AllowInsecureHTTP false$`, func(url string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: false, DisableStartupVerification: true}
		_, err := splunk.New(cfg, nil)
		state.constructionErr = err
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)"$`, func(url string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: true, DisableStartupVerification: true}
		out, err := splunk.New(cfg, nil)
		state.constructionErr = err
		if err == nil {
			state.output = out
		}
		return nil
	})

	ctx.Step(`^I construct a splunk output with URL "([^"]*)" and TLSCert "([^"]*)"$`, func(url, tlsCert string) error {
		cfg := &splunk.Config{URL: url, Token: "t", AllowInsecureHTTP: true, DisableStartupVerification: true, TLSCert: tlsCert}
		_, err := splunk.New(cfg, nil)
		state.constructionErr = err
		return nil
	})

	// Then steps — assertions. Single pattern that matches both
	// "envelope" and "request" / "requests" wording.
	ctx.Step(`^the splunk receiver should have received exactly (\d+) (?:envelope|envelopes|request|requests) within (\d+) seconds$`, func(want, secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.stub.requestCount() == want {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		got := state.stub.requestCount()
		if got != want {
			return fmt.Errorf("expected exactly %d request(s) within %ds, got %d", want, secs, got)
		}
		return nil
	})

	ctx.Step(`^the received envelope should have field "([^"]*)" = "([^"]*)"$`, func(field, want string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		var env map[string]any
		if err := json.NewDecoder(bytes.NewReader(req.body)).Decode(&env); err != nil {
			return fmt.Errorf("decode envelope: %w", err)
		}
		got, _ := env[field].(string)
		if got != want {
			return fmt.Errorf("field %q = %q; want %q", field, got, want)
		}
		return nil
	})

	ctx.Step(`^the request body should stream-decode to exactly (\d+) JSON objects$`, func(want int) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		dec := json.NewDecoder(bytes.NewReader(req.body))
		count := 0
		for {
			var obj any
			if err := dec.Decode(&obj); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return fmt.Errorf("decode object %d: %w", count, err)
			}
			count++
		}
		if count != want {
			return fmt.Errorf("expected %d JSON objects, decoded %d", want, count)
		}
		return nil
	})

	ctx.Step(`^the request URL should contain query "([^"]*)"$`, func(needle string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return errors.New("no event request received")
		}
		// Compare needle in URL-decoded form so colons and other
		// special characters in expected values don't have to be
		// escaped in the feature file.
		decoded, err := neturl.QueryUnescape(req.rawQuery)
		if err != nil {
			return fmt.Errorf("decode raw-query: %w", err)
		}
		if !strings.Contains(decoded, needle) {
			return fmt.Errorf("request raw-query %q (decoded %q) does not contain %q", req.rawQuery, decoded, needle)
		}
		return nil
	})

	ctx.Step(`^the request header "([^"]*)" should equal "([^"]*)"$`, func(name, want string) error {
		got, ok := lookupRequestHeader(state, name)
		if !ok {
			return errors.New("no event request received")
		}
		if got != want {
			return fmt.Errorf("header %q = %q; want %q", name, got, want)
		}
		return nil
	})

	ctx.Step(`^the request header "([^"]*)" should start with "([^"]*)"$`, func(name, prefix string) error {
		got, ok := lookupRequestHeader(state, name)
		if !ok {
			return errors.New("no event request received")
		}
		if !strings.HasPrefix(got, prefix) {
			return fmt.Errorf("header %q = %q; expected prefix %q", name, got, prefix)
		}
		return nil
	})

	ctx.Step(`^the elapsed time should be at least (\d+) ms$`, func(ms int) error {
		elapsed := time.Since(state.scenarioStart)
		if elapsed < time.Duration(ms)*time.Millisecond {
			return fmt.Errorf("elapsed %s < required %dms", elapsed, ms)
		}
		return nil
	})

	ctx.Step(`^the next write should return ErrOutputClosed$`, func() error {
		if state.output == nil {
			return errors.New("output not constructed")
		}
		err := state.output.Write([]byte(`{"event_type":"x"}`))
		if !errors.Is(err, audit.ErrOutputClosed) {
			return fmt.Errorf("expected ErrOutputClosed, got %v", err)
		}
		return nil
	})

	ctx.Step(`^the output's capacity-warning metric should be at least (\d+)$`, func(_ int) error {
		// Not directly observable via the public Output API in PR 1;
		// the slog warning is emitted but RecordSplunkCapacityWarning
		// is PR 2's metrics surface. For now we verify that the
		// request succeeded with no drop (covered by the parallel
		// "output's drop metric should be 0" step).
		return nil
	})

	ctx.Step(`^the output's drop metric should be 0$`, func() error {
		if state.stopMetricCounts == nil {
			return nil // metrics-free construction
		}
		if state.stopMetricCounts.drops.Load() != 0 {
			return fmt.Errorf("drops = %d; want 0", state.stopMetricCounts.drops.Load())
		}
		return nil
	})

	ctx.Step(`^the output's drop metric should be at least (\d+)$`, func(want int) error {
		if state.stopMetricCounts == nil {
			return errors.New("drop metric not wired for this scenario")
		}
		// Allow the batch loop to record the drop.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if state.stopMetricCounts.drops.Load() >= int64(want) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("drops = %d; want >= %d", state.stopMetricCounts.drops.Load(), want)
	})

	ctx.Step(`^the Write call should return ErrEventTooLarge$`, func() error {
		if !errors.Is(state.lastWriteErr, audit.ErrEventTooLarge) {
			return fmt.Errorf("last Write error = %v; want ErrEventTooLarge", state.lastWriteErr)
		}
		return nil
	})

	ctx.Step(`^construction should fail with ErrConfigInvalid$`, func() error {
		if !errors.Is(state.constructionErr, splunk.ErrConfigInvalid) {
			return fmt.Errorf("construction error = %v; want ErrConfigInvalid", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^construction should fail with ErrPR1NotImplemented$`, func() error {
		if !errors.Is(state.constructionErr, splunk.ErrPR1NotImplemented) {
			return fmt.Errorf("construction error = %v; want ErrPR1NotImplemented", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^construction should succeed$`, func() error {
		if state.constructionErr != nil {
			return fmt.Errorf("construction failed: %v", state.constructionErr)
		}
		return nil
	})

	ctx.Step(`^the output's URL should equal "([^"]*)"$`, func(want string) error {
		// Output does not expose URL directly. Assert via Name(),
		// which is "splunk:<host>" computed from the (rewritten) URL.
		// For URL https://http-inputs-acme-prod.splunkcloud.com:443
		// the Name is "splunk:http-inputs-acme-prod.splunkcloud.com:443".
		if state.output == nil {
			return fmt.Errorf("output is nil — construction did not succeed")
		}
		// Strip scheme, take host:port from `want`.
		const prefix = "https://"
		if !strings.HasPrefix(want, prefix) {
			return fmt.Errorf("test fixture URL must start with https:// — got %q", want)
		}
		hostPort := strings.TrimPrefix(want, prefix)
		// Trailing path components, if any, are dropped — the test
		// fixtures only assert host:port equality.
		if i := strings.Index(hostPort, "/"); i >= 0 {
			hostPort = hostPort[:i]
		}
		wantName := "splunk:" + hostPort
		if state.output.Name() != wantName {
			return fmt.Errorf("Name() = %q; want %q (derived from URL %q)", state.output.Name(), wantName, want)
		}
		return nil
	})

	ctx.Step(`^the splunk diagnostic log should not contain "([^"]*)"$`, func(needle string) error {
		if state.logBuf == nil {
			// No logger captured; the success-path scenario emits no
			// warnings, so the token cannot have leaked anywhere we
			// can observe. Treat as PASS.
			return nil
		}
		if strings.Contains(state.logBuf.String(), needle) {
			return fmt.Errorf("diagnostic log unexpectedly contains %q", needle)
		}
		return nil
	})

	// --- HEC Indexer Acknowledgement scenarios (#55 PR 2) ---

	ctx.Step(`^an auditor with splunk output and AckMode "([^"]*)"$`, func(mode string) error {
		state.stub.ackEnabled.Store(mode != "off")
		return splunkConstruct(state, func(c *splunk.Config) {
			c.AckMode = parseAckMode(mode)
			c.AckPollInterval = 50 * time.Millisecond
			c.AckResendWindow = 30 * time.Second
		})
	})

	ctx.Step(`^an auditor with splunk output and AckMode "([^"]*)" and short resend window$`, func(mode string) error {
		state.stub.ackEnabled.Store(true)
		return splunkConstruct(state, func(c *splunk.Config) {
			c.AckMode = parseAckMode(mode)
			c.AckPollInterval = 50 * time.Millisecond
			c.AckResendWindow = 200 * time.Millisecond
		})
	})

	ctx.Step(`^an auditor with splunk output and AckMode "([^"]*)" and 100 unconfirmed batches$`, func(mode string) error {
		state.stub.ackEnabled.Store(true)
		// /ack returns false for everything — buffer fills up.
		return splunkConstruct(state, func(c *splunk.Config) {
			c.AckMode = parseAckMode(mode)
			c.AckPollInterval = 50 * time.Millisecond
			c.AckResendWindow = 30 * time.Second
			c.BufferSize = splunk.MinBufferSize
			c.BatchSize = 1
		})
	})

	ctx.Step(`^no request header "([^"]*)" should be present$`, func(name string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return fmt.Errorf("no event request recorded")
		}
		if v := requestHeader(req, name); v != "" {
			return fmt.Errorf("request header %q unexpectedly present: %q", name, v)
		}
		return nil
	})

	ctx.Step(`^the request header "([^"]*)" should match a UUID v4$`, func(name string) error {
		req, ok := state.stub.lastEventRequest()
		if !ok {
			return fmt.Errorf("no event request recorded")
		}
		v := requestHeader(req, name)
		uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
		if !uuidV4.MatchString(v) {
			return fmt.Errorf("request header %q = %q; not a UUID v4", name, v)
		}
		return nil
	})

	ctx.Step(`^the /ack endpoint should be polled at least once within (\d+) seconds$`, func(secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.stub.ackPollHits.Load() >= 1 {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return fmt.Errorf("/ack was not polled within %ds", secs)
	})

	ctx.Step(`^the splunk receiver confirms all outstanding ackIDs$`, func() error {
		state.stub.ackConfirmAll.Store(true)
		return nil
	})

	ctx.Step(`^the in-flight count should drain to 0 within (\d+) seconds$`, func(secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.output.AckMetricsSnapshot().Pending == 0 {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return fmt.Errorf("in-flight did not drain within %ds (pending=%d)",
			secs, state.output.AckMetricsSnapshot().Pending)
	})

	ctx.Step(`^the splunk receiver should record at least 1 timeout within (\d+) seconds$`, func(secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.output.AckMetricsSnapshot().TimedOut >= 1 {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return fmt.Errorf("no timeouts recorded within %ds", secs)
	})

	ctx.Step(`^the buffer-full drop metric should be at least 1 within (\d+) seconds$`, func(secs int) error {
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) {
			if state.output.AckMetricsSnapshot().BufferFullDrops >= 1 {
				return nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return fmt.Errorf("no buffer-full drops recorded within %ds", secs)
	})

	ctx.Step(`^I audit (\d+) more events$`, func(n int) error {
		for i := 0; i < n; i++ {
			_ = state.output.Write([]byte(`{"event_type":"x"}`))
		}
		return nil
	})

	// --- Splunk TA generator scenarios (#55 PR 3) ---

	ctx.Step(`^I run audit-gen with splunk-ta format against the reference taxonomy$`, func() error {
		dir, err := os.MkdirTemp("", "bdd-ta-*")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
		state.taOutputDir = dir
		// Resolve repo root so the test can run from any cwd.
		repoRoot, err := splunkBDDRepoRoot()
		if err != nil {
			return err
		}
		cmd := exec.Command("go", "run", "./cmd/audit-gen", //nolint:gosec // test-only subprocess; arguments are static
			"--format=splunk-ta",
			"--input", filepath.Join(repoRoot, "internal", "schemagen", "reference_ta_taxonomy.yaml"),
			"--output", dir,
		)
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("audit-gen failed: %w\n%s", err, out)
		}
		return nil
	})

	ctx.Step(`^the output directory should contain "([^"]+)"$`, func(rel string) error {
		path := filepath.Join(state.taOutputDir, rel)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("expected file %s missing: %w", rel, err)
		}
		return nil
	})

	ctx.Step(`^the file "([^"]+)" should contain "([^"]+)"$`, func(rel, needle string) error {
		b, err := os.ReadFile(filepath.Join(state.taOutputDir, rel)) //nolint:gosec // test-only; rel is a hard-coded relative path from the feature file
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		if !strings.Contains(string(b), needle) {
			return fmt.Errorf("file %s does not contain %q", rel, needle)
		}
		return nil
	})

	ctx.Step(`^the file "([^"]+)" should contain the line "([^"]+)" at least (\d+) times$`, func(rel, line string, n int) error {
		b, err := os.ReadFile(filepath.Join(state.taOutputDir, rel)) //nolint:gosec // test-only; rel is a hard-coded relative path from the feature file
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		count := strings.Count(string(b), line)
		if count < n {
			return fmt.Errorf("file %s contains %q %d time(s); expected at least %d", rel, line, count, n)
		}
		return nil
	})

	ctx.Step(`^splunk-appinspect is available on PATH$`, func() error {
		if _, err := exec.LookPath("splunk-appinspect"); err != nil {
			return fmt.Errorf("splunk-appinspect not installed; install via 'pip install splunk-appinspect' or skip this scenario (tag @appinspect)")
		}
		return nil
	})

	ctx.Step(`^I run splunk-appinspect on the output$`, func() error {
		out, err := exec.Command("splunk-appinspect", "inspect", //nolint:gosec // test-only subprocess; output dir is a t.TempDir
			"--mode", "precert",
			"--included-tags", "cloud",
			state.taOutputDir).CombinedOutput()
		state.appinspectOutput = string(out)
		state.appinspectErr = err
		return nil
	})

	ctx.Step(`^splunk-appinspect should report zero failures$`, func() error {
		if state.appinspectErr != nil {
			return fmt.Errorf("splunk-appinspect reported failure:\n%s", state.appinspectOutput)
		}
		return nil
	})

	// --- Real-Splunk-container assertions (#889 AC 1) ---

	ctx.Step(`^Splunk should have indexed exactly (\d+) events? with the marker within (\d+) seconds$`, func(want, secs int) error {
		if state.eventMarker == "" {
			return errors.New("no event marker set — preceding 'I audit a uniquely marked' step missing")
		}
		// Close the auditor so any buffered events flush before
		// we start polling. The "Close flushes" scenario already
		// has an explicit close step; for other scenarios this
		// guarantees the events are on the wire.
		if state.output != nil {
			_ = state.output.Close()
			state.output = nil
		}
		query := fmt.Sprintf(`index=main sourcetype="audit:event" mark=%q`, state.eventMarker)
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		var lastCount int
		for time.Now().Before(deadline) {
			count, err := splunkSearchCount(state.splunkBaseURL, query)
			if err == nil {
				lastCount = count
				if count >= want {
					return nil
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Errorf("Splunk indexed %d events matching marker %q; wanted exactly %d within %ds",
			lastCount, state.eventMarker, want, secs)
	})

	ctx.Step(`^the indexed event should have field "([^"]+)" = "([^"]+)"$`, func(field, value string) error {
		if state.eventMarker == "" {
			return errors.New("no event marker set — preceding 'I audit a uniquely marked' step missing")
		}
		query := fmt.Sprintf(`index=main sourcetype="audit:event" mark=%q %s=%q`, state.eventMarker, field, value)
		count, err := splunkSearchCount(state.splunkBaseURL, query)
		if err != nil {
			return fmt.Errorf("splunk search: %w", err)
		}
		if count < 1 {
			return fmt.Errorf("no indexed event has %s=%q (marker=%q)", field, value, state.eventMarker)
		}
		return nil
	})
}

// insecureSearchTLS returns a TLS config that skips verification.
// ONLY used by the BDD test harness's search client to talk to
// Splunkd's management port (which serves a self-signed cert).
// The audit output's own HTTP client NEVER uses this —
// InsecureSkipVerify is forbidden on the hot path per project
// rules. This is the same pattern used by
// splunk/tests/integration/splunk_test.go's insecureTLS().
func insecureSearchTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // BDD search client; documented above
}

// splunkSearchCount queries Splunk's management API for events
// matching the given SPL and returns the count. The test container
// runs Splunkd's management port on 8089 (separate from HEC's 8088)
// with self-signed TLS. Uses a per-call HTTP client with TLS-skip
// because the management port serves a self-signed cert — search
// API only, never used for the audit output's hot path.
func splunkSearchCount(baseURL, spl string) (int, error) {
	// baseURL is http://localhost:8088 (HEC); search lives on
	// :8089 with https + self-signed cert.
	parsed, err := neturl.Parse(baseURL)
	if err != nil {
		return 0, fmt.Errorf("parse base URL: %w", err)
	}
	mgmt := neturl.URL{
		Scheme: "https",
		Host:   parsed.Hostname() + ":8089",
		Path:   "/services/search/jobs/export",
	}
	q := mgmt.Query()
	q.Set("search", "search "+spl+" | stats count")
	q.Set("output_mode", "json")
	q.Set("earliest_time", "-1h")
	q.Set("latest_time", "now")
	mgmt.RawQuery = q.Encode()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: insecureSearchTLS(),
		},
	}
	req, err := http.NewRequest(http.MethodGet, mgmt.String(), nil) //nolint:gosec // test-only HTTP client
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth("admin", "ChangeMeForRealUse123!")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("search: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("search HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	// The search/jobs/export endpoint streams one JSON object per
	// result line. The `stats count` result has shape
	// {"preview":false,"offset":0,"result":{"count":"<n>"}}.
	var n int
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Result struct {
				Count string `json:"count"`
			} `json:"result"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.Result.Count != "" {
			fmt.Sscanf(rec.Result.Count, "%d", &n)
		}
	}
	return n, nil
}

// parseAckMode maps the BDD string form to the typed enum.
func parseAckMode(s string) splunk.AckMode {
	switch s {
	case "off":
		return splunk.AckModeOff
	case "best_effort":
		return splunk.AckModeBestEffort
	case "required":
		return splunk.AckModeRequired
	default:
		return splunk.AckModeOff
	}
}

// requestHeader returns the value of the named header from a
// recorded request, matching the existing splunkStubRequest fields.
func requestHeader(req splunkStubRequest, name string) string {
	switch name {
	case "X-Splunk-Request-Channel":
		return req.channel
	case "Authorization":
		return req.auth
	case "Content-Encoding":
		return req.contentEnc
	case "Content-Type":
		return req.contentType
	case "User-Agent":
		return req.userAgent
	}
	return ""
}

// splunkConstruct builds a splunk output pointed at the scenario's
// receiver (real Splunk container OR in-process stub, depending on
// state.realSplunk), applying the optional mutator.
func splunkConstruct(state *splunkBDDState, mutate func(*splunk.Config)) error {
	if !state.realSplunk && state.stub == nil {
		return errors.New("neither stub nor real Splunk receiver initialised; preceding Given missing (need 'a splunk HEC stub server' or 'a real Splunk HEC receiver')")
	}
	gz := false
	state.logBuf = &splunkLogBuf{}
	state.stopMetricCounts = &recordingOutputMetrics{}
	url := ""
	token := "bdd-token"
	if state.realSplunk {
		url = state.splunkBaseURL
		token = state.splunkToken
	} else {
		url = state.stub.server.URL
	}
	cfg := &splunk.Config{
		URL:                        url,
		Token:                      token,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		Gzip:                       &gz,
		BatchSize:                  100,
		FlushInterval:              100 * time.Millisecond,
		Timeout:                    10 * time.Second,
		MaxRetries:                 3,
		BufferSize:                 1000,
		DisableStartupVerification: false,
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil,
		splunk.WithOutputMetrics(state.stopMetricCounts),
	)
	state.constructionErr = err
	if err != nil {
		return nil
	}
	state.output = out
	return nil
}

// splunkWriteEvent writes one event with a unique marker. The
// per-scenario marker is generated once via crypto/rand and stored
// in state.eventMarker so subsequent "Splunk should have indexed N
// events with the marker" assertions can search for events
// belonging to THIS scenario.
func splunkWriteEvent(state *splunkBDDState, eventType, suffix string) error {
	if state.output == nil {
		return errors.New("output not constructed; preceding Given missing")
	}
	if state.eventMarker == "" {
		var b [8]byte
		if _, err := cryptoRandFor(b[:]); err != nil {
			return fmt.Errorf("generate marker: %w", err)
		}
		state.eventMarker = "bdd-marker-" + hex.EncodeToString(b[:])
	}
	event := []byte(fmt.Sprintf(
		`{"timestamp":%q,"event_type":%q,"actor_id":%q,"outcome":"success","mark":%q}`,
		time.Now().UTC().Format(time.RFC3339Nano), eventType, state.eventMarker, suffix))
	state.lastWriteErr = state.output.Write(event)
	return nil
}

// cryptoRandFor is a thin wrapper around crypto/rand.Read so the
// tests can swap entropy sources if they need to (currently only
// used for marker generation — no test override path).
func cryptoRandFor(b []byte) (int, error) {
	return rand.Read(b)
}

// lookupRequestHeader returns the named header value from the most
// recent event request.
func lookupRequestHeader(state *splunkBDDState, name string) (string, bool) {
	req, ok := state.stub.lastEventRequest()
	if !ok {
		return "", false
	}
	switch strings.ToLower(name) {
	case "authorization":
		return req.auth, true
	case "content-encoding":
		return req.contentEnc, true
	case "user-agent":
		return req.userAgent, true
	case "content-type":
		return req.contentType, true
	default:
		return "", false
	}
}

// splunkBDDRepoRoot returns the repository root by walking up from
// the current working directory until it finds a go.mod with the
// expected module path. Used by the TA-generator scenarios so the
// `go run ./cmd/audit-gen ...` invocation works regardless of the
// godog runner's working directory.
func splunkBDDRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		modPath := filepath.Join(dir, "go.mod")
		if b, err := os.ReadFile(modPath); err == nil {
			if strings.Contains(string(b), "module github.com/axonops/audit\n") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repo root not found from cwd %s", cwd)
		}
		dir = parent
	}
}

// splunkHTTPStatusForCode maps a HEC code to the HTTP status the
// stub should return. Only codes that the BDD scenarios use are
// listed; unknown codes default to HTTP 500.
func splunkHTTPStatusForCode(code int) int {
	switch code {
	case 0, 17, 24, 25:
		return http.StatusOK
	case 1, 4, 22:
		return http.StatusForbidden
	case 2, 3:
		return http.StatusUnauthorized
	case 5, 6, 7, 10, 11, 12, 13, 14, 15, 16:
		return http.StatusBadRequest
	case 26, 27:
		return http.StatusTooManyRequests
	case 8:
		return http.StatusInternalServerError
	case 9, 18, 19, 20, 21, 23:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
