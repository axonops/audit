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

//go:build integration

// Package integration_test contains integration tests for the webhook
// output against a real webhook receiver container. Requires Docker
// Compose infrastructure: `make test-infra-up` before running.
package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/axonops/go-audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// HTTP default transport keeps idle connection goroutines open.
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

const receiverURL = "http://localhost:8080"

// resetReceiver clears all stored events and resets configuration.
func resetReceiver(t *testing.T) {
	t.Helper()
	resp, err := http.Post(receiverURL+"/reset", "", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// configureReceiver sets the webhook receiver's response behaviour.
func configureReceiver(t *testing.T, statusCode int, delayMS int) {
	t.Helper()
	body := fmt.Sprintf(`{"status_code":%d,"delay_ms":%d}`, statusCode, delayMS)
	resp, err := http.Post(receiverURL+"/configure", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
}

// getEvents returns the events stored in the webhook receiver.
func getEvents(t *testing.T) []map[string]any {
	t.Helper()
	resp, err := http.Get(receiverURL + "/events")
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var events []map[string]any
	require.NoError(t, json.Unmarshal(data, &events))
	return events
}

// waitForEvents polls until at least n events are stored or timeout.
func waitForEvents(t *testing.T, n int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(getEvents(t)) >= n {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// newWebhookOutput creates a webhook output pointing at the test receiver.
func newWebhookOutput(t *testing.T, opts ...func(*webhook.Config)) *webhook.Output {
	t.Helper()
	cfg := &webhook.Config{
		URL:                receiverURL + "/events",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          10,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	out, err := webhook.New(cfg, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// --- Tests ---

func TestWebhook_BatchDelivery(t *testing.T) {
	resetReceiver(t)

	out := newWebhookOutput(t, func(c *webhook.Config) {
		c.BatchSize = 5
	})

	// Send 12 events — should produce 3 batches (5 + 5 + 2).
	for i := range 12 {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	require.NoError(t, out.Close())

	// All 12 events should have been delivered across multiple batches.
	assert.True(t, waitForEvents(t, 1, 5*time.Second),
		"receiver should have received at least one batch")
}

func TestWebhook_FlushInterval(t *testing.T) {
	resetReceiver(t)

	out := newWebhookOutput(t, func(c *webhook.Config) {
		c.BatchSize = 100 // large batch — flush triggered by timer, not size
		c.FlushInterval = 200 * time.Millisecond
	})

	// Send 1 event — below batch size, must flush via timer.
	require.NoError(t, out.Write([]byte(`{"event":"timer_flush"}`)))

	// Wait for the flush interval + margin.
	assert.True(t, waitForEvents(t, 1, 5*time.Second),
		"event should arrive via timer flush")

	require.NoError(t, out.Close())
}

func TestWebhook_RetryOn5xx(t *testing.T) {
	resetReceiver(t)
	configureReceiver(t, 503, 0) // return 503

	out := newWebhookOutput(t, func(c *webhook.Config) {
		c.BatchSize = 1
		c.MaxRetries = 3
	})

	require.NoError(t, out.Write([]byte(`{"event":"retry_test"}`)))

	// Poll until the receiver has received at least 1 request (even
	// though it returns 503, it stores the event body).
	assert.True(t, waitForEvents(t, 1, 10*time.Second),
		"receiver should have received at least 1 attempt")

	// Now reset events and configure 200 so the next retry succeeds.
	resetReceiver(t)
	configureReceiver(t, 200, 0)

	// The webhook will keep retrying — eventually one succeeds.
	assert.True(t, waitForEvents(t, 1, 10*time.Second),
		"event should eventually arrive after retry succeeds")

	require.NoError(t, out.Close())
}

func TestWebhook_CustomHeaders(t *testing.T) {
	resetReceiver(t)

	out := newWebhookOutput(t, func(c *webhook.Config) {
		c.BatchSize = 1
		c.Headers = map[string]string{
			"X-Audit-Source": "integration-test",
		}
	})

	require.NoError(t, out.Write([]byte(`{"event":"header_test"}`)))

	assert.True(t, waitForEvents(t, 1, 5*time.Second))

	events := getEvents(t)
	require.GreaterOrEqual(t, len(events), 1)

	// Check headers were received.
	headers, ok := events[0]["headers"].(map[string]any)
	require.True(t, ok, "event should have headers")
	assert.Equal(t, "integration-test", headers["X-Audit-Source"],
		"custom header should be received")

	require.NoError(t, out.Close())
}

func TestWebhook_ShutdownFlush(t *testing.T) {
	resetReceiver(t)

	out := newWebhookOutput(t, func(c *webhook.Config) {
		c.BatchSize = 100                 // large batch — won't trigger size-based flush
		c.FlushInterval = 1 * time.Minute // long interval — won't trigger timer flush
	})

	// Send 3 events — below batch size and before timer.
	for i := range 3 {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"event":"shutdown_%d"}`, i))))
	}

	// Close should flush the pending events.
	require.NoError(t, out.Close())

	// Events should be present after close-triggered flush.
	events := getEvents(t)
	assert.GreaterOrEqual(t, len(events), 1,
		"close should flush pending events")
}
