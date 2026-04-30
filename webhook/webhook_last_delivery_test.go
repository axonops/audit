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

package webhook_test

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookOutput_LastDeliveryNanos_AdvancesOn2xx verifies the
// LastDeliveryReporter implementation timestamps the most recent
// HTTP 2xx response (#753 AC #4).
func TestWebhookOutput_LastDeliveryNanos_AdvancesOn2xx(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	out := newTestWebhookOutput(t, srv.url())

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"never-delivered output must report 0")

	require.NoError(t, out.Write([]byte(`{"event_type":"first"}`)))
	require.True(t, srv.waitForRequests(1, 5*time.Second), "server should receive first request")

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > 0
	}, 5*time.Second, 5*time.Millisecond,
		"successful delivery must advance the timestamp")
	first := out.LastDeliveryNanos()

	time.Sleep(2 * time.Millisecond)
	require.NoError(t, out.Write([]byte(`{"event_type":"second"}`)))
	require.True(t, srv.waitForRequests(2, 5*time.Second), "server should receive second request")

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > first
	}, 5*time.Second, 5*time.Millisecond,
		"successive 2xx responses must monotonically advance")
}

// TestWebhookOutput_LastDeliveryNanos_FrozenOn5xx verifies that
// retried-and-exhausted 5xx responses do NOT advance the timestamp
// (#753 AC #3).
func TestWebhookOutput_LastDeliveryNanos_FrozenOn5xx(t *testing.T) {
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.MaxRetries = 2
	})

	require.NoError(t, out.Write([]byte(`{"event_type":"doomed"}`)))

	// Wait for the server to receive at least one request — confirms
	// the batch goroutine has reached the HTTP layer.
	require.True(t, srv.waitForRequests(1, 5*time.Second),
		"server should receive at least one request")

	// Settle window for retry exhaustion (jittered backoff up to ~5s).
	time.Sleep(2 * time.Second)

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"5xx-retry-exhausted batch must NOT advance the timestamp")
}

// TestWebhookOutput_LastDeliveryNanos_AdvancesAfterRetrySuccess
// verifies that a retry success after initial 5xx still advances
// the timestamp — the gate is "any 2xx", not "first try 2xx".
func TestWebhookOutput_LastDeliveryNanos_AdvancesAfterRetrySuccess(t *testing.T) {
	var attempts atomic.Int32
	srv := newWebhookTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// First attempt 500, subsequent 200.
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	out := newTestWebhookOutput(t, srv.url(), func(c *webhook.Config) {
		c.MaxRetries = 3
	})

	require.NoError(t, out.Write([]byte(`{"event_type":"retry-success"}`)))
	require.True(t, srv.waitForRequests(2, 5*time.Second), "expected retry to be issued")

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > 0
	}, 5*time.Second, 5*time.Millisecond,
		"a 2xx after a retry must advance the timestamp")
}
