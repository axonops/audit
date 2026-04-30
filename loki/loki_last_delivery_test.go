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
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLokiOutput_LastDeliveryNanos_AdvancesOn2xx verifies that the
// LastDeliveryReporter implementation timestamps the most recent
// successful push API response (#753 AC #4).
func TestLokiOutput_LastDeliveryNanos_AdvancesOn2xx(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	out, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"never-delivered output must report 0")

	require.NoError(t, out.Write([]byte(`{"event_type":"first"}`)))

	require.Eventually(t, func() bool {
		return requests.Load() >= 1 && out.LastDeliveryNanos() > 0
	}, 5*time.Second, 5*time.Millisecond,
		"successful push must advance the timestamp")
	first := out.LastDeliveryNanos()

	time.Sleep(2 * time.Millisecond)
	require.NoError(t, out.Write([]byte(`{"event_type":"second"}`)))

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > first
	}, 5*time.Second, 5*time.Millisecond,
		"successive 2xx pushes must monotonically advance")
}

// TestLokiOutput_LastDeliveryNanos_FrozenOn5xx verifies that
// retries-exhausted 5xx responses do NOT advance the timestamp
// (#753 AC #3).
func TestLokiOutput_LastDeliveryNanos_FrozenOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	out, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		BufferSize:         100,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event_type":"doomed"}`)))

	// Settle window for retry exhaustion (jittered backoff up to ~5s).
	time.Sleep(2 * time.Second)

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"5xx-retry-exhausted batch must NOT advance the timestamp")
}
