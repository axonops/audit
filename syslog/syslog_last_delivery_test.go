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

package syslog_test

import (
	"testing"
	"time"

	"github.com/axonops/audit/syslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSyslogOutput_LastDeliveryNanos_AdvancesOnSuccess verifies that
// the LastDeliveryReporter implementation timestamps the most recent
// successful TCP delivery (#753 AC #4).
func TestSyslogOutput_LastDeliveryNanos_AdvancesOnSuccess(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"never-delivered output must report 0")

	require.NoError(t, out.Write([]byte(`{"event_type":"first"}`)))
	require.True(t, srv.waitForData(2*time.Second), "server should receive first event")

	// Wait briefly for the writer goroutine to record the delivery
	// timestamp after the network write returns.
	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > 0
	}, 2*time.Second, 5*time.Millisecond,
		"successful delivery must advance the timestamp")
	first := out.LastDeliveryNanos()

	time.Sleep(2 * time.Millisecond)
	require.NoError(t, out.Write([]byte(`{"event_type":"second"}`)))

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > first
	}, 2*time.Second, 5*time.Millisecond,
		"successive successful deliveries must monotonically advance")

	require.NoError(t, out.Close())
}

// TestSyslogOutput_LastDeliveryNanos_FrozenAfterServerKill verifies
// that delivery failures do NOT advance the timestamp (#753 AC #3).
// Establishes a successful initial delivery, kills the server,
// drives writes until at least one failure is observed via the
// metrics recorder, then verifies the timestamp does not advance
// while only failures are happening.
func TestSyslogOutput_LastDeliveryNanos_FrozenAfterServerKill(t *testing.T) {
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       addr,
		MaxRetries:    1, // fail fast,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	out.SetOutputMetrics(m)

	require.NoError(t, out.Write([]byte(`{"event_type":"first"}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server. TCP OS buffers may still absorb a few writes;
	// drive events until the metrics recorder observes a failed
	// reconnect, which means the writer goroutine has actually seen
	// a delivery error.
	srv.close()

	go func() {
		for range 200 {
			_ = out.Write([]byte(`{"event_type":"doomed"}`))
			time.Sleep(2 * time.Millisecond)
		}
	}()

	m.waitForReconnectCount(t, addr, false, 1, 5*time.Second)

	// Capture the timestamp AFTER the writer has begun failing.
	// Subsequent failing deliveries must not advance it.
	frozen := out.LastDeliveryNanos()
	require.Greater(t, frozen, int64(0),
		"the initial successful write must have set a baseline")

	// Settle window: any further failing deliveries arrive here.
	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, frozen, out.LastDeliveryNanos(),
		"failing deliveries must NOT advance the timestamp")

	require.NoError(t, out.Close())
}
