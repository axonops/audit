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
	"bytes"
	"testing"
	"time"

	"github.com/axonops/audit/syslog"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestSyslogOutput_Property_ConservationInvariant verifies that for any N
// events submitted over TCP, flushes + drops == N after Close. The test
// uses a real in-process TCP server (newMockSyslogServer, already defined
// in syslog_test.go) so the network path is exercised.
//
// Buffer is sized well above N to eliminate drops. All events go through
// writeEntry → writeLoop → srslog → TCP → mock server. The only accounting
// path exercised is RecordFlush; drops and errors must be zero.
func TestSyslogOutput_Property_ConservationInvariant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// 1 to 200 events per trial. Kept lower than the file test
		// because each event transits a real TCP connection.
		n := rapid.IntRange(1, 200).Draw(rt, "n")

		srv := newMockSyslogServer(t)
		t.Cleanup(srv.close)

		out, err := syslog.New(&syslog.Config{
			Network:    "tcp",
			Address:    srv.addr(),
			BufferSize: 500, // >> max N of 200
		})
		require.NoError(rt, err)

		om := &mockOutputMetrics{}
		out.SetOutputMetrics(om)

		for i := range n {
			data := []byte(`{"seq":` + itoa(i) + `}` + "\n")
			writeErr := out.Write(data)
			require.NoError(rt, writeErr,
				"Write must not return an error when buffer has capacity and output is open")
		}

		require.NoError(rt, out.Close())

		got := om.flushes.Load() + om.drops.Load() + om.errors.Load()
		if got != int64(n) {
			rt.Fatalf("conservation invariant violated: flushes(%d) + drops(%d) + errors(%d) = %d, want %d",
				om.flushes.Load(), om.drops.Load(), om.errors.Load(), got, n)
		}

		// In the happy path, all events must be flushed — no drops,
		// no errors.
		if om.drops.Load() != 0 {
			rt.Fatalf("unexpected drops=%d with buffer sized above N=%d",
				om.drops.Load(), n)
		}
		if om.errors.Load() != 0 {
			rt.Fatalf("unexpected errors=%d with a reliable mock TCP server",
				om.errors.Load())
		}
	})
}

// TestSyslogOutput_Property_CopySafety verifies that mutating the []byte
// slice passed to Write after Write returns does not affect what is sent
// over TCP.
//
// The syslog output copies data inside enqueue() before the slice is
// sent to writeLoop. This test verifies that contract: the caller may
// immediately reuse (overwrite) the backing array once Write returns.
//
// Design rationale for payload encoding:
// We use printable ASCII strings rather than raw binary because the
// syslog framer wraps payloads in an RFC 5424 envelope. Parsing the
// envelope out of the raw TCP stream would require a full RFC 5424
// parser. Instead, we embed a unique sentinel string that cannot appear
// in syslog framing characters, then verify the sentinel is present
// (original delivered) and that a 0xFF-overwritten version is absent
// (mutation did not propagate).
//
// We use rapid.StringOf to generate only printable ASCII content
// (letters, digits, punctuation), which is unambiguous in the syslog
// TCP stream and cannot collide with either the RFC 5424 header or the
// 0xFF poison bytes.
func TestSyslogOutput_Property_CopySafety(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Printable ASCII rune generator — letters, digits, safe
		// punctuation. This avoids bytes that appear in RFC 5424
		// framing so that the payload is unambiguously identifiable
		// in the TCP stream.
		alphabet := []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.")
		printableRune := rapid.RuneFrom(alphabet)
		content := rapid.StringOfN(printableRune, 4, 128, -1).Draw(rt, "content")

		// Embed a unique sentinel that cannot appear in syslog framing.
		// The sentinel is prefix + generated content. The 0xFF poison
		// cannot appear in any valid RFC 5424 frame header.
		payload := []byte("COPYSAFETY:" + content)

		srv := newMockSyslogServer(t)
		t.Cleanup(srv.close)

		out, err := syslog.New(&syslog.Config{
			Network: "tcp",
			Address: srv.addr(),
		})
		require.NoError(rt, err)

		// Capture the original content before enqueue copies it.
		original := make([]byte, len(payload))
		copy(original, payload)

		require.NoError(rt, out.Write(payload))

		// Overwrite the caller's slice with 0xFF — simulating the drain
		// loop reusing its format cache buffer for the next event.
		for i := range payload {
			payload[i] = 0xFF
		}

		// Close flushes the async buffer: writeLoop drains the channel
		// and sends all events to the syslog writer. After Close returns,
		// the bytes have been written to the TCP socket. However, the
		// mock server's read goroutine reads asynchronously with a
		// 100ms deadline, so data may not yet be in srv.messages.
		// We call Close first to ensure the socket write completes,
		// then wait for the sentinel to appear in the server buffer.
		require.NoError(rt, out.Close())

		// Wait up to 2s for the sentinel to arrive at the server.
		// The sentinel prefix is unique and cannot appear in framing.
		sentinelStr := "COPYSAFETY:" + content
		if !srv.waitForContent([]string{sentinelStr}, 2*time.Second) {
			all := bytes.Join(stringsToBytes(srv.getMessages()), nil)
			rt.Fatalf("copy safety violated: original payload not found in received data\noriginal: %q\nreceived: %q",
				truncateSyslog(original, 64), truncateSyslog(all, 128))
		}

		// The syslog framer wraps the payload in an RFC 5424 message.
		// Verify presence of the original sentinel and absence of the
		// 0xFF poison block in the received TCP data.
		all := bytes.Join(stringsToBytes(srv.getMessages()), nil)

		// The sentinel prefix "COPYSAFETY:" is deterministic and cannot
		// appear in syslog framing. Its presence proves the original
		// payload was delivered correctly.
		if !bytes.Contains(all, original) {
			rt.Fatalf("copy safety violated: original payload not found in received data\noriginal: %q\nreceived: %q",
				truncateSyslog(original, 64), truncateSyslog(all, 128))
		}

		// The poisoned block (0xFF repeated len times) must not appear.
		// 0xFF is not a valid RFC 5424 header byte, so any occurrence
		// must come from the payload — which would mean the copy failed.
		poison := bytes.Repeat([]byte{0xFF}, len(payload))
		if bytes.Contains(all, poison) {
			rt.Fatalf("copy safety violated: received data contains overwritten bytes (0xFF×%d)",
				len(payload))
		}
	})
}

// TestSyslogOutput_Property_DropConservation verifies that with a
// deliberately undersized buffer, every event is accounted for as either
// flushed, dropped, or errored. Nothing disappears without a metric.
//
// Note: the syslog output's reconnection logic means a write failure may
// trigger a retry that results in a flush, so errors count toward the
// invariant alongside flushes and drops.
func TestSyslogOutput_Property_DropConservation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(20, 200).Draw(rt, "n")
		bufSize := rapid.IntRange(1, 10).Draw(rt, "bufSize")

		srv := newMockSyslogServer(t)
		t.Cleanup(srv.close)

		out, err := syslog.New(&syslog.Config{
			Network:    "tcp",
			Address:    srv.addr(),
			BufferSize: bufSize,
		})
		require.NoError(rt, err)

		om := &mockOutputMetrics{}
		out.SetOutputMetrics(om)

		for i := range n {
			data := []byte(`{"seq":` + itoa(i) + `}` + "\n")
			_ = out.Write(data) // drops expected; ignore return
		}

		require.NoError(rt, out.Close())

		got := om.flushes.Load() + om.drops.Load() + om.errors.Load()
		if got != int64(n) {
			rt.Fatalf("drop conservation violated: flushes(%d) + drops(%d) + errors(%d) = %d, want %d",
				om.flushes.Load(), om.drops.Load(), om.errors.Load(), got, n)
		}
	})
}

// stringsToBytes converts a []string to a [][]byte for bytes.Join.
func stringsToBytes(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

// truncateSyslog is the syslog package's local version of the truncate
// helper — returns at most maxLen bytes from b with a "..." suffix.
func truncateSyslog(b []byte, maxLen int) []byte {
	if len(b) <= maxLen {
		return b
	}
	return append(b[:maxLen:maxLen], []byte("...")...)
}

// itoa converts an int to its decimal string representation. Defined
// here independently so property_test.go is self-contained and does
// not rely on the helper defined in syslog_test.go (different test
// binary linkage is not guaranteed when files are in the same package).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
