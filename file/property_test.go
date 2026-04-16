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

package file_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axonops/audit/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestFileOutput_Property_ConservationInvariant verifies that for any N
// events submitted, flushes + drops == N after Close. This is the core
// accounting invariant of an async output: every event is accounted for,
// nothing disappears silently.
//
// The buffer is sized well above N so no drops occur in the happy path.
// We assert >= N rather than == N because a race between Write and the
// channel select is impossible to trigger here (no concurrent goroutines),
// so flushes always equals N. The >= bound is intentional: it documents
// that the implementation may legitimately account for more events via
// retries, but never fewer.
//
// Errors (write failures) are not expected against a real writable file.
// If any error occurs, the invariant becomes flushes + drops + errors == N,
// which we also verify.
func TestFileOutput_Property_ConservationInvariant(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate N in a range that exercises non-trivial batching
		// without making tests slow. 1 to 500 events per run.
		n := rapid.IntRange(1, 500).Draw(rt, "n")

		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		// Buffer larger than the maximum N so no event is ever dropped
		// due to backpressure. This isolates the conservation property
		// from the drop policy.
		out, err := file.New(file.Config{
			Path:       path,
			BufferSize: 1000, // >> max N of 500
		}, nil)
		require.NoError(rt, err)

		om := &mockOutputMetrics{}
		out.SetOutputMetrics(om)

		for i := range n {
			// Each event is a distinct JSON line. The content is
			// irrelevant to the invariant — we vary it to avoid
			// write-combining optimisations that might mask bugs.
			data := []byte(`{"seq":` + itoa(i) + `}` + "\n")
			writeErr := out.Write(data)
			// Write never returns an error in the non-closed case with
			// buffer capacity; ErrOutputClosed is the only possible error.
			require.NoError(rt, writeErr)
		}

		require.NoError(rt, out.Close())

		got := om.flushes.Load() + om.drops.Load() + om.errors.Load()
		if got != int64(n) {
			rt.Fatalf("conservation invariant violated: flushes(%d) + drops(%d) + errors(%d) = %d, want %d",
				om.flushes.Load(), om.drops.Load(), om.errors.Load(), got, n)
		}

		// In the happy path (large buffer, writable file), drops and
		// errors must be zero. Every event must have been flushed.
		if om.drops.Load() != 0 {
			rt.Fatalf("unexpected drops=%d with buffer sized above N=%d",
				om.drops.Load(), n)
		}
		if om.errors.Load() != 0 {
			rt.Fatalf("unexpected errors=%d writing to a writable temp file",
				om.errors.Load())
		}
	})
}

// TestFileOutput_Property_CopySafety verifies that mutating the []byte
// slice passed to Write after Write returns does not affect the data
// actually written to disk.
//
// This is the copy safety contract: Write must copy data before
// returning so that the caller — typically the drain loop reusing a
// format buffer — cannot corrupt an in-flight event.
//
// Verification strategy: we embed a unique sentinel prefix in every
// payload so that the original content is unambiguously distinguishable
// from the 0xFF overwrite pattern. After Close we read the file and
// assert byte-exact equality against the original. The sentinel prefix
// approach avoids a false positive when the generated content happens
// to equal the poison bytes.
func TestFileOutput_Property_CopySafety(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Printable ASCII rune generator — content that is
		// unambiguously distinguishable from 0xFF overwrite bytes.
		alphabet := []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.")
		printableRune := rapid.RuneFrom(alphabet)
		content := rapid.StringOfN(printableRune, 4, 128, -1).Draw(rt, "content")

		// Sentinel prefix makes the payload unique and non-overlapping
		// with any pattern of 0xFF bytes.
		payload := []byte("COPYSAFETY:" + content + "\n")

		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		out, err := file.New(file.Config{Path: path}, nil)
		require.NoError(rt, err)

		// Capture the original content before Write copies and enqueues it.
		original := make([]byte, len(payload))
		copy(original, payload)

		require.NoError(rt, out.Write(payload))

		// Overwrite the caller's slice with 0xFF — simulating the drain
		// loop reusing its format cache buffer for the next event.
		for i := range payload {
			payload[i] = 0xFF
		}

		// Close drains the async buffer and flushes to disk.
		require.NoError(rt, out.Close())

		written, err := os.ReadFile(path)
		require.NoError(rt, err)

		// Exact equality: the file must contain exactly the bytes that
		// were in the slice at the moment Write was called, not the
		// 0xFF-overwritten bytes.
		if !bytes.Equal(written, original) {
			rt.Fatalf("copy safety violated: disk content differs from original\ngot:  %q\nwant: %q",
				truncate(written, 64), truncate(original, 64))
		}
	})
}

// TestFileOutput_Property_DropConservation verifies the drop-path
// accounting: when the buffer is deliberately undersized, every event
// is still accounted for as either flushed or dropped. Nothing is lost
// without a metric call.
func TestFileOutput_Property_DropConservation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// N between 20 and 200 events, buffer between 1 and 10.
		// Chosen so drops are likely but not guaranteed — rapid will
		// find the cases where the invariant breaks regardless.
		n := rapid.IntRange(20, 200).Draw(rt, "n")
		bufSize := rapid.IntRange(1, 10).Draw(rt, "bufSize")

		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		out, err := file.New(file.Config{
			Path:       path,
			BufferSize: bufSize,
		}, nil)
		require.NoError(rt, err)

		om := &mockOutputMetrics{}
		out.SetOutputMetrics(om)

		for i := range n {
			data := []byte(`{"seq":` + itoa(i) + `}` + "\n")
			_ = out.Write(data) // drops are expected; ignore return value
		}

		require.NoError(rt, out.Close())

		got := om.flushes.Load() + om.drops.Load() + om.errors.Load()
		if got != int64(n) {
			rt.Fatalf("drop conservation violated: flushes(%d) + drops(%d) + errors(%d) = %d, want %d",
				om.flushes.Load(), om.drops.Load(), om.errors.Load(), got, n)
		}
	})
}

// TestFileOutput_Property_ContentIntegrity verifies that the lines
// written to disk exactly match the events that were accepted (not
// dropped). This catches bugs where data is enqueued but transformed
// incorrectly or partially written.
func TestFileOutput_Property_ContentIntegrity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 100).Draw(rt, "n")

		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		// Large buffer guarantees no drops, so every submitted event
		// must appear in the file.
		out, err := file.New(file.Config{
			Path:       path,
			BufferSize: 10_000,
		}, nil)
		require.NoError(rt, err)

		// Generate distinct events so we can verify exact content.
		events := make([]string, n)
		for i := range n {
			events[i] = `{"idx":` + itoa(i) + `,` + `"tag":"prop"}` + "\n"
			require.NoError(rt, out.Write([]byte(events[i])))
		}

		require.NoError(rt, out.Close())

		content, err := os.ReadFile(path)
		require.NoError(rt, err)

		lines := strings.SplitAfter(string(content), "\n")
		// SplitAfter leaves an empty string after the trailing newline.
		// Remove it before comparing.
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}

		assert.Equal(rt, n, len(lines),
			"line count must equal the number of submitted events")

		for i, want := range events {
			if i >= len(lines) {
				break
			}
			assert.Equal(rt, want, lines[i],
				"line %d content mismatch", i)
		}
	})
}

// itoa converts an int to its decimal string representation without
// importing strconv into every test helper call site. The standard
// library's strconv.Itoa would be fine, but this keeps the property
// test self-contained.
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

// truncate returns at most maxLen bytes from b, adding a "..." suffix
// if truncation occurred. Used for readable failure messages.
func truncate(b []byte, maxLen int) []byte {
	if len(b) <= maxLen {
		return b
	}
	return append(b[:maxLen], []byte("...")...)
}
