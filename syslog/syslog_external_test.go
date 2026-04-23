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
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit/syslog"
)

// TestSyslog_SetDiagnosticLoggerUnderEventLoad drives SetDiagnosticLogger
// and Write concurrently to prove the logger field is safe under the
// race detector. Closes #474 AC #3.
//
// Uses a local TCP listener to accept the syslog connection so New
// succeeds. The listener just drains bytes — we do not validate
// delivery, only that the logger field survives concurrent access.
//
// Lives in syslog_external_test.go (not syslog_test.go) per the
// explicit file-naming acceptance criterion in #474 Testing
// Requirements. Per-test goleak.VerifyNone(t) complements the
// package-level goleak.VerifyTestMain to catch leaks from this
// test's goroutines specifically.
func TestSyslog_SetDiagnosticLoggerUnderEventLoad(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	// Accept loop goroutine — exits when the listener is closed at end
	// of test. Tracked so goleak does not flag it as a leak.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()

	out, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  listener.Addr().String(),
		Facility: "local0",
		AppName:  "race-test",
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	const iters = 100
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iters {
			out.SetDiagnosticLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
		}
	}()
	go func() {
		defer wg.Done()
		for range iters {
			_ = out.Write([]byte(`{"event":"race"}`))
		}
	}()
	wg.Wait()

	// Close the syslog output and the listener BEFORE goleak runs so
	// their background goroutines have exited by the time we assert.
	require.NoError(t, out.Close())
	_ = listener.Close()
	<-acceptDone
	goleak.VerifyNone(t)
}
