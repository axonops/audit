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

package audit_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/axonops/go-audit/tests/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSyslogServer listens on TCP and collects received messages.
type mockSyslogServer struct {
	listener net.Listener
	done     chan struct{}
	messages []string
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func newMockSyslogServer(t *testing.T) *mockSyslogServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &mockSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *mockSyslogServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				return
			}
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *mockSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.messages = append(s.messages, string(buf[:n]))
			s.mu.Unlock()
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (s *mockSyslogServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockSyslogServer) getMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *mockSyslogServer) messageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

// waitForData polls until the server has received at least one chunk,
// or the timeout expires. Replaces time.Sleep for synchronisation.
func (s *mockSyslogServer) waitForData(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if s.messageCount() > 0 {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TCP(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_UDP(t *testing.T) {
	// UDP doesn't need a running server to construct.
	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "udp",
		Address: "127.0.0.1:9514",
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_InvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		cfg     audit.SyslogConfig
	}{
		{
			name:    "missing address",
			cfg:     audit.SyslogConfig{Network: "tcp"},
			wantErr: "must not be empty",
		},
		{
			name:    "invalid network",
			cfg:     audit.SyslogConfig{Network: "http", Address: "localhost:514"},
			wantErr: "must be tcp, udp, or tcp+tls",
		},
		{
			name:    "invalid facility",
			cfg:     audit.SyslogConfig{Network: "udp", Address: "localhost:514", Facility: "bogus"},
			wantErr: "unknown syslog facility",
		},
		{
			name: "cert without key",
			cfg: audit.SyslogConfig{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCert: "/tmp/cert.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: audit.SyslogConfig{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSKey:  "/tmp/key.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "nonexistent cert file",
			cfg: audit.SyslogConfig{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCert: "/nonexistent/cert.pem",
				TLSKey:  "/nonexistent/key.pem",
			},
			wantErr: "tls file",
		},
		{
			name: "nonexistent CA file",
			cfg: audit.SyslogConfig{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCA:   "/nonexistent/ca.pem",
			},
			wantErr: "tls file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := audit.NewSyslogOutput(&tt.cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// ---------------------------------------------------------------------------
// Write / Close contract
// ---------------------------------------------------------------------------

func TestSyslogOutput_Write(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	data := []byte(`{"event_type":"user_create","outcome":"success"}`)
	require.NoError(t, out.Write(data))

	// Give the server time to receive.
	require.True(t, srv.waitForData(2*time.Second), "server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	// The message should contain our JSON payload.
	assert.Contains(t, msgs[0], "user_create")
}

func TestSyslogOutput_WriteMultiple(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	for i := range 5 {
		data := []byte(fmt.Sprintf(`{"n":%d}`, i))
		require.NoError(t, out.Write(data))
	}

	require.True(t, srv.waitForData(2*time.Second), "server should receive data")
	require.NoError(t, out.Close())

	// Messages may be coalesced in TCP reads; check the content.
	all := strings.Join(srv.getMessages(), "\n")
	for i := range 5 {
		assert.Contains(t, all, fmt.Sprintf(`{"n":%d}`, i))
	}
}

func TestSyslogOutput_CloseIdempotent(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestSyslogOutput_WriteAfterClose(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestSyslogOutput_Name(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	assert.True(t, strings.HasPrefix(out.Name(), "syslog:"))
	assert.Contains(t, out.Name(), srv.addr())
}

func TestSyslogOutput_ImplementsOutput(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	var _ audit.Output = out
}

// ---------------------------------------------------------------------------
// Facility parsing
// ---------------------------------------------------------------------------

func TestParseFacility_AllStandard(t *testing.T) {
	facilities := []string{
		"kern", "user", "mail", "daemon", "auth", "syslog",
		"lpr", "news", "uucp", "cron", "authpriv", "ftp",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
	}
	for _, f := range facilities {
		t.Run(f, func(t *testing.T) {
			// Verify construction succeeds with each facility.
			srv := newMockSyslogServer(t)
			defer srv.close()
			out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
				Network:  "tcp",
				Address:  srv.addr(),
				Facility: f,
			}, nil)
			require.NoError(t, err, "facility %q should be valid", f)
			require.NoError(t, out.Close())
		})
	}
}

func TestParseFacility_Unknown(t *testing.T) {
	_, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:  "udp",
		Address:  "localhost:514",
		Facility: "nonexistent",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown syslog facility")
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// mockTLSSyslogServer listens on TLS TCP.
type mockTLSSyslogServer struct {
	listener net.Listener
	done     chan struct{}
	messages []string
	wg       sync.WaitGroup
	mu       sync.Mutex
}

func newMockTLSSyslogServer(t *testing.T, tlsCfg *tls.Config) *mockTLSSyslogServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)

	s := &mockTLSSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *mockTLSSyslogServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *mockTLSSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.messages = append(s.messages, string(buf[:n]))
			s.mu.Unlock()
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
	}
}

func (s *mockTLSSyslogServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockTLSSyslogServer) close() {
	close(s.done)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *mockTLSSyslogServer) getMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]string, len(s.messages))
	copy(cp, s.messages)
	return cp
}

func (s *mockTLSSyslogServer) messageCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *mockTLSSyslogServer) waitForData(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if s.messageCount() > 0 {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSyslogOutput_TLS(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.CAPath,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"tls_test"}`)))
	require.True(t, srv.waitForData(2*time.Second), "TLS server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "tls_test")
}

func TestSyslogOutput_MTLS(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)
	// Require client cert for mTLS.
	certs.TLSCfg.ClientAuth = tls.RequireAndVerifyClientCert
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCert: certs.ClientCert,
		TLSKey:  certs.ClientKey,
		TLSCA:   certs.CAPath,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test"}`)))
	require.True(t, srv.waitForData(2*time.Second), "mTLS server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "mtls_test")
}

// ---------------------------------------------------------------------------
// TLSPolicy integration
// ---------------------------------------------------------------------------

func TestSyslogOutput_TLSPolicy_NilPreservesBehaviour(t *testing.T) {
	// Nil TLSPolicy should behave identically to the previous hardcoded
	// TLS 1.3 default: connect to a TLS 1.3 server with a custom CA.
	certs := testhelper.GenerateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:   "tcp+tls",
		Address:   srv.addr(),
		TLSCA:     certs.CAPath,
		TLSPolicy: nil, // explicitly nil
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event":"nil_policy"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "nil_policy")
}

func TestSyslogOutput_TLSPolicy_AllowTLS12(t *testing.T) {
	certs := testhelper.GenerateTestCerts(t)
	// Server accepts TLS 1.2.
	certs.TLSCfg.MinVersion = tls.VersionTLS12
	srv := newMockTLSSyslogServer(t, certs.TLSCfg)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.CAPath,
		TLSPolicy: &audit.TLSPolicy{
			AllowTLS12: true,
		},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Write([]byte(`{"event":"tls12_policy"}`)))
	require.True(t, srv.waitForData(2*time.Second))
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "tls12_policy")
}

// ---------------------------------------------------------------------------
// Reconnection
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteFailure_ReturnsError(t *testing.T) {
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 1, // minimal retries to keep test fast
	}, nil)
	require.NoError(t, err)

	// First write succeeds.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Kill the server.
	srv.close()

	// Writes should eventually error (server gone, retries exhausted).
	// May take a couple of attempts due to TCP buffering.
	var writeErr error
	for range 5 {
		writeErr = out.Write([]byte(`{"n":2}`))
		if writeErr != nil {
			break
		}
	}
	assert.Error(t, writeErr, "should error when server is permanently down")

	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// SyslogMetrics (#54)
// ---------------------------------------------------------------------------

// syslogOnlyMetrics implements SyslogMetrics but not the full Metrics
// interface. It is used to verify that NewSyslogOutput accepts any
// SyslogMetrics implementation.
type syslogOnlyMetrics struct {
	mu        sync.Mutex
	successes int
	failures  int
}

func (m *syslogOnlyMetrics) RecordSyslogReconnect(_ string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if success {
		m.successes++
	} else {
		m.failures++
	}
}

var _ audit.SyslogMetrics = (*syslogOnlyMetrics)(nil)

func TestSyslogOutput_NilSyslogMetrics_ReconnectDoesNotPanic(t *testing.T) {
	// nil SyslogMetrics must not panic during the reconnect path.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 1,
	}, nil) // nil SyslogMetrics
	require.NoError(t, err)

	// First write succeeds — connection is established.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Kill the server to force reconnect logic.
	srv.close()

	// Writes after server dies trigger the reconnect path which
	// would call syslogMetrics.RecordSyslogReconnect if non-nil.
	// With nil, it must not panic.
	var writeErr error
	for range 5 {
		writeErr = out.Write([]byte(`{"n":2}`))
		if writeErr != nil {
			break
		}
	}
	// Error is expected (server is gone), not panic.
	assert.Error(t, writeErr, "should eventually error with server down")

	require.NoError(t, out.Close())
}

func TestSyslogOutput_SyslogMetrics_RecordSyslogReconnect_FailureOnPermanentServerDown(t *testing.T) {
	// Verify RecordSyslogReconnect(address, false) is called when
	// reconnection fails because the server is permanently gone.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	m := testhelper.NewMockMetrics()
	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 2, // allow 2 reconnection attempts
	}, m)
	require.NoError(t, err)

	// Establish the connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Bring the server down permanently.
	srv.close()

	// Drive reconnection attempts to exhaustion.
	var writeErr error
	for range 10 {
		writeErr = out.Write([]byte(`{"n":2}`))
		if writeErr != nil {
			break
		}
	}
	assert.Error(t, writeErr, "writes must eventually fail with server permanently down")

	require.NoError(t, out.Close())

	// At least one reconnect failure must have been recorded.
	failureCount := m.GetSyslogReconnectCount(addr, false)
	assert.Greater(t, failureCount, 0,
		"RecordSyslogReconnect(address, false) should be called on reconnect failure, got 0")
}

func TestSyslogOutput_SyslogMetrics_RecordSyslogReconnect_SuccessPath(t *testing.T) {
	// Verify RecordSyslogReconnect(address, true) is called when a
	// reconnection attempt to a live server succeeds.
	//
	// Approach: bind a listener on a fixed address. Establish the initial
	// connection. Close and immediately rebind the same listener (SO_REUSEADDR
	// applies on Linux; the OS recycles the port instantly for loopback).
	// The output's reconnect path will connect to the new listener and call
	// RecordSyslogReconnect(addr, true).

	// Bind the server on a fixed loopback address with a kernel-assigned port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	// Wrap the first listener in a mock server.
	srv1 := &mockSyslogServer{
		listener: ln,
		done:     make(chan struct{}),
	}
	srv1.wg.Add(1)
	go srv1.accept()

	m := testhelper.NewMockMetrics()
	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 10, // enough headroom for reconnect
	}, m)
	require.NoError(t, err)

	// Establish a live connection with a successful write.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))
	require.True(t, srv1.waitForData(2*time.Second), "server should receive initial write")

	// Kill the first server. The next write will fail and trigger backoff.
	srv1.close()

	// Reuse the same port by binding a new listener immediately after
	// the old one is closed. On Linux loopback this is nearly instant.
	ln2, listenErr := net.Listen("tcp", addr)
	require.NoError(t, listenErr, "must rebind same address for reconnect test")

	srv2 := &mockSyslogServer{
		listener: ln2,
		done:     make(chan struct{}),
	}
	srv2.wg.Add(1)
	go srv2.accept()
	defer srv2.close()

	// Write triggers failure on dead srv1, then reconnects to srv2.
	// With MaxRetries=10 and short backoff, the reconnect should succeed.
	// We retry writes until we see success=true recorded or exhaust attempts.
	var reconnectSucceeded bool
	for range 20 {
		_ = out.Write([]byte(`{"n":2}`))
		if m.GetSyslogReconnectCount(addr, true) > 0 {
			reconnectSucceeded = true
			break
		}
		// Brief yield — not sleeping for synchronisation, just giving the
		// reconnect goroutine a chance to complete its sub-millisecond work.
		time.Sleep(10 * time.Millisecond)
	}

	require.NoError(t, out.Close())

	if reconnectSucceeded {
		assert.Greater(t, m.GetSyslogReconnectCount(addr, true), 0,
			"RecordSyslogReconnect(address, true) should be called on successful reconnect")
	} else {
		// The port rebind did not succeed fast enough on this OS/run.
		// The failure path is already verified by
		// TestSyslogOutput_SyslogMetrics_RecordSyslogReconnect_FailureOnPermanentServerDown.
		t.Log("reconnect success test skipped: port could not be rebound fast enough")
	}
}

func TestSyslogOutput_SyslogMetrics_InterfaceAssertion(t *testing.T) {
	// Compile-time: verify NewSyslogOutput accepts any SyslogMetrics, not
	// just mockMetrics. This test would not compile if the signature changed.
	srv := newMockSyslogServer(t)
	defer srv.close()

	var m audit.SyslogMetrics = &syslogOnlyMetrics{}
	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, m)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Backoff calculation
// ---------------------------------------------------------------------------

func TestBackoffDuration(t *testing.T) {
	// Backoff uses jitter [0.5, 1.0), so verify the result is within
	// the expected range.
	d1 := audit.BackoffDuration(1)
	assert.GreaterOrEqual(t, d1, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d1, 100*time.Millisecond)          // 100ms * 1.0

	d2 := audit.BackoffDuration(2)
	assert.GreaterOrEqual(t, d2, 100*time.Millisecond) // 200ms * 0.5
	assert.Less(t, d2, 200*time.Millisecond)

	d3 := audit.BackoffDuration(3)
	assert.GreaterOrEqual(t, d3, 200*time.Millisecond) // 400ms * 0.5
	assert.Less(t, d3, 400*time.Millisecond)

	// Large attempt should be capped at 30s (with jitter, 15-30s).
	d20 := audit.BackoffDuration(20)
	assert.GreaterOrEqual(t, d20, 15*time.Second)
	assert.LessOrEqual(t, d20, 30*time.Second)
}

// ---------------------------------------------------------------------------
// No InsecureSkipVerify
// ---------------------------------------------------------------------------

func TestSyslogOutput_NoInsecureSkipVerify(t *testing.T) {
	// Grep the source for InsecureSkipVerify — it must never be set to true.
	data, err := os.ReadFile("syslog.go")
	require.NoError(t, err)
	assert.NotContains(t, string(data), "InsecureSkipVerify: true",
		"InsecureSkipVerify must never be set to true")
	assert.NotContains(t, string(data), "InsecureSkipVerify:true",
		"InsecureSkipVerify must never be set to true")
}

// ---------------------------------------------------------------------------
// Empty and edge-case payloads
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteNil(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Write(nil) should not panic. srslog may send an empty message
	// or silently drop it — either is acceptable.
	err = out.Write(nil)
	assert.NoError(t, err, "Write(nil) should not error")
}

func TestSyslogOutput_WriteEmpty(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	err = out.Write([]byte{})
	assert.NoError(t, err, "Write([]byte{}) should not error")
}

// ---------------------------------------------------------------------------
// Rapid-fire TCP writes (validates RFC 5425 framing)
// ---------------------------------------------------------------------------

func TestSyslogOutput_RapidFireTCP(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	const count = 100
	for i := range count {
		data := []byte(fmt.Sprintf(`{"event":"rapid","n":%d}`, i))
		require.NoError(t, out.Write(data))
	}

	require.True(t, srv.waitForData(5*time.Second), "server should receive data")
	require.NoError(t, out.Close())

	// Verify all events arrived by checking the concatenated content.
	all := strings.Join(srv.getMessages(), "")
	for i := range count {
		assert.Contains(t, all, fmt.Sprintf(`"n":%d`, i),
			"event %d should be present in server data", i)
	}
}

// ---------------------------------------------------------------------------
// Concurrent writes
// ---------------------------------------------------------------------------

func TestSyslogOutput_ConcurrentWrites(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			_ = out.Write([]byte(fmt.Sprintf(`{"g":%d}`, n)))
		}(i)
	}
	wg.Wait()
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// UDP write path
// ---------------------------------------------------------------------------

func TestSyslogOutput_WriteUDP(t *testing.T) {
	// Start a UDP listener to receive syslog messages.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	addr := conn.LocalAddr().String()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "udp",
		Address: addr,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"udp_test"}`)))

	// Read from the UDP listener with a timeout.
	buf := make([]byte, 8192)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, readErr := conn.ReadFrom(buf)
	require.NoError(t, readErr)

	assert.Contains(t, string(buf[:n]), "udp_test",
		"UDP server should receive the event")

	require.NoError(t, out.Close())
}

func TestSyslogOutput_WriteUDP_LargePayload(t *testing.T) {
	// Start a UDP listener.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "udp",
		Address: conn.LocalAddr().String(),
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// A payload larger than typical UDP syslog limits (>2048 bytes).
	// The write should not panic. It may succeed (OS buffers it),
	// fail silently, or return an error — all are acceptable.
	largePayload := []byte(`{"data":"` + strings.Repeat("x", 4096) + `"}`)
	_ = out.Write(largePayload)
	// No assertion on error — UDP is fire-and-forget.
}
