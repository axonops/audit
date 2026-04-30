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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stallingTCPListener accepts every TCP connection but never reads or
// writes — modelling a server that completes the TCP three-way
// handshake and then refuses to participate in TLS hello (#746).
//
// Returns the listener address (host:port) and a cleanup function the
// caller MUST defer-call. Cleanup closes the listener AND every
// accepted connection AND waits for every spawned goroutine to exit
// so goleak.VerifyNone does not race the teardown.
func stallingTCPListener(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	stop := make(chan struct{})
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			// Hold the conn open by parking the goroutine; it
			// returns when stop is closed.
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				<-stop
				_ = c.Close()
			}(c)
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close() // unblocks Accept
		close(stop)    // unblocks per-conn goroutines
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait() // synchronously drain so goleak does not race
	}
}

func TestNew_TLSHandshakeTimeout_StalledServer_ReturnsBounded(t *testing.T) {
	t.Parallel()
	// Goroutine-leak detection runs once at TestMain via
	// goleak.VerifyTestMain (see syslog_test.go).

	addr, stop := stallingTCPListener(t)
	defer stop()

	cfg := &syslog.Config{
		Network:             "tcp+tls",
		Address:             addr,
		TLSHandshakeTimeout: 500 * time.Millisecond,
	}

	start := time.Now()
	out, err := syslog.New(cfg)
	elapsed := time.Since(start)

	require.Error(t, err)
	if out != nil {
		_ = out.Close()
	}
	assert.Contains(t, err.Error(), "tls handshake timeout",
		"error must contain the substring 'tls handshake timeout' for operator diagnosis")
	// AC #3: returns within TLSHandshakeTimeout + 1s scheduling
	// jitter allowance.
	assert.Less(t, elapsed, 1500*time.Millisecond,
		"New must return within ~TLSHandshakeTimeout, took %s", elapsed)
}

func TestNew_TLSHandshakeTimeout_ErrorIsTransient(t *testing.T) {
	t.Parallel()
	// Goroutine-leak detection runs once at TestMain via
	// goleak.VerifyTestMain (see syslog_test.go).

	addr, stop := stallingTCPListener(t)
	defer stop()

	cfg := &syslog.Config{
		Network:             "tcp+tls",
		Address:             addr,
		TLSHandshakeTimeout: 500 * time.Millisecond,
	}

	out, err := syslog.New(cfg)
	require.Error(t, err)
	if out != nil {
		_ = out.Close()
	}
	// AC #4: handshake timeout MUST NOT wrap audit.ErrConfigInvalid —
	// it is a transient connect failure, eligible for the existing
	// reconnect path.
	assert.False(t, errors.Is(err, audit.ErrConfigInvalid),
		"handshake-timeout error must not be classed as a permanent config error: %v", err)
}

func TestNew_TLSHandshakeTimeout_Validation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		value          time.Duration
		wantErrInvalid bool
		wantResolved   time.Duration
	}{
		{name: "negative", value: -1 * time.Second, wantErrInvalid: true},
		{name: "below_min", value: 30 * time.Millisecond, wantErrInvalid: true},
		{name: "above_max", value: 90 * time.Second, wantErrInvalid: true},
		{name: "zero_defaults", value: 0, wantResolved: syslog.DefaultTLSHandshakeTimeout},
		{name: "five_seconds_kept", value: 5 * time.Second, wantResolved: 5 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &syslog.Config{
				Network:             "tcp+tls",
				Address:             "127.0.0.1:1",
				TLSHandshakeTimeout: tc.value,
			}
			// Use ValidateConfig (export_test.go seam) to inspect
			// the resolved value WITHOUT actually dialling.
			err := syslog.ValidateConfig(cfg)
			if tc.wantErrInvalid {
				require.Error(t, err)
				assert.True(t, errors.Is(err, audit.ErrConfigInvalid),
					"expected ErrConfigInvalid, got: %v", err)
				assert.Contains(t, err.Error(), "tls_handshake_timeout",
					"validator error must mention the YAML key (snake_case)")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantResolved, cfg.TLSHandshakeTimeout,
				"resolved TLSHandshakeTimeout mismatch")
		})
	}
}

func TestNew_TLSHandshakeTimeout_IgnoredForTCP(t *testing.T) {
	t.Parallel()

	// Plain-TCP listener that accepts and immediately discards reads.
	// Uses a WaitGroup so cleanup synchronously drains every goroutine
	// before goleak.VerifyNone runs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	cfg := &syslog.Config{
		Network:             "tcp",
		Address:             ln.Addr().String(),
		TLSHandshakeTimeout: 5 * time.Second, // value is silently ignored on tcp
	}
	out, err := syslog.New(cfg)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestNew_TLSHandshakeTimeout_IgnoredForUDP(t *testing.T) {
	t.Parallel()
	// Goroutine-leak detection runs once at TestMain via
	// goleak.VerifyTestMain (see syslog_test.go).

	// UDP "server" — bind a packet conn so the dial succeeds.
	// No accept goroutine to drain; UDP is connectionless.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	cfg := &syslog.Config{
		Network:             "udp",
		Address:             pc.LocalAddr().String(),
		TLSHandshakeTimeout: 5 * time.Second, // value is silently ignored on udp
	}
	out, err := syslog.New(cfg)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestReconnect_TLSHandshakeTimeout_RespectedOnRetry(t *testing.T) {
	t.Parallel()
	// Goroutine-leak detection runs once at TestMain via
	// goleak.VerifyTestMain (see syslog_test.go).

	// AC #10: the reconnect path honours TLSHandshakeTimeout on
	// every reconnect attempt, not just the initial dial. Rather
	// than orchestrate a complex first-success-then-stall listener,
	// drive the package-internal boundedTLSDialer directly twice
	// against the same stalling listener. Each invocation MUST
	// honour the configured budget independently — the same dialer
	// closure is used by both initial connect() and every
	// reconnect (writeLoop calls connect() unchanged).
	addr, stop := stallingTCPListener(t)
	defer stop()

	// Minimal TLS config — the handshake never completes, so the
	// server certificate is never validated. We only need a non-nil
	// *tls.Config so tls.Client() can wrap the conn.
	tlsCfg := &tls.Config{
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}
	out := syslog.NewOutputForTesting(tlsCfg)
	dialer := out.BoundedTLSDialer(400 * time.Millisecond)

	for attempt := 1; attempt <= 2; attempt++ {
		start := time.Now()
		conn, err := dialer("custom", addr)
		elapsed := time.Since(start)

		require.Error(t, err, "attempt %d: stalled handshake must error", attempt)
		assert.Nil(t, conn, "attempt %d: no connection returned on timeout", attempt)
		assert.Contains(t, err.Error(), "tls handshake timeout",
			"attempt %d: error must signal handshake timeout", attempt)
		assert.Less(t, elapsed, 1*time.Second,
			"attempt %d: each invocation must honour the timeout independently (got %s)",
			attempt, elapsed)
	}
}
