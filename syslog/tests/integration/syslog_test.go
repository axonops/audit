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

// Package integration_test contains integration tests for the syslog
// output against a real syslog-ng container. Requires Docker Compose
// infrastructure: `make test-infra-up` before running.
package integration_test

import (
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit/syslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// certDir returns the absolute path to the test certificates directory.
func certDir(t *testing.T) string {
	t.Helper()
	// Tests run from syslog/tests/integration/, certs are at repo root.
	abs, err := filepath.Abs("../../../tests/testdata/certs")
	require.NoError(t, err)
	return abs
}

// marker generates a unique test marker to identify events in the
// syslog log file. Uses crypto/rand to avoid collisions.
func marker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "MARKER_" + hex.EncodeToString(b)
}

// readSyslogLog reads the syslog-ng audit log file from the running
// container via docker exec.
func readSyslogLog(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", "bdd-syslog-ng-1",
		"cat", "/var/log/syslog-ng/audit.log").CombinedOutput()
	if err != nil {
		t.Logf("docker exec cat failed: %v, output: %s", err, string(out))
		return ""
	}
	return string(out)
}

// waitForMarker polls the syslog log until the marker string appears
// or the timeout expires.
func waitForMarker(t *testing.T, m string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log := readSyslogLog(t)
		if strings.Contains(log, m) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// --- TCP plain (port 5514) ---

func TestSyslog_TCP_SendAndReceive(t *testing.T) {
	m := marker(t)
	out, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  "localhost:5514",
		Facility: "local0",
		AppName:  "audit-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"tcp_test","marker":"`+m+`"}`)))

	assert.True(t, waitForMarker(t, m, 10*time.Second),
		"syslog should contain marker %s", m)
}

func TestSyslog_TCP_MultipleEvents(t *testing.T) {
	markers := make([]string, 5)
	out, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  "localhost:5514",
		Facility: "local0",
		AppName:  "audit-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	for i := range markers {
		markers[i] = marker(t)
		require.NoError(t, out.Write([]byte(`{"event":"multi","marker":"`+markers[i]+`"}`)))
	}

	for _, m := range markers {
		assert.True(t, waitForMarker(t, m, 10*time.Second),
			"syslog should contain marker %s", m)
	}
}

// --- UDP (port 5515) ---

func TestSyslog_UDP_SendAndReceive(t *testing.T) {
	m := marker(t)
	// Use 127.0.0.1 explicitly — Docker maps UDP to IPv4 only;
	// "localhost" may resolve to ::1 on dual-stack hosts.
	out, err := syslog.New(&syslog.Config{
		Network:  "udp",
		Address:  "127.0.0.1:5515",
		Facility: "local0",
		AppName:  "audit-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"udp_test","marker":"`+m+`"}`)))

	assert.True(t, waitForMarker(t, m, 10*time.Second),
		"syslog should contain UDP marker %s", m)
}

// --- TCP+TLS (port 6514) ---

func TestSyslog_TLS_SendAndReceive(t *testing.T) {
	m := marker(t)
	certs := certDir(t)
	out, err := syslog.New(&syslog.Config{
		Network:  "tcp+tls",
		Address:  "localhost:6514",
		Facility: "local0",
		AppName:  "audit-test",
		TLSCA:    filepath.Join(certs, "ca.crt"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"tls_test","marker":"`+m+`"}`)))

	assert.True(t, waitForMarker(t, m, 10*time.Second),
		"syslog should contain TLS marker %s", m)
}

// --- TCP+mTLS (port 6515) ---

func TestSyslog_MTLS_SendAndReceive(t *testing.T) {
	m := marker(t)
	certs := certDir(t)
	out, err := syslog.New(&syslog.Config{
		Network:  "tcp+tls",
		Address:  "localhost:6515",
		Facility: "local0",
		AppName:  "audit-test",
		TLSCA:    filepath.Join(certs, "ca.crt"),
		TLSCert:  filepath.Join(certs, "client.crt"),
		TLSKey:   filepath.Join(certs, "client.key"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test","marker":"`+m+`"}`)))

	assert.True(t, waitForMarker(t, m, 10*time.Second),
		"syslog should contain mTLS marker %s", m)
}

// --- Invalid certificate ---

func TestSyslog_InvalidCert_Rejected(t *testing.T) {
	certs := certDir(t)
	// Use the invalid (self-signed) cert as the CA — the server's cert
	// won't validate against it. The syslog output connects eagerly in
	// New(), so the TLS handshake failure occurs at construction time.
	_, err := syslog.New(&syslog.Config{
		Network:  "tcp+tls",
		Address:  "localhost:6514",
		Facility: "local0",
		AppName:  "audit-test",
		TLSCA:    filepath.Join(certs, "invalid.crt"),
	})
	assert.Error(t, err, "construction with invalid CA should fail TLS handshake")
	// text-only: error originates from crypto/tls handshake; no audit sentinel in the chain.
	assert.Contains(t, err.Error(), "certificate")
}

// --- RFC 5424 format ---

func TestSyslog_RFC5424_Format(t *testing.T) {
	m := marker(t)
	out, err := syslog.New(&syslog.Config{
		Network:  "tcp",
		Address:  "localhost:5514",
		Facility: "local0",
		AppName:  "audit-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write([]byte(`{"event":"rfc5424","marker":"`+m+`"}`)))

	require.True(t, waitForMarker(t, m, 10*time.Second))

	log := readSyslogLog(t)
	// Find the line with our marker.
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, m) {
			// Verify it contains the app name.
			assert.Contains(t, line, "audit-test",
				"syslog line should contain app name")
			// Verify it has a timestamp (current year).
			assert.Contains(t, line, time.Now().Format("2006"),
				"syslog line should contain a timestamp")
			return
		}
	}
	t.Fatal("marker line not found in syslog log")
}
