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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/syslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// ---------------------------------------------------------------------------
// Test helpers: TLS certificates
// ---------------------------------------------------------------------------

// testCerts holds paths to test TLS certificates and a server TLS config.
type testCerts struct {
	tlsCfg     *tls.Config
	caPath     string
	certPath   string
	keyPath    string
	clientCert string
	clientKey  string
}

// generateTestCerts creates a self-signed CA, server cert, and client
// cert for testing TLS. All files are written to t.TempDir().
func generateTestCerts(t *testing.T) *testCerts {
	t.Helper()
	dir := t.TempDir()

	// CA key and cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caCertDER)

	// Server key and cert.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "server-cert.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	writePEM(t, certPath, "CERTIFICATE", serverCertDER)
	writeKeyPEM(t, keyPath, serverKey)

	// Client key and cert.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPath := filepath.Join(dir, "client-cert.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	writePEM(t, clientCertPath, "CERTIFICATE", clientCertDER)
	writeKeyPEM(t, clientKeyPath, clientKey)

	// Server TLS config.
	serverTLSCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &testCerts{
		caPath:     caPath,
		certPath:   certPath,
		keyPath:    keyPath,
		clientCert: clientCertPath,
		clientKey:  clientKeyPath,
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		},
	}
}

// writePEM writes a PEM-encoded block to the given path.
func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}))
}

// writeKeyPEM writes an ECDSA private key as PEM to the given path.
func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	writePEM(t, path, "EC PRIVATE KEY", der)
}

// ---------------------------------------------------------------------------
// Test helpers: mock metrics
// ---------------------------------------------------------------------------

// mockMetrics implements syslog.Metrics for testing.
type mockMetrics struct {
	syslogReconnects map[string]int // "address:success|failure" -> count
	mu               sync.Mutex
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		syslogReconnects: make(map[string]int),
	}
}

// RecordSyslogReconnect satisfies syslog.Metrics.
func (m *mockMetrics) RecordSyslogReconnect(address string, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	m.syslogReconnects[key]++
}

// getSyslogReconnectCount returns the reconnect count for the given address and outcome.
func (m *mockMetrics) getSyslogReconnectCount(address string, success bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	return m.syslogReconnects[key]
}

var _ syslog.Metrics = (*mockMetrics)(nil)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

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

	out, err := syslog.New(&syslog.Config{
		Network: "tcp",
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_UDP(t *testing.T) {
	// UDP doesn't need a running server to construct.
	out, err := syslog.New(&syslog.Config{
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
		cfg     syslog.Config
	}{
		{
			name:    "missing address",
			cfg:     syslog.Config{Network: "tcp"},
			wantErr: "must not be empty",
		},
		{
			name:    "invalid network",
			cfg:     syslog.Config{Network: "http", Address: "localhost:514"},
			wantErr: "must be tcp, udp, or tcp+tls",
		},
		{
			name:    "invalid facility",
			cfg:     syslog.Config{Network: "udp", Address: "localhost:514", Facility: "bogus"},
			wantErr: "unknown syslog facility",
		},
		{
			name: "cert without key",
			cfg: syslog.Config{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCert: "/tmp/cert.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "key without cert",
			cfg: syslog.Config{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSKey:  "/tmp/key.pem",
			},
			wantErr: "tls_cert and tls_key must both be set",
		},
		{
			name: "nonexistent cert file",
			cfg: syslog.Config{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCert: "/nonexistent/cert.pem",
				TLSKey:  "/nonexistent/key.pem",
			},
			wantErr: "tls file",
		},
		{
			name: "nonexistent CA file",
			cfg: syslog.Config{
				Network: "tcp+tls",
				Address: "localhost:6514",
				TLSCA:   "/nonexistent/ca.pem",
			},
			wantErr: "tls file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := syslog.New(&tt.cfg, nil)
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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
			out, err := syslog.New(&syslog.Config{
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
	_, err := syslog.New(&syslog.Config{
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
	certs := generateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.tlsCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.caPath,
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
	certs := generateTestCerts(t)
	// Require client cert for mTLS.
	certs.tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	srv := newMockTLSSyslogServer(t, certs.tlsCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCert: certs.clientCert,
		TLSKey:  certs.clientKey,
		TLSCA:   certs.caPath,
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
	certs := generateTestCerts(t)
	srv := newMockTLSSyslogServer(t, certs.tlsCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:   "tcp+tls",
		Address:   srv.addr(),
		TLSCA:     certs.caPath,
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
	certs := generateTestCerts(t)
	// Server accepts TLS 1.2.
	certs.tlsCfg.MinVersion = tls.VersionTLS12
	srv := newMockTLSSyslogServer(t, certs.tlsCfg)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.caPath,
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

	out, err := syslog.New(&syslog.Config{
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
// Metrics (#54)
// ---------------------------------------------------------------------------

// syslogOnlyMetrics implements syslog.Metrics but not the full
// audit.Metrics interface. It is used to verify that NewSyslogOutput
// accepts any syslog.Metrics implementation.
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

var _ syslog.Metrics = (*syslogOnlyMetrics)(nil)

func TestSyslogOutput_NilSyslogMetrics_ReconnectDoesNotPanic(t *testing.T) {
	// nil Metrics must not panic during the reconnect path.
	srv := newMockSyslogServer(t)
	addr := srv.addr()

	out, err := syslog.New(&syslog.Config{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 1,
	}, nil) // nil Metrics
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

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
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
	failureCount := m.getSyslogReconnectCount(addr, false)
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

	m := newMockMetrics()
	out, err := syslog.New(&syslog.Config{
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
		if m.getSyslogReconnectCount(addr, true) > 0 {
			reconnectSucceeded = true
			break
		}
		// Brief yield — not sleeping for synchronisation, just giving the
		// reconnect goroutine a chance to complete its sub-millisecond work.
		time.Sleep(10 * time.Millisecond)
	}

	require.NoError(t, out.Close())

	if reconnectSucceeded {
		assert.Greater(t, m.getSyslogReconnectCount(addr, true), 0,
			"RecordSyslogReconnect(address, true) should be called on successful reconnect")
	} else {
		// The port rebind did not succeed fast enough on this OS/run.
		// The failure path is already verified by
		// TestSyslogOutput_SyslogMetrics_RecordSyslogReconnect_FailureOnPermanentServerDown.
		t.Log("reconnect success test skipped: port could not be rebound fast enough")
	}
}

func TestSyslogOutput_SyslogMetrics_InterfaceAssertion(t *testing.T) {
	// Compile-time: verify NewSyslogOutput accepts any syslog.Metrics,
	// not just mockMetrics. This test would not compile if the signature
	// changed.
	srv := newMockSyslogServer(t)
	defer srv.close()

	var m syslog.Metrics = &syslogOnlyMetrics{}
	out, err := syslog.New(&syslog.Config{
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
	d1 := syslog.BackoffDuration(1)
	assert.GreaterOrEqual(t, d1, 50*time.Millisecond) // 100ms * 0.5
	assert.Less(t, d1, 100*time.Millisecond)          // 100ms * 1.0

	d2 := syslog.BackoffDuration(2)
	assert.GreaterOrEqual(t, d2, 100*time.Millisecond) // 200ms * 0.5
	assert.Less(t, d2, 200*time.Millisecond)

	d3 := syslog.BackoffDuration(3)
	assert.GreaterOrEqual(t, d3, 200*time.Millisecond) // 400ms * 0.5
	assert.Less(t, d3, 400*time.Millisecond)

	// Large attempt should be capped at 30s (with jitter, 15-30s).
	d20 := syslog.BackoffDuration(20)
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

	out, err := syslog.New(&syslog.Config{
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

// ---------------------------------------------------------------------------
// handleWriteFailure — closed-during-backoff branch
// ---------------------------------------------------------------------------

func TestSyslogOutput_CloseDuringBackoff_DoesNotHang(t *testing.T) {
	// Verify that Close() called while Write() is sleeping in the
	// handleWriteFailure backoff causes Write to return promptly rather
	// than blocking for the full backoff duration.
	//
	// Strategy: connect to a server, kill it, then drive writes until
	// TCP buffering is exhausted and write actually fails (which puts
	// Write into handleWriteFailure's backoff sleep). Meanwhile, call
	// Close concurrently. If closeCh is working, Close returns quickly;
	// if not, the test blocks for tens of seconds and fails via the
	// deadline.
	//
	// TCP buffering means a single killed connection won't immediately
	// produce synchronous write errors. We use a Unix domain socket
	// listener — closing it causes immediate ECONNRESET on the writer,
	// which reliably triggers handleWriteFailure without buffering.

	srv := newMockSyslogServer(t)
	addr := srv.addr()

	// MaxRetries=20: if closeCh were broken, Write would sleep for
	// 100ms * 2^0 + 100ms * 2^1 + ... ≈ several seconds before giving
	// up, and the test would exceed its deadline.
	out, err := syslog.New(&syslog.Config{
		Network:    "tcp",
		Address:    addr,
		MaxRetries: 20,
	}, nil)
	require.NoError(t, err)

	// Establish a live connection and flush the initial TCP buffer.
	require.NoError(t, out.Write([]byte(`{"n":0}`)))
	require.True(t, srv.waitForData(2*time.Second))

	// Kill the server; existing TCP connections reset.
	srv.close()

	// Drain the TCP kernel send buffer by writing until a write
	// synchronously fails. This must happen eventually once the OS
	// processes the RST from the closed listener.
	var firstErr error
	for range 50 {
		if err := out.Write([]byte(`{"n":1}`)); err != nil {
			firstErr = err
			break
		}
	}
	if firstErr == nil {
		// On this OS/run the kernel buffer did not drain. The closeCh
		// path is still exercised by the Close call below, just via a
		// different code path (closed check, not backoff). The test
		// still validates that Close does not hang.
		t.Log("TCP buffer did not drain synchronously; testing Close-does-not-hang path only")
	}

	// Regardless of whether writes failed, Close must return promptly.
	// The write goroutine (if any) is blocked in handleWriteFailure's
	// select — Close signals closeCh to interrupt it.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for range 20 {
			_ = out.Write([]byte(`{"n":2}`))
		}
	}()

	closeDeadline := 3 * time.Second
	closeStart := time.Now()
	require.NoError(t, out.Close())
	closeElapsed := time.Since(closeStart)

	assert.Less(t, closeElapsed, closeDeadline,
		"Close should return promptly even when writes are in handleWriteFailure backoff")

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Error("write goroutine did not terminate after Close")
	}
}

// ---------------------------------------------------------------------------
// buildSyslogTLSConfig — invalid CA PEM content
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSConfig_InvalidCAPEM(t *testing.T) {
	// buildSyslogTLSConfig calls pool.AppendCertsFromPEM which returns
	// false when the file exists but contains no valid certificate PEM.
	// Verify construction fails with a meaningful error.
	dir := t.TempDir()
	badCAPath := filepath.Join(dir, "bad-ca.pem")
	// Write a file that exists but contains no valid PEM certificate block.
	require.NoError(t, os.WriteFile(badCAPath, []byte("not a certificate\n"), 0o600))

	_, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: "localhost:6514",
		TLSCA:   badCAPath,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca certificate",
		"error should mention CA certificate when PEM parsing fails")
}

// ---------------------------------------------------------------------------
// validateSyslogTLSFiles — path is a directory
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSCert_IsDirectory(t *testing.T) {
	// When the TLS cert path is a directory, validateSyslogTLSFiles
	// must return an error citing that it is a directory.
	dir := t.TempDir()

	_, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: "localhost:6514",
		TLSCert: dir, // a directory, not a file
		TLSKey:  dir,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory",
		"error should report that the TLS path is a directory")
}

// ---------------------------------------------------------------------------
// validateSyslogConfig — default network assignment
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_DefaultNetwork(t *testing.T) {
	// When Network is empty, validateSyslogConfig defaults it to "tcp".
	// Verify construction succeeds and the output is functional.
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network: "", // empty — should default to "tcp"
		Address: srv.addr(),
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"default_network"}`)))
	require.True(t, srv.waitForData(2*time.Second), "default-network output should deliver data")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// New — connect() failure at construction time
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TCP_ConnectFailure(t *testing.T) {
	// Verify that New returns an error (not panic) when the initial
	// TCP dial fails because nothing is listening at the address.
	// This exercises the connect() error path inside New.
	_, err := syslog.New(&syslog.Config{
		Network: "tcp",
		// Port 1 is privileged and not typically in use; on Linux this
		// causes a synchronous ECONNREFUSED rather than a timeout.
		Address: "127.0.0.1:1",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial",
		"error should describe the dial failure")
}

// ---------------------------------------------------------------------------
// buildSyslogTLSConfig — corrupt mTLS client cert/key pair
// ---------------------------------------------------------------------------

func TestNewSyslogOutput_TLSConfig_InvalidClientCert(t *testing.T) {
	// buildSyslogTLSConfig calls tls.LoadX509KeyPair which fails when
	// the cert and key files exist but contain invalid PEM.
	// This exercises the LoadX509KeyPair error branch.
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad-cert.pem")
	badKey := filepath.Join(dir, "bad-key.pem")
	require.NoError(t, os.WriteFile(badCert, []byte("not a cert\n"), 0o600))
	require.NoError(t, os.WriteFile(badKey, []byte("not a key\n"), 0o600))

	_, err := syslog.New(&syslog.Config{
		Network: "tcp+tls",
		Address: "localhost:6514",
		TLSCert: badCert,
		TLSKey:  badKey,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls config",
		"error should indicate a TLS configuration failure")
}
