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

	"github.com/axonops/go-audit"
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
	})
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestNewSyslogOutput_UDP(t *testing.T) {
	// UDP doesn't need a running server to construct.
	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "udp",
		Address: "127.0.0.1:9514",
	})
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
			_, err := audit.NewSyslogOutput(&tt.cfg)
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
	})
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
	})
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
	})
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
	})
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
	})
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
	})
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
			})
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
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown syslog facility")
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// testCerts generates a self-signed CA, server cert, and optionally
// a client cert for testing TLS.
type testCerts struct {
	tlsCfg     *tls.Config
	caPath     string
	certPath   string
	keyPath    string
	clientCert string
	clientKey  string
}

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

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}))
}

func writeKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	writePEM(t, path, "EC PRIVATE KEY", der)
}

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

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCA:   certs.caPath,
	})
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

	out, err := audit.NewSyslogOutput(&audit.SyslogConfig{
		Network: "tcp+tls",
		Address: srv.addr(),
		TLSCert: certs.clientCert,
		TLSKey:  certs.clientKey,
		TLSCA:   certs.caPath,
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"mtls_test"}`)))
	require.True(t, srv.waitForData(2*time.Second), "mTLS server should receive data")
	require.NoError(t, out.Close())

	msgs := srv.getMessages()
	require.NotEmpty(t, msgs)
	assert.Contains(t, msgs[0], "mtls_test")
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
	})
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
