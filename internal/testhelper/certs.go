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

// Package testhelper provides shared test utilities for audit
// sub-modules. It is never published as a release artifact.
package testhelper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCerts holds paths to test TLS certificates and a server TLS config.
type TestCerts struct {
	TLSCfg     *tls.Config
	CAPath     string
	CertPath   string
	KeyPath    string
	ClientCert string
	ClientKey  string
}

// GenerateTestCerts creates a self-signed CA, server cert, and client
// cert for testing TLS. All files are written to t.TempDir().
func GenerateTestCerts(t *testing.T) *TestCerts {
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
	WritePEM(t, caPath, "CERTIFICATE", caCertDER)

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
	WritePEM(t, certPath, "CERTIFICATE", serverCertDER)
	WriteKeyPEM(t, keyPath, serverKey)

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
	WritePEM(t, clientCertPath, "CERTIFICATE", clientCertDER)
	WriteKeyPEM(t, clientKeyPath, clientKey)

	// Server TLS config.
	serverTLSCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &TestCerts{
		CAPath:     caPath,
		CertPath:   certPath,
		KeyPath:    keyPath,
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
		TLSCfg: &tls.Config{
			Certificates: []tls.Certificate{serverTLSCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		},
	}
}

// BadCerts holds a CA plus two server certificates with deliberate
// defects, used by negative-path TLS tests (#552). Both server
// certs are signed by the same runtime CA, so a client trusting
// CAPath fails for the installed defect — expired NotAfter or
// CN/SAN mismatch — rather than "unknown authority".
type BadCerts struct {
	CAPath          string
	ExpiredCertPath string
	ExpiredKeyPath  string
	WrongCNCertPath string
	WrongCNKeyPath  string
}

// GenerateBadCerts produces a fresh CA and two server certificates
// (one expired, one with wrong CN/SAN) under t.TempDir. ECDSA
// P-256. The two server cert pairs are independently usable in
// TLS server configs that need to be rejected by a client that
// trusts CAPath.
//
//   - Expired: NotAfter set one hour in the past; DNSNames
//     "localhost" + IPAddresses 127.0.0.1.
//   - WrongCN: NotAfter valid; DNSNames "elsewhere.example.com".
//
// Use [ExpiredCert] / [WrongCNCert] for a single-cert convenience
// when only one defect is needed.
func GenerateBadCerts(t *testing.T) *BadCerts {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Bad-Cert Test CA"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
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
	WritePEM(t, caPath, "CERTIFICATE", caCertDER)

	expiredCertPath, expiredKeyPath := writeBadServerCert(t, dir, "expired",
		caCert, caKey,
		&x509.Certificate{
			SerialNumber: big.NewInt(101),
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-2 * time.Hour),
			NotAfter:     time.Now().Add(-1 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		})

	wrongCertPath, wrongKeyPath := writeBadServerCert(t, dir, "wrong-cn",
		caCert, caKey,
		&x509.Certificate{
			SerialNumber: big.NewInt(102),
			Subject:      pkix.Name{CommonName: "elsewhere.example.com"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"elsewhere.example.com"},
		})

	return &BadCerts{
		CAPath:          caPath,
		ExpiredCertPath: expiredCertPath,
		ExpiredKeyPath:  expiredKeyPath,
		WrongCNCertPath: wrongCertPath,
		WrongCNKeyPath:  wrongKeyPath,
	}
}

// ExpiredCert is a convenience wrapper that returns just the
// expired-NotAfter cert pair (plus its CA path). Equivalent to
// (BadCerts.ExpiredCertPath, .ExpiredKeyPath, .CAPath) from
// [GenerateBadCerts].
func ExpiredCert(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	bc := GenerateBadCerts(t)
	return bc.ExpiredCertPath, bc.ExpiredKeyPath, bc.CAPath
}

// WrongCNCert is the matching convenience wrapper for the
// CN/SAN-mismatch cert pair. Returns
// (BadCerts.WrongCNCertPath, .WrongCNKeyPath, .CAPath).
func WrongCNCert(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	bc := GenerateBadCerts(t)
	return bc.WrongCNCertPath, bc.WrongCNKeyPath, bc.CAPath
}

// writeBadServerCert is a sequential helper used by
// GenerateBadCerts to keep the per-defect template list readable.
func writeBadServerCert(t *testing.T, dir, name string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, template *x509.Certificate) (certPath, keyPath string) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	certPath = filepath.Join(dir, name+"-cert.pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	WritePEM(t, certPath, "CERTIFICATE", der)
	WriteKeyPEM(t, keyPath, leafKey)
	return certPath, keyPath
}

// WritePEM writes a PEM-encoded block to the given path.
func WritePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}))
}

// WriteKeyPEM writes an ECDSA private key as PEM to the given path.
func WriteKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	WritePEM(t, path, "EC PRIVATE KEY", der)
}
