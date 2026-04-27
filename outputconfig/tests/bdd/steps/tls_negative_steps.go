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

package steps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit/outputconfig"
	"github.com/axonops/audit/secrets/openbao"
	"github.com/axonops/audit/secrets/vault"
)

// registerSecretsTLSNegativeSteps wires step definitions for the
// expired-cert scenarios in
// outputconfig/tests/bdd/features/secret_resolution.feature (#552
// AC#2). The scenario stands up an in-process HTTPS server presenting
// a deliberately-expired certificate, points a real secrets provider
// (vault or openbao) at it through the audit-trusted CA, and asserts
// that outputconfig.Load surfaces the TLS handshake failure rather
// than silently succeeding or hanging.
//
// The receiver path mirrors the syslog/webhook/loki TLS negative-path
// helpers in tests/bdd/steps/tls_negative_steps.go. It lives in this
// sub-module because the secrets provider Load path is what we want
// to exercise — outputconfig.Load drives provider.Resolve, which is
// where the HTTPS GET fails.
func registerSecretsTLSNegativeSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(
		`^an? (vault|openbao) HTTPS provider with an expired server certificate$`,
		func(scheme string) error { return startBadCertProvider(tc, scheme) },
	)
}

// startBadCertProvider generates a fresh CA + expired server cert,
// starts an HTTPS server presenting that cert, and registers a real
// vault or openbao provider pointed at it. The audit-side provider
// trusts the runtime CA, so the TLS rejection cause is exactly
// "certificate has expired" — not "unknown authority".
//
//nolint:funlen,gocyclo,cyclop // sequential cert + server + provider scaffolding.
func startBadCertProvider(tc *TestContext, scheme string) error {
	dir, err := os.MkdirTemp("", "bdd-secrets-bad-certs-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	// The After-hook in steps.go cleans up tc.realSecretsTempDir
	// at scenario end — no separate cleanup needed.
	tc.realSecretsTempDir = dir

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ca key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "Bad-Cert Secrets CA"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("ca parse: %w", err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if writeErr := writePEMBlock(caPath, "CERTIFICATE", caCertDER); writeErr != nil {
		return fmt.Errorf("write ca pem: %w", writeErr)
	}

	// Expired server cert valid for localhost / 127.0.0.1.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("leaf key: %w", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(301),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}

	// In-process HTTPS server. Body unused — TLS handshake fails
	// before the handler is reached.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		}},
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	tc.realProviderCleanup = append(tc.realProviderCleanup, srv.Close)
	addr := srv.URL // "https://127.0.0.1:PORT"

	// Build the real provider with caPath as trust anchor and
	// AllowPrivateRanges so the SSRF guard does not pre-empt the TLS
	// rejection.
	switch scheme {
	case "vault":
		p, pErr := vault.New(&vault.Config{
			Address:            addr,
			Token:              "test-token-not-used-because-tls-fails",
			TLSCA:              caPath,
			AllowPrivateRanges: true,
		})
		if pErr != nil {
			return fmt.Errorf("vault new: %w", pErr)
		}
		tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(p))
		tc.realProviderCleanup = append(tc.realProviderCleanup, func() { _ = p.Close() })
	case "openbao":
		p, pErr := openbao.New(&openbao.Config{
			Address:            addr,
			Token:              "test-token-not-used-because-tls-fails",
			TLSCA:              caPath,
			AllowPrivateRanges: true,
		})
		if pErr != nil {
			return fmt.Errorf("openbao new: %w", pErr)
		}
		tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(p))
		tc.realProviderCleanup = append(tc.realProviderCleanup, func() { _ = p.Close() })
	default:
		return fmt.Errorf("unknown provider scheme %q", scheme)
	}
	return nil
}

// writePEMBlock writes a PEM-encoded block to the given path. The
// path is constructed from a test-helper-controlled temp directory;
// gosec G304 is suppressed accordingly.
func writePEMBlock(path, blockType string, der []byte) error {
	f, err := os.Create(path) //nolint:gosec // path is test-helper-controlled
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("pem encode: %w", err)
	}
	return nil
}
