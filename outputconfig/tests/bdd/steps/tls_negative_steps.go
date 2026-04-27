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
// in-process secrets-provider scenarios in
// outputconfig/tests/bdd/features/secret_resolution.feature:
//
//   - expired-cert (#552 AC#2): TLS handshake fails because the
//     server presents a deliberately-expired leaf certificate.
//   - malformed-JSON (#563): TLS handshake succeeds but the server
//     responds with a body the vault/openbao provider's JSON parser
//     rejects.
//
// Both pathways stand up an in-process HTTPS server signed by a
// fresh CA the audit-side provider trusts; the rejection cause is
// therefore exactly the defect we install — not "unknown
// authority" or "connection refused".
func registerSecretsTLSNegativeSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(
		`^an? (vault|openbao) HTTPS provider with an expired server certificate$`,
		func(scheme string) error {
			return startInProcHTTPSProvider(tc, scheme, certSpecExpired, tlsRejectHandler())
		},
	)
	ctx.Step(
		`^an? (vault|openbao) HTTPS provider returning malformed JSON$`,
		func(scheme string) error {
			return startInProcHTTPSProvider(tc, scheme, certSpecValid, malformedJSONHandler())
		},
	)
}

// certSpec selects which leaf-certificate template the in-process
// HTTPS server presents.
type certSpec int

const (
	certSpecExpired certSpec = iota // NotAfter one hour in the past
	certSpecValid                   // NotAfter one hour in the future
)

// startInProcHTTPSProvider stands up an in-process HTTPS receiver
// and points a real vault or openbao provider at it. The shared
// scaffolding (CA generation, leaf cert, server start, provider
// construction) is reused by every secrets failure-mode scenario;
// callers vary only the leaf cert validity and the HTTP handler.
//
// The audit-side provider trusts the runtime CA, so the rejection
// cause is exactly the defect we install — expired NotAfter for
// the TLS rejection scenario, or malformed body for the JSON
// scenario — not "unknown authority".
//
//nolint:funlen,gocyclo,cyclop // sequential cert + server + provider scaffolding.
func startInProcHTTPSProvider(tc *TestContext, scheme string, spec certSpec, handler http.Handler) error {
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

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("leaf key: %w", err)
	}
	leafTemplate := leafTemplateFor(spec)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("leaf cert: %w", err)
	}

	srv := httptest.NewUnstartedServer(handler)
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
	// AllowPrivateRanges so the SSRF guard does not pre-empt the
	// rejection we are testing.
	switch scheme {
	case "vault":
		p, pErr := vault.New(&vault.Config{
			Address:            addr,
			Token:              "bdd-token-value-irrelevant-for-failure-modes",
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
			Token:              "bdd-token-value-irrelevant-for-failure-modes",
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

// leafTemplateFor returns a leaf-certificate template valid for
// localhost / 127.0.0.1, with the NotAfter selected by spec.
func leafTemplateFor(spec certSpec) *x509.Certificate {
	notBefore := time.Now().Add(-2 * time.Hour)
	notAfter := time.Now().Add(time.Hour)
	if spec == certSpecExpired {
		notAfter = time.Now().Add(-1 * time.Hour)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(301),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

// tlsRejectHandler returns a handler that 500s any request that
// reaches it. The expired-cert scenario should never let a request
// through because the TLS handshake fails first; if a request does
// arrive the 500 makes the failure unmistakable.
func tlsRejectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
}

// malformedJSONHandler returns a handler that responds 200 OK with
// a body the vault/openbao JSON parser must reject. The body
// places a raw 0xff at value position (where a quoted string is
// expected) followed by trailing junk and an unterminated object,
// so json.Unmarshal returns a SyntaxError that no recovery mode
// can mask. The vault provider's fetchPath wraps the parse error
// as `secrets.ErrSecretResolveFailed: parse response: ...` — the
// BDD assertion pins on the substring "parse response".
func malformedJSONHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"data":{"salt":` + "\xff" + `not-json,]`))
	})
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
