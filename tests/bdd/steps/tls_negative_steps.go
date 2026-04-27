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
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit/loki"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
)

// registerTLSNegativeSteps wires step definitions for the TLS
// expired-cert and CN-mismatch scenarios in
// tests/bdd/features/{syslog,webhook,loki}_output.feature (#552).
//
// Each scenario constructs an in-process TLS receiver presenting a
// deliberately-broken certificate (NotAfter in the past or DNSNames
// pointing somewhere other than localhost / 127.0.0.1), points the
// audit output at that receiver, and verifies the construction
// path returns a clear TLS-rejection error.
//
// Certificates are generated per-scenario at test runtime. The
// trust anchor presented to the audit output's TLS config is the
// runtime CA, so the rejection cause is exactly the defect we
// installed (expired / wrong-CN) — not "unknown CA".
//
//nolint:gocognit,gocyclo,cyclop // independent ctx.Step registrations.
func registerTLSNegativeSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^bad TLS certs are generated$`, func() error {
		bc, err := generateBadCerts()
		if err != nil {
			return fmt.Errorf("generate bad certs: %w", err)
		}
		tc.BadCerts = bc
		tc.AddCleanup(func() { _ = os.RemoveAll(bc.dir) })
		return nil
	})

	ctx.Step(`^a syslog TLS receiver presenting an expired certificate$`,
		func() error { return startSyslogReceiver(tc, tc.BadCerts.expiredTLS) })
	ctx.Step(`^a syslog TLS receiver presenting a wrong-CN certificate$`,
		func() error { return startSyslogReceiver(tc, tc.BadCerts.wrongCNTLS) })

	ctx.Step(`^a webhook HTTPS receiver presenting an expired certificate$`,
		func() error { return startHTTPSReceiver(tc, tc.BadCerts.expiredTLS) })
	ctx.Step(`^a webhook HTTPS receiver presenting a wrong-CN certificate$`,
		func() error { return startHTTPSReceiver(tc, tc.BadCerts.wrongCNTLS) })

	ctx.Step(`^a loki HTTPS receiver presenting an expired certificate$`,
		func() error { return startHTTPSReceiver(tc, tc.BadCerts.expiredTLS) })
	ctx.Step(`^a loki HTTPS receiver presenting a wrong-CN certificate$`,
		func() error { return startHTTPSReceiver(tc, tc.BadCerts.wrongCNTLS) })

	ctx.Step(`^I try to send a syslog event over TLS to that receiver$`, func() error {
		out, err := syslog.New(&syslog.Config{
			Network: "tcp+tls",
			Address: tc.BadReceiverAddr,
			TLSCA:   tc.BadCerts.caPath,
		})
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
			// Try one Write to surface the handshake error if construction
			// did not perform the handshake itself.
			if writeErr := out.Write([]byte("syslog test\n")); writeErr != nil {
				err = writeErr
			}
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to send a webhook event to that receiver$`, func() error {
		out, err := webhook.New(&webhook.Config{
			URL:   "https://" + tc.BadReceiverAddr + "/audit",
			TLSCA: tc.BadCerts.caPath,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
			if writeErr := out.Write([]byte(`{"event":"test"}` + "\n")); writeErr != nil {
				err = writeErr
			}
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to send a loki event to that receiver$`, func() error {
		out, err := loki.New(&loki.Config{
			URL:   "https://" + tc.BadReceiverAddr + "/loki/api/v1/push",
			TLSCA: tc.BadCerts.caPath,
		}, nil)
		if out != nil {
			tc.AddCleanup(func() { _ = out.Close() })
			if writeErr := out.Write([]byte(`{"streams":[]}` + "\n")); writeErr != nil {
				err = writeErr
			}
		}
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^the bad-cert receiver should have received no requests$`, func() error {
		if tc.BadReceiverHits == nil {
			return fmt.Errorf("no HTTPS receiver was started")
		}
		// Give the async webhook/loki delivery goroutine time to
		// attempt the handshake and fail. The handshake fails fast
		// (well under 100 ms locally); 500 ms is comfortable for
		// CI under load. If TLS rejection is broken, the request
		// reaches the receiver in this window.
		time.Sleep(500 * time.Millisecond)
		hits := atomic.LoadUint32(tc.BadReceiverHits)
		if hits != 0 {
			return fmt.Errorf("bad-cert receiver got %d requests; "+
				"TLS rejection failed — the audit client did not "+
				"refuse the broken certificate", hits)
		}
		return nil
	})

	ctx.Step(`^the TLS handshake should fail with "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected TLS handshake error containing %q, got nil", substr)
		}
		msg := tc.LastErr.Error()
		if !strings.Contains(msg, substr) {
			// Allow Go's portable phrasing — a few variants for the
			// same underlying defect across stdlib versions.
			alts := tlsErrorAlternatives(substr)
			matched := false
			for _, alt := range alts {
				if strings.Contains(msg, alt) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("expected error containing %q (or one of %v), got: %s",
					substr, alts, msg)
			}
		}
		return nil
	})
}

// tlsErrorAlternatives returns Go-stdlib error-string variants that
// describe the same TLS-rejection class. Used so step assertions are
// not wedded to a specific Go release's wording.
func tlsErrorAlternatives(substr string) []string {
	switch substr {
	case "expired":
		return []string{"certificate has expired", "expired or is not yet valid"}
	case "valid for":
		return []string{
			"is valid for", "x509: certificate is valid for",
			"cannot validate certificate",
			"doesn't contain any IP SANs",
		}
	}
	return nil
}

// badCerts holds the two server-side TLS configs for the
// expired-cert and wrong-CN scenarios, plus the CA the audit client
// trusts so the rejection is for the cert defect — not for unknown
// authority. caCert/caKey are exposed so additional in-process
// receivers (e.g., the flapping-restart server in
// tls_handshake_steps.go) can mint valid leaf certs from the same
// CA without spawning a fresh trust anchor.
type badCerts struct {
	expiredTLS *tls.Config
	wrongCNTLS *tls.Config
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	caPath     string
	dir        string
}

// generateBadCerts produces a fresh CA plus two server certs (one
// expired, one with wrong CN/SAN) under a temp directory. Caller
// must clean up bc.dir. Sequential cert scaffolding is clearer
// inline than as a chain of helpers.
//
//nolint:funlen // sequential cert scaffolding.
func generateBadCerts() (*badCerts, error) {
	dir, err := os.MkdirTemp("", "bdd-bad-certs-*")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("ca parse: %w", err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	if writeErr := writePEMFile(caPath, "CERTIFICATE", caCertDER); writeErr != nil {
		return nil, fmt.Errorf("ca pem: %w", writeErr)
	}

	// Expired server cert.
	expiredTLS, err := makeServerTLSConfig(caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		return nil, fmt.Errorf("expired cert: %w", err)
	}

	// Wrong-CN server cert: presents a name the client did not
	// dial, so hostname verification fails.
	wrongCNTLS, err := makeServerTLSConfig(caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "elsewhere.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"elsewhere.example.com"},
	})
	if err != nil {
		return nil, fmt.Errorf("wrong-cn cert: %w", err)
	}

	return &badCerts{
		expiredTLS: expiredTLS,
		wrongCNTLS: wrongCNTLS,
		caPath:     caPath,
		dir:        dir,
		caCert:     caCert,
		caKey:      caKey,
	}, nil
}

// validLocalhostTemplate returns a server-cert template good for
// localhost / 127.0.0.1 with a valid 1-hour expiry window. Used by
// receivers that need to present a valid (non-defective) cert from
// the same CA the audit client trusts — for example the flapping
// rapid-restart receiver, where the test target is the connection
// drop, not the TLS rejection.
func validLocalhostTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
}

func makeServerTLSConfig(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, template *x509.Certificate) (*tls.Config, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("leaf key: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("leaf cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  leafKey,
		}},
		MinVersion: tls.VersionTLS12,
	}, nil
}

// writePEMFile writes a PEM block to a path under a temp directory
// chosen by the caller. The path is constructed from the caller's
// own temp dir; gosec G304 warning is silenced because the path is
// internal to the test helper.
func writePEMFile(path, blockType string, der []byte) error {
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

// startSyslogReceiver starts a TCP+TLS listener on a free local
// port using the given config. The listener accepts and discards
// any connection that completes the handshake. The bad certs
// configured here will cause the client's handshake to fail before
// reaching the accept loop, so the receiver is effectively a dummy
// — it just owns the port the client dials.
func startSyslogReceiver(tc *AuditTestContext, cfg *tls.Config) error {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		return fmt.Errorf("syslog tls listen: %w", err)
	}
	tc.BadReceiverAddr = ln.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()
	tc.AddCleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return nil
}

// startHTTPSReceiver starts an httptest.NewUnstartedServer with the
// given TLS config, then calls StartTLS so it serves over HTTPS
// using our custom (broken) cert. Increments tc.BadReceiverHits on
// every request that completes the handshake — used by the webhook
// and loki TLS scenarios to assert "no request reached the
// handler" (because the audit client refused the certificate).
func startHTTPSReceiver(tc *AuditTestContext, cfg *tls.Config) error {
	tc.BadReceiverHits = new(uint32)
	hits := tc.BadReceiverHits
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddUint32(hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	tc.BadReceiverAddr = strings.TrimPrefix(srv.URL, "https://")
	tc.AddCleanup(func() { srv.Close() })
	return nil
}

// errIsTLSHandshakeFailure is a backstop when the per-scenario
// substring assertion does not match — most TLS handshake errors
// surface generic error types.
//
//nolint:unused // retained for use by future TLS scenarios.
func errIsTLSHandshakeFailure(err error) bool {
	if err == nil {
		return false
	}
	var rec tls.RecordHeaderError
	return errors.As(err, &rec) || strings.Contains(err.Error(), "tls:") ||
		strings.Contains(err.Error(), "x509:") ||
		strings.Contains(err.Error(), "TLS handshake")
}
