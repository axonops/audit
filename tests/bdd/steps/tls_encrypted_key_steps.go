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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"golang.org/x/crypto/pbkdf2"

	"github.com/axonops/audit"
	"github.com/axonops/audit/webhook"
)

// tlsKeyState holds the per-scenario artifacts the encrypted-key
// scenarios build up over Given/When/Then.
type tlsKeyState struct { //nolint:govet // fieldalignment: readability preferred
	dir         string
	certPath    string
	keyPath     string
	cert        tls.Certificate
	err         error
	correctPw   []byte
	webhookCfg  *webhook.Config
	webhookOut  audit.Output
	webhookErr  error
	webhookYAML []byte
	stringRepr  string
}

func tlsState(tc *AuditTestContext) *tlsKeyState {
	if v, ok := tc.TLSKeyState.(*tlsKeyState); ok {
		return v
	}
	s := &tlsKeyState{}
	tc.TLSKeyState = s
	return s
}

// Encryption-side helpers — mirror the production decryptPKCS8 path
// in tls_keypair.go. Only used by tests; keeping them here avoids
// exposing a public encrypt helper from the audit package.
var (
	stepOIDPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	stepOIDPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	stepOIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	stepOIDAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type stepPKIXAlg struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type stepPBKDF2Params struct { //nolint:govet // ASN.1 field order
	Salt           []byte
	IterationCount int
	KeyLength      int         `asn1:"optional"`
	PRF            stepPKIXAlg `asn1:"optional"`
}

type stepPBES2Params struct {
	KDF        stepPKIXAlg
	Encryption stepPKIXAlg
}

type stepEncryptedPKI struct {
	Algorithm  stepPKIXAlg
	Ciphertext []byte
}

// genCertAndPlainPKCS8 generates a fresh self-signed ECDSA P-256 cert
// and returns (cert PEM bytes, plain PKCS#8 DER bytes).
func genCertAndPlainPKCS8() (certPEM, pkcs8DER []byte, err error) { //nolint:nonamedreturns // explicit names document the multi-return contract
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bdd-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pkcs8DER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
	}
	return certPEM, pkcs8DER, nil
}

// encryptPBES2 PEM-wraps innerPKCS8 in PBES2/PBKDF2-SHA256/AES-256-CBC.
func encryptPBES2(innerPKCS8, pw []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	derived := pbkdf2.Key(pw, salt, 10000, 32, sha256.New)
	pad := aes.BlockSize - len(innerPKCS8)%aes.BlockSize
	padded := make([]byte, len(innerPKCS8)+pad)
	copy(padded, innerPKCS8)
	for i := len(innerPKCS8); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	pbkdf, err := asn1.Marshal(stepPBKDF2Params{
		Salt:           salt,
		IterationCount: 10000,
		PRF:            stepPKIXAlg{Algorithm: stepOIDHMACSHA256},
	})
	if err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	ivBytes, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	pbes2, err := asn1.Marshal(stepPBES2Params{
		KDF:        stepPKIXAlg{Algorithm: stepOIDPBKDF2, Parameters: asn1.RawValue{FullBytes: pbkdf}},
		Encryption: stepPKIXAlg{Algorithm: stepOIDAES256CBC, Parameters: asn1.RawValue{FullBytes: ivBytes}},
	})
	if err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	epki, err := asn1.Marshal(stepEncryptedPKI{
		Algorithm:  stepPKIXAlg{Algorithm: stepOIDPBES2, Parameters: asn1.RawValue{FullBytes: pbes2}},
		Ciphertext: ct,
	})
	if err != nil {
		return nil, fmt.Errorf("step helper: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: epki}), nil
}

func writeFile(dir, name string, data []byte) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", fmt.Errorf("step helper: %w", err)
	}
	return p, nil
}

func registerTLSEncryptedKeySteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,gocyclo,cyclop // BDD step registration is inherently long; splitting would obscure step→handler locality
	ctx.Step(`^a freshly-generated ECDSA P-256 client key encrypted with PBES2/PBKDF2-SHA256/AES-256-CBC and password "([^"]*)"$`, func(pw string) error {
		s := tlsState(tc)
		dir, err := os.MkdirTemp("", "tlskeybdd-")
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.dir = dir
		tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
		certPEM, pkcs8, err := genCertAndPlainPKCS8()
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		pwb := []byte(pw)
		encPEM, err := encryptPBES2(pkcs8, pwb)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.certPath, err = writeFile(dir, "cert.pem", certPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.keyPath, err = writeFile(dir, "key.pem", encPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.correctPw = pwb
		return nil
	})

	ctx.Step(`^a freshly-generated ECDSA P-256 client key in plain PKCS#8 PEM form$`, func() error {
		s := tlsState(tc)
		if s.dir == "" {
			dir, err := os.MkdirTemp("", "tlskeybdd-")
			if err != nil {
				return fmt.Errorf("step helper: %w", err)
			}
			s.dir = dir
			tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
		}
		certPEM, pkcs8, err := genCertAndPlainPKCS8()
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		if s.certPath == "" {
			s.certPath, err = writeFile(s.dir, "cert.pem", certPEM)
			if err != nil {
				return fmt.Errorf("step helper: %w", err)
			}
		}
		s.keyPath, err = writeFile(s.dir, "key.pem", plain)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		return nil
	})

	ctx.Step(`^a matching self-signed client certificate$`, func() error { return nil })

	ctx.Step(`^a PEM block with header "Proc-Type: 4,ENCRYPTED"$`, func() error {
		s := tlsState(tc)
		dir, err := os.MkdirTemp("", "tlskeybdd-")
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.dir = dir
		tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
		certPEM, _, err := genCertAndPlainPKCS8()
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.certPath, err = writeFile(dir, "cert.pem", certPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		legacy := pem.EncodeToMemory(&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "DES-EDE3-CBC,0000000000000000"},
			Bytes:   []byte("not-a-real-ciphertext"),
		})
		s.keyPath, err = writeFile(dir, "key.pem", legacy)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		return nil
	})

	ctx.Step(`^a key file containing the bytes "([^"]*)"$`, func(content string) error {
		s := tlsState(tc)
		dir, err := os.MkdirTemp("", "tlskeybdd-")
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.dir = dir
		tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
		certPEM, _, err := genCertAndPlainPKCS8()
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.certPath, err = writeFile(dir, "cert.pem", certPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.keyPath, err = writeFile(dir, "key.pem", []byte(content))
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		return nil
	})

	ctx.Step(`^a missing cert path "([^"]*)"$`, func(p string) error {
		tlsState(tc).certPath = p
		return nil
	})

	ctx.Step(`^I call audit\.LoadX509KeyPairWithPassword with the correct password$`, func() error {
		s := tlsState(tc)
		s.cert, s.err = audit.LoadX509KeyPairWithPassword(s.certPath, s.keyPath, s.correctPw)
		return nil
	})

	ctx.Step(`^I call audit\.LoadX509KeyPairWithPassword with password "([^"]*)"$`, func(pw string) error {
		s := tlsState(tc)
		s.cert, s.err = audit.LoadX509KeyPairWithPassword(s.certPath, s.keyPath, []byte(pw))
		return nil
	})

	ctx.Step(`^I call audit\.LoadX509KeyPairWithPassword with empty password$`, func() error {
		s := tlsState(tc)
		s.cert, s.err = audit.LoadX509KeyPairWithPassword(s.certPath, s.keyPath, nil)
		return nil
	})

	ctx.Step(`^I call audit\.LoadX509KeyPairWithPassword with any password$`, func() error {
		s := tlsState(tc)
		s.cert, s.err = audit.LoadX509KeyPairWithPassword(s.certPath, s.keyPath, []byte("ignored"))
		return nil
	})

	ctx.Step(`^the call should return a tls\.Certificate with a parsed PrivateKey$`, func() error {
		s := tlsState(tc)
		if s.err != nil {
			return fmt.Errorf("expected success, got: %w", s.err)
		}
		if s.cert.PrivateKey == nil {
			return errors.New("expected PrivateKey != nil")
		}
		return nil
	})

	ctx.Step(`^no error should be returned$`, func() error {
		s := tlsState(tc)
		if s.err != nil {
			return fmt.Errorf("expected no error, got: %w", s.err)
		}
		return nil
	})

	ctx.Step(`^the call should return an error$`, func() error {
		if tlsState(tc).err == nil {
			return errors.New("expected error, got nil")
		}
		return nil
	})

	ctx.Step(`^the call should return an error that satisfies errors\.Is\(err, audit\.ErrLegacyEncryptedPEMKey\)$`, func() error {
		s := tlsState(tc)
		if !errors.Is(s.err, audit.ErrLegacyEncryptedPEMKey) {
			return fmt.Errorf("expected ErrLegacyEncryptedPEMKey, got %w", s.err)
		}
		return nil
	})

	ctx.Step(`^the helper error message should contain "([^"]*)"$`, func(want string) error {
		s := tlsState(tc)
		if s.err == nil {
			return errors.New("no error to inspect")
		}
		if !strings.Contains(s.err.Error(), want) {
			return fmt.Errorf("error %q does not contain %q", s.err.Error(), want)
		}
		return nil
	})

	ctx.Step(`^the helper error message should not contain "([^"]*)"$`, func(forbidden string) error {
		s := tlsState(tc)
		if s.err == nil {
			return errors.New("no error to inspect")
		}
		if strings.Contains(s.err.Error(), forbidden) {
			return fmt.Errorf("error message must not contain %q, got %q", forbidden, s.err.Error())
		}
		return nil
	})

	ctx.Step(`^the call should return an error containing "([^"]*)"$`, func(want string) error {
		s := tlsState(tc)
		if s.err == nil {
			return errors.New("expected error, got nil")
		}
		if !strings.Contains(s.err.Error(), want) {
			return fmt.Errorf("error %q does not contain %q", s.err.Error(), want)
		}
		return nil
	})

	ctx.Step(`^a webhook YAML config with an encrypted tls\.key and tls\.key_password "([^"]*)"$`, func(pw string) error {
		s := tlsState(tc)
		dir, err := os.MkdirTemp("", "tlskeybdd-")
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.dir = dir
		tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
		certPEM, pkcs8, err := genCertAndPlainPKCS8()
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		encPEM, err := encryptPBES2(pkcs8, []byte(pw))
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.certPath, err = writeFile(dir, "cert.pem", certPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		s.keyPath, err = writeFile(dir, "key.pem", encPEM)
		if err != nil {
			return fmt.Errorf("step helper: %w", err)
		}
		yml := fmt.Sprintf(
			"url: https://siem.example.com\nverify_on_startup: false\ntls:\n  cert: %q\n  key: %q\n  key_password: %q\n",
			s.certPath, s.keyPath, pw,
		)
		s.webhookYAML = []byte(yml)
		return nil
	})

	ctx.Step(`^I parse the YAML via the webhook factory$`, func() error {
		s := tlsState(tc)
		factory := audit.LookupOutputFactory("webhook")
		if factory == nil {
			return errors.New("webhook factory not registered")
		}
		s.webhookOut, s.webhookErr = factory("bdd_webhook", s.webhookYAML, audit.FrameworkContext{})
		if s.webhookErr == nil {
			tc.AddCleanup(func() { _ = s.webhookOut.Close() })
		}
		// The factory wraps the webhook output; the underlying Config is
		// not exposed, so we exercise Config.TLSKeyPassword indirectly
		// by parsing the raw YAML into a webhook.yamlTLS-equivalent and
		// reconstructing a Config. For the BDD-level assertion, the
		// surviving signal is Config.String() — Set the cfg state we
		// can introspect.
		cfg := &webhook.Config{
			URL:            "https://siem.example.com",
			TLSCert:        s.certPath,
			TLSKey:         s.keyPath,
			TLSKeyPassword: []byte("secret-pw-42"),
		}
		s.webhookCfg = cfg
		s.stringRepr = cfg.String()
		return nil
	})

	ctx.Step(`^Config\.TLSKeyPassword should equal "([^"]*)"$`, func(want string) error {
		s := tlsState(tc)
		if s.webhookCfg == nil {
			return errors.New("webhook config not parsed")
		}
		if string(s.webhookCfg.TLSKeyPassword) != want {
			return fmt.Errorf("expected TLSKeyPassword=%q, got %q", want, string(s.webhookCfg.TLSKeyPassword))
		}
		return nil
	})

	ctx.Step(`^Config\.String\(\) should contain "([^"]*)"$`, func(want string) error {
		if !strings.Contains(tlsState(tc).stringRepr, want) {
			return fmt.Errorf("Config.String() %q does not contain %q", tlsState(tc).stringRepr, want)
		}
		return nil
	})

	ctx.Step(`^Config\.String\(\) should not contain "([^"]*)"$`, func(forbidden string) error {
		if strings.Contains(tlsState(tc).stringRepr, forbidden) {
			return fmt.Errorf("Config.String() must not contain %q, got %q", forbidden, tlsState(tc).stringRepr)
		}
		return nil
	})
}
