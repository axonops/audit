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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"

	"github.com/axonops/audit"
)

// makeCertAndKey generates a self-signed ECDSA P-256 cert and its
// PKCS#8 DER bytes. Used by every test that needs a real cert/key
// pair.
func makeCertAndKey(t *testing.T) (certPEM, keyPKCS8DER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return certPEM, pkcs8
}

// PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC encrypted PKCS#8 wrapper.
// Mirrors the structures decoded by decryptPKCS8 in tls_keypair.go;
// used only by tests to produce known-good encrypted blocks.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}

	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type pkixAlg struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbkdf2Params struct { //nolint:govet // ASN.1 marshalling requires this field order
	Salt           []byte
	IterationCount int
	KeyLength      int     `asn1:"optional"`
	PRF            pkixAlg `asn1:"optional"`
}

type pbes2Params struct {
	KDF        pkixAlg
	Encryption pkixAlg
}

type encryptedPKI struct {
	Algorithm  pkixAlg
	Ciphertext []byte
}

// encryptPKCS8WithPBES2 builds an `ENCRYPTED PRIVATE KEY` PEM block
// encrypting innerPKCS8DER with PBKDF2-HMAC-SHA256 + AES-256-CBC.
// Used only by tests.
func encryptPKCS8WithPBES2(t *testing.T, innerPKCS8DER, pw []byte) []byte {
	t.Helper()
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	const iters = 10000
	derivedKey := pbkdf2.Key(pw, salt, iters, 32, sha256.New)

	// PKCS#7 pad to AES block size.
	pad := aes.BlockSize - len(innerPKCS8DER)%aes.BlockSize
	padded := make([]byte, len(innerPKCS8DER)+pad)
	copy(padded, innerPKCS8DER)
	for i := len(innerPKCS8DER); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	block, err := aes.NewCipher(derivedKey)
	require.NoError(t, err)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	pbkdfParams := pbkdf2Params{
		Salt:           salt,
		IterationCount: iters,
		PRF:            pkixAlg{Algorithm: oidHMACSHA256},
	}
	pbkdfDER, err := asn1.Marshal(pbkdfParams)
	require.NoError(t, err)
	ivDER, err := asn1.Marshal(iv)
	require.NoError(t, err)
	pbes2 := pbes2Params{
		KDF: pkixAlg{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: pbkdfDER},
		},
		Encryption: pkixAlg{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivDER},
		},
	}
	pbes2DER, err := asn1.Marshal(pbes2)
	require.NoError(t, err)

	epki := encryptedPKI{
		Algorithm: pkixAlg{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2DER},
		},
		Ciphertext: ciphertext,
	}
	epkiDER, err := asn1.Marshal(epki)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: epkiDER})
}

func writeTempPEM(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func TestLoadX509KeyPairWithPassword_PKCS8_AES256_Success(t *testing.T) {
	t.Parallel()
	certPEM, pkcs8DER := makeCertAndKey(t)
	pw := []byte("correct-horse-battery-staple")
	encPEM := encryptPKCS8WithPBES2(t, pkcs8DER, pw)

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", encPEM)

	cert, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, pw)
	require.NoError(t, err)
	require.NotNil(t, cert.Certificate)
	require.NotNil(t, cert.PrivateKey)
}

func TestLoadX509KeyPairWithPassword_WrongPassword(t *testing.T) {
	t.Parallel()
	certPEM, pkcs8DER := makeCertAndKey(t)
	pw := []byte("real-password")
	encPEM := encryptPKCS8WithPBES2(t, pkcs8DER, pw)

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", encPEM)

	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, []byte("wrong-password"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "real-password",
		"correct password MUST NOT appear in error output")
	assert.NotContains(t, err.Error(), "wrong-password",
		"supplied password MUST NOT appear in error output")
}

func TestLoadX509KeyPairWithPassword_LegacyDEKInfo_Refused(t *testing.T) {
	t.Parallel()
	certPEM, _ := makeCertAndKey(t)
	// Hand-craft a PEM block with the legacy `Proc-Type: 4,ENCRYPTED`
	// header — we don't even need to put a real ciphertext in; the
	// loader rejects on the header alone.
	legacy := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "DES-EDE3-CBC,0000000000000000",
		},
		Bytes: []byte("not-a-real-ciphertext"),
	})

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", legacy)

	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, []byte("ignored"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, audit.ErrLegacyEncryptedPEMKey),
		"expected ErrLegacyEncryptedPEMKey, got %T %v", err, err)
	assert.Contains(t, err.Error(), "openssl pkcs8 -topk8 -v2 aes256",
		"error must include the rewrap recipe: %q", err.Error())
}

func TestLoadX509KeyPairWithPassword_UnencryptedKey_NonEmptyPassword_Refused(t *testing.T) {
	t.Parallel()
	certPEM, pkcs8DER := makeCertAndKey(t)
	// Encode the PKCS#8 as a plain `PRIVATE KEY` (no encryption).
	plainKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", plainKey)

	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, []byte("unexpected"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not encrypted", "error must explain the mismatch: %q", err.Error())
}

func TestLoadX509KeyPairWithPassword_EncryptedKey_EmptyPassword_Refused(t *testing.T) {
	t.Parallel()
	certPEM, pkcs8DER := makeCertAndKey(t)
	encPEM := encryptPKCS8WithPBES2(t, pkcs8DER, []byte("hunter2"))

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", encPEM)

	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a non-empty key_password",
		"error must request the missing password: %q", err.Error())
}

func TestLoadX509KeyPairWithPassword_PlainKey_EmptyPassword_Success(t *testing.T) {
	t.Parallel()
	// Verify the unencrypted path still works.
	certPEM, pkcs8DER := makeCertAndKey(t)
	plainKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", plainKey)

	cert, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, nil)
	require.NoError(t, err)
	require.NotNil(t, cert.PrivateKey)
}

func TestLoadX509KeyPairWithPassword_MalformedKey_PEM(t *testing.T) {
	t.Parallel()
	certPEM, _ := makeCertAndKey(t)
	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", []byte("not a PEM file"))

	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PEM block", "expected PEM diagnostic: %q", err.Error())
}

func TestLoadX509KeyPairWithPassword_MissingCertFile(t *testing.T) {
	t.Parallel()
	_, pkcs8DER := makeCertAndKey(t)
	keyPath := writeTempPEM(t, "key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))

	_, err := audit.LoadX509KeyPairWithPassword("/nonexistent/cert.pem", keyPath, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read certificate", "expected explicit read-certificate error: %q", err.Error())
}

func TestLoadX509KeyPairWithPassword_ErrorsDoNotLeakPassword(t *testing.T) {
	t.Parallel()
	certPEM, pkcs8DER := makeCertAndKey(t)
	secret := []byte("PASSWORD-SHOULD-NEVER-APPEAR-IN-ERRORS")
	encPEM := encryptPKCS8WithPBES2(t, pkcs8DER, secret)
	certPath := writeTempPEM(t, "cert.pem", certPEM)
	keyPath := writeTempPEM(t, "key.pem", encPEM)

	// Iterate a handful of failure-producing scenarios; each must
	// keep the secret bytes out of err.Error().
	_, err := audit.LoadX509KeyPairWithPassword(certPath, keyPath, []byte("WRONG-PASSWORD"))
	require.Error(t, err)
	if bytes.Contains([]byte(err.Error()), secret) ||
		strings.Contains(err.Error(), "WRONG-PASSWORD") {
		t.Fatalf("error message must not contain password bytes: %q", err.Error())
	}
}
