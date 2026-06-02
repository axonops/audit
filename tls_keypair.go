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

package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by RFC 8018 §A.2 as the PBKDF2-HMAC-SHA1 PRF.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// LoadX509KeyPairWithPassword loads an X.509 certificate and matching
// private key from the given file paths. If pw is empty the key is
// expected to be an unencrypted PEM; if pw is non-empty the key is
// expected to be a PKCS#8 v2 `ENCRYPTED PRIVATE KEY` PEM block
// encrypted with one of:
//
//   - PBES2 with AES-128/192/256-CBC + PBKDF2-HMAC-SHA1/SHA256/SHA512
//   - PBES2 with AES-128/192/256-CBC + scrypt
//
// Legacy PKCS#1 `Proc-Type: 4,ENCRYPTED` (`DEK-Info`) PEM blocks are
// refused with [ErrLegacyEncryptedPEMKey]; the error string carries
// the `openssl pkcs8 -topk8 -v2 aes256` rewrap recipe. Go's
// `x509.DecryptPEMBlock` exists but is deprecated since Go 1.16 as
// "insecure by design" (PKCS#5 v1.5 / MD5 KDF / DES/3DES); we do not
// fall back to it.
//
// A non-empty pw against an unencrypted key is refused (likely
// misconfiguration). An empty pw against an encrypted key is also
// refused — we do not silently send an empty password to the
// decryption routine.
//
// The password bytes are not retained by the returned
// [tls.Certificate]; callers SHOULD zero `pw` after this call returns
// to limit credential lifetime in memory.
func LoadX509KeyPairWithPassword(certPath, keyPath string, pw []byte) (tls.Certificate, error) {
	certPEM, keyPEM, err := readCertAndKey(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM, err = unsealKeyPEM(keyPEM, pw)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer zeroBytes(keyPEM)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("audit: tls: parse certificate/key pair: %w", err)
	}
	return cert, nil
}

func readCertAndKey(certPath, keyPath string) (certPEM, keyPEM []byte, err error) { //nolint:nonamedreturns // explicit names document the multi-return contract
	certPEM, err = os.ReadFile(certPath) //nolint:gosec // path is operator-supplied configuration
	if err != nil {
		return nil, nil, fmt.Errorf("audit: tls: read certificate: %w", err)
	}
	keyPEM, err = os.ReadFile(keyPath) //nolint:gosec // path is operator-supplied configuration
	if err != nil {
		return nil, nil, fmt.Errorf("audit: tls: read key: %w", err)
	}
	return certPEM, keyPEM, nil
}

// unsealKeyPEM returns a PEM-encoded unencrypted private key. If the
// input PEM is already an unencrypted block it is returned verbatim;
// if it is a PKCS#8 v2 encrypted block it is decrypted with pw and
// re-wrapped as an unencrypted `PRIVATE KEY` block. Legacy PKCS#1
// `DEK-Info` blocks and password-mismatch states are rejected.
func unsealKeyPEM(keyPEM, pw []byte) ([]byte, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("audit: tls: key file does not contain a PEM block")
	}
	// Detect legacy PKCS#1 `Proc-Type: 4,ENCRYPTED` blocks (the
	// `openssl genrsa -des3` output) and refuse with the rewrap
	// recipe. PKCS#1 encrypted keys use PKCS#5 v1.5 with an MD5-based
	// KDF and DES/3DES ciphers — Go's `x509.DecryptPEMBlock` is
	// deprecated since 1.16 for exactly this reason. We never invoke
	// that path.
	if procType := keyBlock.Headers["Proc-Type"]; procType != "" {
		return nil, ErrLegacyEncryptedPEMKey
	}
	encrypted := keyBlock.Type == "ENCRYPTED PRIVATE KEY"
	switch {
	case encrypted && len(pw) == 0:
		return nil, errors.New("audit: tls: encrypted PKCS#8 key requires a non-empty key_password")
	case !encrypted && len(pw) > 0:
		return nil, errors.New("audit: tls: key is not encrypted but key_password was supplied — remove key_password or supply an encrypted PKCS#8 key")
	case !encrypted:
		return keyPEM, nil
	}
	keyDER, err := decryptPKCS8(keyBlock.Bytes, pw)
	if err != nil {
		return nil, fmt.Errorf("audit: tls: decrypt private key: %w", err)
	}
	defer zeroBytes(keyDER)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// zeroBytes overwrites p with zeros. Best-effort defence-in-depth
// against credential material lingering in memory; Go's GC may have
// already copied the slice, so this is not a guarantee.
func zeroBytes(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

// PBES2 / PBKDF2 / scrypt OIDs per RFC 8018 (PKCS#5 v2.1) and RFC 7914.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// encryptedPrivateKeyInfo per RFC 5958 §3.
type encryptedPrivateKeyInfo struct {
	Algorithm  pkixAlgorithm
	Ciphertext []byte
}

// pkixAlgorithm mirrors crypto/x509/pkix.AlgorithmIdentifier. We
// re-declare it here to keep the file free of imports outside the
// crypto packages we already use.
type pkixAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// pbes2Params: { keyDerivationFunc AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier }.
type pbes2Params struct {
	KDF        pkixAlgorithm
	Encryption pkixAlgorithm
}

// pbkdf2Params per RFC 8018 §A.2.
type pbkdf2Params struct { //nolint:govet // ASN.1 marshalling requires this field order
	Salt           []byte
	IterationCount int
	KeyLength      int           `asn1:"optional"`
	PRF            pkixAlgorithm `asn1:"optional"`
}

// scryptParams per RFC 7914 §7.1.
type scryptParams struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelisationParameter int
	KeyLength                int `asn1:"optional"`
}

// decryptPKCS8 decodes the DER bytes of a PKCS#8
// EncryptedPrivateKeyInfo (RFC 5958), derives the key via PBKDF2 or
// scrypt, decrypts the inner ciphertext with AES-CBC, and returns the
// cleartext DER. The caller is responsible for zeroing the returned
// slice and the password bytes after use.
func decryptPKCS8(der, pw []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("parse EncryptedPrivateKeyInfo: %w", err)
	}
	if !epki.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported encryption algorithm %v (expected PBES2)", epki.Algorithm.Algorithm)
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("parse PBES2 parameters: %w", err)
	}
	plain, err := decryptAESCBC(&params, &epki, pw)
	if err != nil {
		return nil, err
	}
	// Sanity-check the result parses as PKCS#8.
	if _, err := x509.ParsePKCS8PrivateKey(plain); err != nil {
		zeroBytes(plain)
		return nil, fmt.Errorf("parse decrypted PKCS#8: %w (possibly wrong password)", err)
	}
	return plain, nil
}

// decryptAESCBC derives the symmetric key per the PBES2 parameters,
// runs AES-CBC over the ciphertext, and PKCS#7-unpads the result.
// Split out of decryptPKCS8 so the cognitive complexity gate is
// happy.
func decryptAESCBC(params *pbes2Params, epki *encryptedPrivateKeyInfo, pw []byte) ([]byte, error) {
	derivedKey, keyLen, err := deriveKey(&params.KDF, pw, &params.Encryption)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(derivedKey)

	if !isAESCBC(params.Encryption.Algorithm) {
		return nil, fmt.Errorf("unsupported encryption cipher %v (expected AES-128/192/256-CBC)", params.Encryption.Algorithm)
	}
	var iv []byte
	if _, ivErr := asn1.Unmarshal(params.Encryption.Parameters.FullBytes, &iv); ivErr != nil {
		return nil, fmt.Errorf("parse IV: %w", ivErr)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length %d (expected %d)", len(iv), aes.BlockSize)
	}
	block, err := aes.NewCipher(derivedKey[:keyLen])
	if err != nil {
		return nil, fmt.Errorf("AES cipher init: %w", err)
	}
	if len(epki.Ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of AES block size", len(epki.Ciphertext))
	}
	plain := make([]byte, len(epki.Ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, epki.Ciphertext)
	return pkcs7Unpad(plain)
}

// pkcs7Unpad strips PKCS#7 padding from p, returning the inner
// plaintext. Returns an error if the padding is invalid (which
// almost always means a wrong password).
func pkcs7Unpad(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return nil, errors.New("empty plaintext after decryption")
	}
	padLen := int(p[len(p)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(p) {
		return nil, errors.New("invalid PKCS#7 padding (possibly wrong password)")
	}
	for _, b := range p[len(p)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid PKCS#7 padding (possibly wrong password)")
		}
	}
	return p[:len(p)-padLen], nil
}

// deriveKey runs PBKDF2 or scrypt per the KDF parameters and returns
// the derived key plus the symmetric key length implied by the
// encryption algorithm.
func deriveKey(kdf *pkixAlgorithm, pw []byte, enc *pkixAlgorithm) (derivedKey []byte, keyLen int, err error) { //nolint:nonamedreturns // explicit names document the multi-return contract
	keyLen, err = aesKeyLen(enc.Algorithm)
	if err != nil {
		return nil, 0, err
	}

	switch {
	case kdf.Algorithm.Equal(oidPBKDF2):
		var p pbkdf2Params
		if _, perr := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); perr != nil {
			return nil, 0, fmt.Errorf("parse PBKDF2 parameters: %w", perr)
		}
		prf := pbkdf2PRF(p.PRF.Algorithm)
		if prf == nil {
			return nil, 0, fmt.Errorf("unsupported PBKDF2 PRF %v", p.PRF.Algorithm)
		}
		if p.IterationCount < 1000 {
			return nil, 0, fmt.Errorf("PBKDF2 iteration count %d is below 1000 (refusing for security)", p.IterationCount)
		}
		dk := pbkdf2.Key(pw, p.Salt, p.IterationCount, keyLen, prf)
		return dk, keyLen, nil

	case kdf.Algorithm.Equal(oidScrypt):
		var p scryptParams
		if _, perr := asn1.Unmarshal(kdf.Parameters.FullBytes, &p); perr != nil {
			return nil, 0, fmt.Errorf("parse scrypt parameters: %w", perr)
		}
		dk, scryptErr := scrypt.Key(pw, p.Salt, p.CostParameter, p.BlockSize, p.ParallelisationParameter, keyLen)
		if scryptErr != nil {
			return nil, 0, fmt.Errorf("scrypt: %w", scryptErr)
		}
		return dk, keyLen, nil

	default:
		return nil, 0, fmt.Errorf("unsupported KDF %v (expected PBKDF2 or scrypt)", kdf.Algorithm)
	}
}

func pbkdf2PRF(oid asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case oid.Equal(oidHMACWithSHA1):
		return sha1.New
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New
	default:
		// PBKDF2 default per RFC 8018 §A.2 is HMAC-SHA1 when no PRF
		// is specified. We accept SHA-1 here in that defaulted form;
		// modern files (openssl pkcs8 -topk8 -v2 aes256) emit an
		// explicit SHA-256 OID so this branch primarily covers
		// legacy-but-not-deprecated tooling.
		if len(oid) == 0 {
			return sha1.New
		}
		return nil
	}
}

func isAESCBC(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidAES128CBC) || oid.Equal(oidAES192CBC) || oid.Equal(oidAES256CBC)
}

func aesKeyLen(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES192CBC):
		return 24, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported AES variant %v", oid)
	}
}
