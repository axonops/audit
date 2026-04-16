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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

// MinSaltLength is the minimum salt length in bytes for HMAC
// computation, per NIST SP 800-224 (minimum key length: 128 bits).
const MinSaltLength = 16

// HMACConfig holds per-output HMAC configuration. When Enabled is
// true, every event delivered to the output has an HMAC appended.
// The HMAC is computed over the final serialised payload (after
// field stripping and event_category append).
type HMACConfig struct { //nolint:govet // readability over alignment
	// Enabled controls whether HMAC is computed for this output.
	// Default: false. Must be explicitly true.
	Enabled bool

	// SaltVersion is a user-defined identifier for the salt, included
	// in the output alongside the HMAC. Supports salt rotation —
	// consumers use this to look up the correct salt for verification.
	SaltVersion string

	// SaltValue is the raw salt bytes. MUST be at least MinSaltLength
	// (16 bytes / 128 bits). Never appears in logs or error messages.
	SaltValue []byte

	// Algorithm is the HMAC hash algorithm. Must be one of the
	// NIST-approved values: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512,
	// HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512.
	Algorithm string
}

// String returns a safe representation that never includes the salt value.
func (c HMACConfig) String() string {
	if !c.Enabled {
		return "HMACConfig{Enabled: false}"
	}
	return fmt.Sprintf("HMACConfig{Enabled: true, SaltVersion: %q, Algorithm: %q, SaltLen: %d}",
		c.SaltVersion, c.Algorithm, len(c.SaltValue))
}

// GoString implements [fmt.GoStringer] to prevent salt leakage via %#v.
func (c HMACConfig) GoString() string {
	return c.String()
}

// hmacHashFunc returns the hash constructor for the given algorithm name.
// Only NIST SP 800-224 approved algorithms are included.
// SHA-1 and MD5 are explicitly excluded. Returns nil for unknown names.
func hmacHashFunc(name string) func() hash.Hash {
	switch name {
	case "HMAC-SHA-256":
		return sha256.New
	case "HMAC-SHA-384":
		return sha512.New384
	case "HMAC-SHA-512":
		return sha512.New
	case "HMAC-SHA3-256":
		return func() hash.Hash { return sha3.New256() }
	case "HMAC-SHA3-384":
		return func() hash.Hash { return sha3.New384() }
	case "HMAC-SHA3-512":
		return func() hash.Hash { return sha3.New512() }
	default:
		return nil
	}
}

// SupportedHMACAlgorithms returns the list of supported HMAC algorithm
// names for use in documentation and error messages.
func SupportedHMACAlgorithms() []string {
	return []string{
		"HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512",
		"HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512",
	}
}

// ValidateHMACConfig checks that an HMACConfig is valid. Returns an
// error wrapping [ErrConfigInvalid] if the config is enabled but has
// missing or invalid fields. Salt values are never included in error
// messages.
func ValidateHMACConfig(cfg *HMACConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if cfg.SaltVersion == "" {
		return fmt.Errorf("%w: hmac salt version is required when hmac is enabled", ErrConfigInvalid)
	}
	if len(cfg.SaltValue) == 0 {
		return fmt.Errorf("%w: hmac salt value is required when hmac is enabled", ErrConfigInvalid)
	}
	if len(cfg.SaltValue) < MinSaltLength {
		return fmt.Errorf("%w: hmac salt must be at least %d bytes", ErrConfigInvalid, MinSaltLength)
	}
	if cfg.Algorithm == "" {
		return fmt.Errorf("%w: hmac hash algorithm is required when hmac is enabled", ErrConfigInvalid)
	}
	if hmacHashFunc(cfg.Algorithm) == nil {
		return fmt.Errorf("%w: unknown hmac algorithm %q (supported: %v)", ErrConfigInvalid, cfg.Algorithm, SupportedHMACAlgorithms())
	}
	return nil
}

// newHMACState creates a pre-constructed hmacState for drain-loop reuse.
// Called once at auditor construction per HMAC-enabled output.
func newHMACState(cfg *HMACConfig) *hmacState {
	hashFunc := hmacHashFunc(cfg.Algorithm)
	if hashFunc == nil {
		return nil // unreachable: ValidateHMACConfig rejects unknown algorithms during New
	}
	mac := hmac.New(hashFunc, cfg.SaltValue)
	return &hmacState{
		mac:     mac,
		hashLen: mac.Size(),
	}
}

// computeHMACFast computes the HMAC using pre-allocated state, returning
// the hex-encoded result as a byte slice from the state's buffer.
// The returned slice is valid only until the next call. Single-goroutine
// use only (drain loop).
func (s *hmacState) computeHMACFast(payload []byte) []byte {
	s.mac.Reset()
	s.mac.Write(payload)
	sum := s.mac.Sum(s.sumBuf[:0])
	hex.Encode(s.hexBuf[:], sum)
	return s.hexBuf[:s.hashLen*2]
}

// ComputeHMAC computes the HMAC for the given payload and returns the
// lowercase hex-encoded result. The algorithm must be one of the
// supported NIST-approved values (see [SupportedHMACAlgorithms]).
func ComputeHMAC(payload, salt []byte, algorithm string) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("audit: hmac payload must not be empty")
	}
	if len(salt) == 0 {
		return "", errors.New("audit: hmac salt must not be empty")
	}
	hashFunc := hmacHashFunc(algorithm)
	if hashFunc == nil {
		return "", fmt.Errorf("audit: unknown hmac algorithm %q", algorithm)
	}
	mac := hmac.New(hashFunc, salt)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC verifies that the HMAC value matches the payload.
// The hmacValue is expected to be lowercase hex-encoded (as produced
// by [ComputeHMAC]). Returns (true, nil) if valid, (false, nil) if
// invalid, or (false, err) for parameter errors.
func VerifyHMAC(payload []byte, hmacValue string, salt []byte, algorithm string) (bool, error) {
	computed, err := ComputeHMAC(payload, salt, algorithm)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(computed), []byte(hmacValue)), nil
}
