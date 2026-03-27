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

import "crypto/tls"

// TLSPolicy controls TLS version and cipher suite policy for output
// connections. The zero value enforces TLS 1.3 only with Go's default
// (secure) cipher suites.
type TLSPolicy struct {
	// AllowTLS12 permits TLS 1.2 connections in addition to TLS 1.3.
	// When false (the default), MinVersion is set to TLS 1.3.
	AllowTLS12 bool

	// AllowWeakCiphers disables cipher suite filtering when AllowTLS12
	// is true. By default, only cipher suites from [tls.CipherSuites]
	// (the non-insecure list) are permitted. Setting this to true allows
	// Go's full default suite selection, which may include weaker ciphers.
	// Has no effect when AllowTLS12 is false, because TLS 1.3 cipher
	// suites are not configurable in Go.
	AllowWeakCiphers bool
}

// Apply sets TLS version and cipher suite policy on cfg. If cfg is nil,
// a fresh [tls.Config] is created. Apply does not modify RootCAs,
// Certificates, ServerName, or any other pre-existing field. A nil
// receiver is treated as the zero value (TLS 1.3 only).
//
// The returned warnings slice contains human-readable messages for
// security-sensitive configurations (e.g. weak ciphers enabled).
func (p *TLSPolicy) Apply(cfg *tls.Config) (*tls.Config, []string) {
	if cfg == nil {
		cfg = &tls.Config{}
	}

	// Nil receiver = zero value = TLS 1.3 only.
	if p == nil || !p.AllowTLS12 {
		cfg.MinVersion = tls.VersionTLS13
		cfg.CipherSuites = nil
		return cfg, nil
	}

	// TLS 1.2 permitted.
	cfg.MinVersion = tls.VersionTLS12

	if p.AllowWeakCiphers {
		// Let Go choose — may include weaker ciphers.
		cfg.CipherSuites = nil
		return cfg, []string{"audit: weak ciphers permitted; consider restricting to TLS 1.3 only"}
	}

	// Filter to secure-only ciphers from tls.CipherSuites().
	secure := tls.CipherSuites()
	ids := make([]uint16, len(secure))
	for i, cs := range secure {
		ids[i] = cs.ID
	}
	cfg.CipherSuites = ids

	return cfg, nil
}
