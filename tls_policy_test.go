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
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TLSPolicy.Apply
// ---------------------------------------------------------------------------

func TestTLSPolicy_Apply_NilReceiver_DefaultsTLS13(t *testing.T) {
	var p *audit.TLSPolicy
	cfg, warnings := p.Apply(nil)
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Nil(t, cfg.CipherSuites)
	assert.Empty(t, warnings)
}

func TestTLSPolicy_Apply_ZeroValue_DefaultsTLS13(t *testing.T) {
	p := &audit.TLSPolicy{}
	cfg, warnings := p.Apply(nil)
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Nil(t, cfg.CipherSuites)
	assert.Empty(t, warnings)
}

func TestTLSPolicy_Apply_NilConfig_ReturnsFreshConfig(t *testing.T) {
	p := &audit.TLSPolicy{}
	cfg, _ := p.Apply(nil)
	require.NotNil(t, cfg, "Apply(nil) must return a non-nil *tls.Config")
}

func TestTLSPolicy_Apply_AllowTLS12_SetsMinVersion(t *testing.T) {
	p := &audit.TLSPolicy{AllowTLS12: true}
	cfg, warnings := p.Apply(nil)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Empty(t, warnings)
}

func TestTLSPolicy_Apply_AllowTLS12_FiltersCiphers(t *testing.T) {
	p := &audit.TLSPolicy{AllowTLS12: true}
	cfg, _ := p.Apply(nil)
	require.NotNil(t, cfg.CipherSuites, "CipherSuites must be set when filtering")
	assert.NotEmpty(t, cfg.CipherSuites, "filtered list must not be empty")

	// Every ID should come from the secure list.
	secure := make(map[uint16]bool)
	for _, cs := range tls.CipherSuites() {
		secure[cs.ID] = true
	}
	for _, id := range cfg.CipherSuites {
		assert.True(t, secure[id], "cipher 0x%04x must be in tls.CipherSuites()", id)
	}
}

func TestTLSPolicy_Apply_AllowTLS12_NoCipherFromInsecureList(t *testing.T) {
	p := &audit.TLSPolicy{AllowTLS12: true}
	cfg, _ := p.Apply(nil)

	insecure := make(map[uint16]bool)
	for _, cs := range tls.InsecureCipherSuites() {
		insecure[cs.ID] = true
	}
	for _, id := range cfg.CipherSuites {
		assert.False(t, insecure[id],
			"cipher 0x%04x is in tls.InsecureCipherSuites() and must not be allowed", id)
	}
}

func TestTLSPolicy_Apply_AllowWeakCiphers_NoCipherFiltering(t *testing.T) {
	p := &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true}
	cfg, _ := p.Apply(nil)
	assert.Nil(t, cfg.CipherSuites,
		"CipherSuites should be nil (Go defaults) when AllowWeakCiphers is true")
}

func TestTLSPolicy_Apply_AllowWeakCiphers_ReturnsWarning(t *testing.T) {
	p := &audit.TLSPolicy{AllowTLS12: true, AllowWeakCiphers: true}
	_, warnings := p.Apply(nil)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "weak ciphers")
}

func TestTLSPolicy_Apply_NoWarningsOnDefault(t *testing.T) {
	for _, p := range []*audit.TLSPolicy{nil, {}, {AllowTLS12: true}} {
		_, warnings := p.Apply(nil)
		assert.Empty(t, warnings)
	}
}

func TestTLSPolicy_Apply_PreservesExistingFields(t *testing.T) {
	pool := x509.NewCertPool()
	existing := &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com",
	}

	p := &audit.TLSPolicy{AllowTLS12: true}
	cfg, _ := p.Apply(existing)

	assert.Same(t, pool, cfg.RootCAs, "RootCAs must not be replaced")
	assert.Equal(t, "example.com", cfg.ServerName, "ServerName must not be replaced")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestTLSPolicy_Apply_TLS13_AllowWeakCiphersNoEffect(t *testing.T) {
	// AllowWeakCiphers without AllowTLS12 should have no effect and no warning.
	p := &audit.TLSPolicy{AllowWeakCiphers: true}
	cfg, warnings := p.Apply(nil)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Nil(t, cfg.CipherSuites)
	assert.Empty(t, warnings, "no warning expected when AllowTLS12 is false")
}
