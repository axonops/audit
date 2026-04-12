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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHintsFromContext_NilWithoutMiddleware(t *testing.T) {
	h := audit.HintsFromContext(context.Background())
	assert.Nil(t, h)
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name     string
		xff      string
		xri      string
		remote   string
		expected string
	}{
		{
			name:     "rightmost XFF",
			xff:      "1.2.3.4, 10.0.0.1, 192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "single XFF",
			xff:      "10.0.0.1",
			expected: "10.0.0.1",
		},
		{
			name:     "XFF with whitespace",
			xff:      " 1.2.3.4 , 10.0.0.1 , 192.168.1.1 ",
			expected: "192.168.1.1",
		},
		{
			name:     "XFF with invalid IP falls to RemoteAddr",
			xff:      "not-an-ip",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "X-Real-IP fallback",
			xri:      "10.0.0.5",
			expected: "10.0.0.5",
		},
		{
			name:     "X-Real-IP invalid falls to RemoteAddr",
			xri:      "not-an-ip",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "RemoteAddr with port",
			remote:   "192.168.1.100:54321",
			expected: "192.168.1.100",
		},
		{
			name:     "RemoteAddr IPv6",
			remote:   "[::1]:8080",
			expected: "::1",
		},
		{
			name:     "empty everything",
			expected: "",
		},
		{
			name:     "XFF takes precedence over X-Real-IP",
			xff:      "10.0.0.1",
			xri:      "10.0.0.2",
			expected: "10.0.0.1",
		},
		{
			name:     "X-Real-IP takes precedence over RemoteAddr",
			xri:      "10.0.0.2",
			remote:   "10.0.0.3:80",
			expected: "10.0.0.2",
		},
		{
			name:     "RemoteAddr without port",
			remote:   "10.0.0.1",
			expected: "10.0.0.1",
		},
		{
			name:     "XFF IPv6",
			xff:      "::1",
			expected: "::1",
		},
		{
			name:     "XFF trailing comma falls through",
			xff:      "10.0.0.1,",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "XFF bare comma falls through",
			xff:      ",",
			remote:   "10.0.0.99:80",
			expected: "10.0.0.99",
		},
		{
			name:     "RemoteAddr unix socket path returned as-is",
			remote:   "/var/run/app.sock",
			expected: "/var/run/app.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-Ip", tt.xri)
			}
			r.RemoteAddr = tt.remote

			got := audit.ClientIP(r)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestTransportSecurity(t *testing.T) {
	tests := []struct {
		name     string
		tls      *tls.ConnectionState
		expected string
	}{
		{
			name:     "nil TLS",
			tls:      nil,
			expected: "none",
		},
		{
			name:     "TLS no peer certs",
			tls:      &tls.ConnectionState{},
			expected: "tls",
		},
		{
			name: "TLS with peer certs (mTLS)",
			tls: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{}},
			},
			expected: "mtls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			r.TLS = tt.tls

			got := audit.TransportSecurity(r)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// uuidV4Pattern matches a v4 UUID: 8-4-4-4-12 hex digits with version 4
// and variant bits [89ab].
var uuidV4Pattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

func TestNewRequestID_Format(t *testing.T) {
	id := audit.NewRequestID()
	assert.Regexp(t, uuidV4Pattern, id)
}

func TestNewRequestID_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		id := audit.NewRequestID()
		require.NotContains(t, seen, id, "duplicate request ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, 100)
}

func TestValidRequestID(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"valid UUID", "550e8400-e29b-41d4-a716-446655440000", true},
		{"valid short", "req-42", true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 129), false},
		{"max length", strings.Repeat("a", 128), true},
		{"contains newline", "req-id\n", false},
		{"contains carriage return", "req-id\r", false},
		{"contains null", "req-id\x00", false},
		{"contains tab", "req-id\t", false},
		{"contains DEL", "req-id\x7f", false},
		{"non-ASCII unicode rejected", "req-\u00e9", false},
		{"RTL override rejected", "req-\u202e", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, audit.ValidRequestID(tt.id))
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
		maxLen int
	}{
		{"under limit", "hello", "hello", 10},
		{"at limit", "hello", "hello", 5},
		{"over limit", "hello world", "hello", 5},
		{"empty", "", "", 10},
		{"multibyte not split", "caf\u00e9!", "caf\u00e9", 5},
		{"multibyte split backed up", "caf\u00e9!", "caf", 4},
		{"exact boundary 512", strings.Repeat("a", 512), strings.Repeat("a", 512), 512},
		{"one over boundary 513", strings.Repeat("a", 513), strings.Repeat("a", 512), 512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.TruncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// --- Benchmarks ---

func BenchmarkNewRequestID(b *testing.B) {
	for b.Loop() {
		audit.NewRequestID()
	}
}

func BenchmarkClientIP(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1, 192.168.1.1")
	for b.Loop() {
		audit.ClientIP(r)
	}
}

func BenchmarkValidRequestID(b *testing.B) {
	for b.Loop() {
		audit.ValidRequestID("550e8400-e29b-41d4-a716-446655440000")
	}
}
