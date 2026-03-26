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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetHints_NilWithoutMiddleware(t *testing.T) {
	h := audit.GetHints(context.Background())
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
			xff:      "spoofed, 10.0.0.1, 192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "single XFF",
			xff:      "10.0.0.1",
			expected: "10.0.0.1",
		},
		{
			name:     "XFF with whitespace",
			xff:      " spoofed , 10.0.0.1 , 192.168.1.1 ",
			expected: "192.168.1.1",
		},
		{
			name:     "X-Real-IP fallback",
			xri:      "10.0.0.5",
			expected: "10.0.0.5",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/test", nil)
			require.NoError(t, err)
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
			r, err := http.NewRequest(http.MethodGet, "/test", nil)
			require.NoError(t, err)
			r.TLS = tt.tls

			got := audit.TransportSecurityFunc(r)
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

// --- responseWriter tests ---

func TestResponseWriter_DefaultStatus200(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	_, err := rw.Write([]byte("hello"))
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, rw.StatusCode())
	assert.True(t, rw.Written())
}

func TestResponseWriter_CapturesStatus(t *testing.T) {
	codes := []int{200, 201, 301, 404, 500}
	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			rec := httptest.NewRecorder()
			rw := audit.NewResponseWriter(rec)

			rw.WriteHeader(code)
			assert.Equal(t, code, rw.StatusCode())
			assert.Equal(t, code, rec.Code)
		})
	}
}

func TestResponseWriter_WriteHeaderIdempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	rw.WriteHeader(http.StatusCreated)
	rw.WriteHeader(http.StatusInternalServerError) // should be ignored

	assert.Equal(t, http.StatusCreated, rw.StatusCode())
	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestResponseWriter_BodyPassThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	data := []byte("audit event data")
	n, err := rw.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, "audit event data", rec.Body.String())
}

// mockFlusher is a ResponseWriter that also implements http.Flusher.
type mockFlusher struct {
	http.ResponseWriter
	flushed bool
}

func (m *mockFlusher) Flush() { m.flushed = true }

func TestResponseWriter_Flush_Supported(t *testing.T) {
	inner := &mockFlusher{ResponseWriter: httptest.NewRecorder()}
	rw := audit.NewResponseWriter(inner)

	rw.Flush()
	assert.True(t, inner.flushed)
}

func TestResponseWriter_Flush_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	// httptest.ResponseRecorder implements Flusher, so wrap it to
	// hide the Flusher interface.
	rw := audit.NewResponseWriter(struct{ http.ResponseWriter }{rec})

	// Should not panic.
	assert.NotPanics(t, func() { rw.Flush() })
}

// mockHijacker is a ResponseWriter that also implements http.Hijacker.
type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	err  error
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return m.conn, nil, m.err
}

func TestResponseWriter_Hijack_Supported(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	inner := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           server,
	}
	rw := audit.NewResponseWriter(inner)

	conn, _, err := rw.Hijack()
	require.NoError(t, err)
	assert.Equal(t, server, conn)
}

func TestResponseWriter_Hijack_NotSupported(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(struct{ http.ResponseWriter }{rec})

	conn, brw, err := rw.Hijack()
	assert.Nil(t, conn)
	assert.Nil(t, brw)
	require.Error(t, err)
	assert.True(t, errors.Is(err, err)) // just ensure it's an error
	assert.Contains(t, err.Error(), "hijacking")
}

func TestResponseWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	inner := rw.Unwrap()
	assert.Equal(t, rec, inner)
}
