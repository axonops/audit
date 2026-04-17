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
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"
)

// clientIP extracts the client IP address from the request. It checks
// (in order): rightmost X-Forwarded-For entry, X-Real-IP header, then
// [http.Request.RemoteAddr]. The rightmost XFF entry is used because
// it is set by the last trusted proxy; leftmost entries are
// user-spoofable.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Rightmost entry is set by the last trusted proxy.
		ip := strings.TrimSpace(parts[len(parts)-1])
		if ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
	}

	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	if r.RemoteAddr == "" {
		return ""
	}

	// Strip port from RemoteAddr. net.SplitHostPort handles both
	// IPv4 ("1.2.3.4:8080") and IPv6 ("[::1]:8080").
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// No port — return as-is (e.g. bare IPv6 or Unix socket).
		return r.RemoteAddr
	}
	return host
}

// transportSecurity determines the TLS state of the request:
//   - "mtls" if TLS with at least one peer (client) certificate
//   - "tls" if TLS without client certificates
//   - "none" if no TLS
func transportSecurity(r *http.Request) string {
	if r.TLS == nil {
		return "none"
	}
	if len(r.TLS.PeerCertificates) > 0 {
		return "mtls"
	}
	return "tls"
}

// randRead is the crypto/rand.Read indirection used by newRequestID.
// Tests override this to exercise the failure path; production code
// never swaps it. Defined here (not in a *_test.go helper) because
// export_test files cannot introduce new package-level variables.
var randRead = rand.Read

// newRequestID generates a v4 UUID using crypto/rand. The format
// follows RFC 4122: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx. The
// logger argument receives the crypto/rand-failure fallback warning;
// pass the auditor's diagnostic logger so the warning routes to the
// consumer's configured handler.
func newRequestID(logger *slog.Logger) string {
	var uuid [16]byte
	// crypto/rand.Read always returns len(p) bytes on supported
	// platforms; the only realistic failure is a broken OS RNG.
	if _, err := randRead(uuid[:]); err != nil {
		// Fallback: return a zero UUID rather than panicking in a
		// library. This should never happen on any supported OS.
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("audit: crypto/rand failed, using zero UUID", "error", err)
		return "00000000-0000-4000-8000-000000000000"
	}
	// Set version (4) and variant (RFC 4122).
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	// Encode directly into a fixed-size buffer to avoid fmt.Sprintf
	// allocations on the hot path.
	var buf [36]byte
	hex.Encode(buf[0:8], uuid[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], uuid[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], uuid[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], uuid[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], uuid[10:16])
	return string(buf[:])
}

// validRequestID checks that a request ID is safe to propagate:
// printable ASCII only (0x20–0x7e), bounded length, no control
// characters or non-ASCII that could enable log injection or visual
// spoofing.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, c := range id {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// truncateString returns s truncated to at most maxLen bytes,
// backing up to the last complete UTF-8 rune boundary to avoid
// producing invalid UTF-8 in serialised output.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	// Truncate to maxLen, then back up to the last valid rune start.
	s = s[:maxLen]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// responseWriter wraps [http.ResponseWriter] to capture the status
// code written by the handler. It delegates all calls to the inner
// writer and supports [http.Flusher], [http.Hijacker], and the
// Unwrap pattern used by [http.ResponseController].
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code on the first call and
// delegates to the inner [http.ResponseWriter]. Subsequent calls are
// ignored per the [http.ResponseWriter] contract.
func (rw *responseWriter) WriteHeader(code int) {
	if rw.written {
		return
	}
	rw.statusCode = code
	rw.written = true
	rw.ResponseWriter.WriteHeader(code)
}

// Write delegates to the inner [http.ResponseWriter]. If WriteHeader
// has not been called, an implicit 200 OK is recorded. Errors are
// returned unmodified to preserve the [http.ResponseWriter] contract
// and allow callers to discriminate error types.
//
//nolint:wrapcheck // transparent proxy — must not alter inner writer errors
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// Unwrap returns the inner [http.ResponseWriter], enabling
// [http.ResponseController] to access underlying interfaces.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Flush delegates to the inner writer if it implements [http.Flusher].
// If the inner writer does not support flushing, the call is a no-op.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ErrHijackNotSupported is returned by the middleware's response
// writer Hijack method when the underlying [http.ResponseWriter] does
// not implement [http.Hijacker].
var ErrHijackNotSupported = errors.New("audit: underlying ResponseWriter does not support hijacking")

// Hijack delegates to the inner writer if it implements
// [http.Hijacker]. Returns [ErrHijackNotSupported] if hijacking is
// not supported. Inner hijack errors are returned unmodified.
//
//nolint:wrapcheck // transparent proxy — must not alter inner hijacker errors
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, ErrHijackNotSupported
}
