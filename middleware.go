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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// hintsKey is the unexported context key for [Hints].
type hintsKey struct{}

// Hints carries mutable, per-request audit metadata through the
// request context. Handlers retrieve it with [GetHints] and populate
// domain-specific fields (actor, target, outcome). The middleware
// reads these fields after the handler returns and passes them to the
// [EventBuilder] callback.
//
// Each request receives its own *Hints allocation; there is no shared
// mutable state between concurrent requests.
type Hints struct {
	// Extra holds arbitrary domain-specific fields. It is initialised
	// lazily by the handler. Keys and values are passed through to
	// the [EventBuilder] callback.
	Extra map[string]any

	// EventType is the audit event type name (e.g. "user_create").
	// If empty, the [EventBuilder] decides the event type.
	EventType string

	// Outcome is the high-level result: "success", "failure", "denied", etc.
	Outcome string

	// ActorID identifies the authenticated principal (user ID, service account, etc.).
	ActorID string

	// ActorType categorises the actor: "user", "service", "api_key", etc.
	ActorType string

	// AuthMethod describes how the actor authenticated: "bearer", "mtls", "session", etc.
	AuthMethod string

	// Role is the actor's role or permission level at the time of the request.
	Role string

	// TargetType categorises the resource being acted upon: "document", "user", etc.
	TargetType string

	// TargetID identifies the specific resource being acted upon.
	TargetID string

	// Reason is a human-readable justification for the action, if applicable.
	Reason string

	// Error holds an error message when the request fails.
	Error string
}

// TransportMetadata contains HTTP transport-level fields captured
// automatically by the middleware. These are read-only values passed
// to the [EventBuilder] callback; handlers do not need to set them.
type TransportMetadata struct {
	// ClientIP is the client's IP address, extracted from the
	// rightmost X-Forwarded-For entry, X-Real-IP, or RemoteAddr.
	ClientIP string

	// TransportSecurity describes the TLS state: "none", "tls", or "mtls".
	TransportSecurity string

	// Method is the HTTP method (GET, POST, etc.).
	Method string

	// Path is the request URL path.
	Path string

	// UserAgent is the request's User-Agent header value.
	UserAgent string

	// RequestID is the request identifier, taken from the X-Request-Id
	// header or generated as a v4 UUID.
	RequestID string

	// Duration is the wall-clock time the handler took to execute.
	Duration time.Duration

	// StatusCode is the HTTP status code written by the handler.
	StatusCode int
}

// EventBuilder is a callback that transforms per-request [Hints] and
// [TransportMetadata] into an audit event. The middleware calls it
// after the handler returns (or panics).
//
// Return values:
//   - eventType: the taxonomy event type name to pass to [Logger.Audit]
//   - fields: the audit event fields
//   - skip: if true, no audit event is emitted for this request
type EventBuilder func(hints *Hints, transport TransportMetadata) (eventType string, fields Fields, skip bool)

// GetHints retrieves the [Hints] from the request context. Returns
// nil if the request was not wrapped by [AuditMiddleware].
func GetHints(ctx context.Context) *Hints {
	h, _ := ctx.Value(hintsKey{}).(*Hints)
	return h
}

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
		if ip != "" {
			return ip
		}
	}

	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
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

// newRequestID generates a v4 UUID using crypto/rand. The format
// follows RFC 4122: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx.
func newRequestID() string {
	var uuid [16]byte
	// crypto/rand.Read always returns len(p) bytes on supported
	// platforms; the only realistic failure is a broken OS RNG.
	if _, err := rand.Read(uuid[:]); err != nil {
		// Fallback: return a zero UUID rather than panicking in a
		// library. This should never happen on any supported OS.
		return "00000000-0000-4000-8000-000000000000"
	}
	// Set version (4) and variant (RFC 4122).
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
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
// has not been called, an implicit 200 OK is recorded.
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

// errHijackNotSupported is returned by Hijack when the inner writer
// does not implement [http.Hijacker].
var errHijackNotSupported = errors.New("audit: underlying ResponseWriter does not support hijacking")

// Hijack delegates to the inner writer if it implements
// [http.Hijacker]. Returns an error if hijacking is not supported.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errHijackNotSupported
}
