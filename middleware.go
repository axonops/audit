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
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	// maxRequestIDLen is the maximum length of an X-Request-Id header
	// value accepted by the middleware. Values exceeding this length
	// or containing control characters are replaced with a generated UUID.
	maxRequestIDLen = 128

	// maxUserAgentLen is the maximum length of the User-Agent header
	// stored in [TransportMetadata]. Longer values are truncated to
	// prevent oversized audit events in size-limited outputs (syslog, CEF).
	maxUserAgentLen = 512

	// maxPathLen is the maximum length of the URL path stored in
	// [TransportMetadata]. Longer paths are truncated to prevent
	// oversized audit events in size-limited outputs (syslog, CEF).
	maxPathLen = 2048
)

// hintsKey is the unexported context key for [Hints].
type hintsKey struct{}

// Hints carries mutable, per-request audit metadata through the
// request context. Handlers retrieve it with [HintsFromContext] and populate
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
//   - eventType: the taxonomy event type name to pass to [Logger.AuditEvent]
//   - fields: the audit event fields
//   - skip: if true, no audit event is emitted for this request
type EventBuilder func(hints *Hints, transport *TransportMetadata) (eventType string, fields Fields, skip bool)

// HintsFromContext retrieves the [Hints] from the request context. Returns
// nil if the request was not wrapped by [Middleware].
func HintsFromContext(ctx context.Context) *Hints {
	h, _ := ctx.Value(hintsKey{}).(*Hints)
	return h
}

// Middleware returns HTTP middleware that captures transport metadata
// automatically and calls the [EventBuilder] after the handler
// returns. The builder transforms [Hints] (populated by the handler)
// and [TransportMetadata] into an audit event.
//
// If logger is nil, the returned middleware is an identity function
// that passes requests through without auditing. This allows
// consumers to conditionally disable audit middleware without
// nil-checking at every call site.
//
// Middleware panics if builder is nil (programming error).
func Middleware(logger *Logger, builder EventBuilder) func(http.Handler) http.Handler {
	if logger == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	if builder == nil {
		panic("audit: EventBuilder must not be nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveAudit(w, r, next, logger, builder)
		})
	}
}

// serveAudit is the per-request handler logic extracted from
// [Middleware] to keep cognitive complexity within bounds.
func serveAudit(w http.ResponseWriter, r *http.Request, next http.Handler, logger *Logger, builder EventBuilder) {
	hints := &Hints{}
	ctx := context.WithValue(r.Context(), hintsKey{}, hints)
	r = r.WithContext(ctx)

	reqID := r.Header.Get("X-Request-Id")
	if !validRequestID(reqID) {
		reqID = newRequestID()
	}

	rw := &responseWriter{ResponseWriter: w}
	start := time.Now()

	panicked, panicVal := invokeHandler(next, rw, r)

	statusCode := rw.statusCode
	if !rw.written {
		statusCode = http.StatusOK
	}

	transport := &TransportMetadata{
		ClientIP:          clientIP(r),
		TransportSecurity: transportSecurity(r),
		Method:            r.Method,
		Path:              truncateString(r.URL.Path, maxPathLen),
		UserAgent:         truncateString(r.UserAgent(), maxUserAgentLen),
		RequestID:         reqID,
		StatusCode:        statusCode,
		Duration:          time.Since(start),
	}

	emitAuditEvent(logger, builder, hints, transport)

	if panicked {
		panic(panicVal)
	}
}

// invokeHandler calls next.ServeHTTP with panic recovery. If the
// handler panics, the status code is set to 500 and the panic value
// is captured for re-raising after the audit event is emitted.
func invokeHandler(next http.Handler, rw *responseWriter, r *http.Request) (panicked bool, panicVal any) {
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			panicVal = v
			if !rw.written {
				rw.statusCode = http.StatusInternalServerError
				rw.written = true
			}
		}
	}()
	next.ServeHTTP(rw, r)
	return false, nil
}

// emitAuditEvent calls the EventBuilder and, if not skipped, emits
// the audit event. Builder panics are recovered and logged.
func emitAuditEvent(logger *Logger, builder EventBuilder, hints *Hints, transport *TransportMetadata) {
	var (
		eventType string
		fields    Fields
		skip      bool
	)

	func() {
		defer func() {
			if v := recover(); v != nil {
				panicStr := truncateString(fmt.Sprintf("%v", v), 512)
				slog.Error("audit: EventBuilder panicked",
					"panic", panicStr,
					"request_id", transport.RequestID)
				skip = true
			}
		}()
		eventType, fields, skip = builder(hints, transport)
	}()

	if skip {
		return
	}

	if err := logger.AuditEvent(NewEvent(eventType, fields)); err != nil {
		slog.Warn("audit: middleware event failed",
			"event_type", eventType,
			"request_id", transport.RequestID,
			"error", err)
	}
}
