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
	"log/slog"
	"net"
	"net/http"
)

// ClientIP exports clientIP for testing.
func ClientIP(r *http.Request) string { return clientIP(r) }

// TransportSecurity exports transportSecurity for testing.
func TransportSecurity(r *http.Request) string { return transportSecurity(r) }

// NewRequestID exports newRequestID for testing.
func NewRequestID() string { return newRequestID(nil) }

// NewRequestIDWithLogger exports newRequestID with a specific logger
// for tests that need to capture the crypto/rand-failure warning path.
func NewRequestIDWithLogger(logger *slog.Logger) string { return newRequestID(logger) }

// SetRandRead swaps the package-level randRead seam used by
// newRequestID. Returns a restore function that reinstates the
// original. For test use only — callers are responsible for
// ensuring serial execution as randRead is process-global.
func SetRandRead(r func([]byte) (int, error)) (restore func()) {
	original := randRead
	randRead = r
	return func() { randRead = original }
}

// ValidRequestID exports validRequestID for testing.
func ValidRequestID(id string) bool { return validRequestID(id) }

// TruncateString exports truncateString for testing.
func TruncateString(s string, maxLen int) string { return truncateString(s, maxLen) }

// NewResponseWriter exports the responseWriter constructor for testing.
func NewResponseWriter(w http.ResponseWriter) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{rw: &responseWriter{ResponseWriter: w}}
}

// ResponseWriterWrapper exposes the unexported responseWriter for testing.
type ResponseWriterWrapper struct {
	rw *responseWriter
}

// WriteHeader delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) WriteHeader(code int) { w.rw.WriteHeader(code) }

// Write delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) Write(b []byte) (int, error) { return w.rw.Write(b) }

// Unwrap delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) Unwrap() http.ResponseWriter { return w.rw.Unwrap() }

// Flush delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) Flush() { w.rw.Flush() }

// Hijack delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.rw.Hijack()
}

// StatusCode returns the captured status code.
func (w *ResponseWriterWrapper) StatusCode() int { return w.rw.statusCode }

// Written returns whether WriteHeader or Write has been called.
func (w *ResponseWriterWrapper) Written() bool { return w.rw.written }

// Header delegates to the wrapped responseWriter.
func (w *ResponseWriterWrapper) Header() http.Header { return w.rw.Header() }
