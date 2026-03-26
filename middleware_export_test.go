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
	"net"
	"net/http"
)

// ClientIP exports clientIP for testing.
var ClientIP = clientIP

// TransportSecurityFunc exports transportSecurity for testing.
var TransportSecurityFunc = transportSecurity

// NewRequestID exports newRequestID for testing.
var NewRequestID = newRequestID

// ValidRequestID exports validRequestID for testing.
var ValidRequestID = validRequestID

// NewResponseWriter exports the responseWriter constructor for testing.
func NewResponseWriter(w http.ResponseWriter) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{W: &responseWriter{ResponseWriter: w}}
}

// ResponseWriterWrapper exposes the unexported responseWriter fields for testing.
type ResponseWriterWrapper struct {
	W *responseWriter
}

// WriteHeader delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) WriteHeader(code int) { rw.W.WriteHeader(code) }

// Write delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) Write(b []byte) (int, error) { return rw.W.Write(b) }

// Unwrap delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) Unwrap() http.ResponseWriter { return rw.W.Unwrap() }

// Flush delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) Flush() { rw.W.Flush() }

// Hijack delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return rw.W.Hijack()
}

// StatusCode returns the captured status code.
func (rw *ResponseWriterWrapper) StatusCode() int { return rw.W.statusCode }

// Written returns whether WriteHeader or Write has been called.
func (rw *ResponseWriterWrapper) Written() bool { return rw.W.written }

// Header delegates to the wrapped responseWriter.
func (rw *ResponseWriterWrapper) Header() http.Header { return rw.W.Header() }
