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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.ErrorIs(t, err, audit.ErrHijackNotSupported)
}

func TestResponseWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	inner := rw.Unwrap()
	assert.Equal(t, rec, inner)
}

// errorWriter is an http.ResponseWriter whose Write always fails.
type errorWriter struct {
	http.ResponseWriter
	err error
}

func (e *errorWriter) Write([]byte) (int, error) { return 0, e.err }

func TestResponseWriter_Write_InnerError(t *testing.T) {
	writeErr := errors.New("disk full")
	inner := &errorWriter{
		ResponseWriter: httptest.NewRecorder(),
		err:            writeErr,
	}
	rw := audit.NewResponseWriter(inner)

	_, err := rw.Write([]byte("data"))
	require.Error(t, err)
	assert.ErrorIs(t, err, writeErr)
}

func TestResponseWriter_Hijack_InnerError(t *testing.T) {
	hijackErr := errors.New("connection reset")
	inner := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		err:            hijackErr,
	}
	rw := audit.NewResponseWriter(inner)

	conn, brw, err := rw.Hijack()
	assert.Nil(t, conn)
	assert.Nil(t, brw)
	assert.ErrorIs(t, err, hijackErr)
}

func TestResponseWriter_WriteAfterWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := audit.NewResponseWriter(rec)

	rw.WriteHeader(http.StatusCreated)
	_, err := rw.Write([]byte("body"))
	require.NoError(t, err)

	// StatusCode should not be overwritten by Write.
	assert.Equal(t, http.StatusCreated, rw.StatusCode())
}
