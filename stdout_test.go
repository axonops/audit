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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdoutOutput_Write(t *testing.T) {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	require.NoError(t, out.Write(data))

	assert.Equal(t, string(data), buf.String())
}

func TestStdoutOutput_WriteMultiple(t *testing.T) {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	events := []string{
		`{"event_type":"e1"}` + "\n",
		`{"event_type":"e2"}` + "\n",
		`{"event_type":"e3"}` + "\n",
	}
	for _, e := range events {
		require.NoError(t, out.Write([]byte(e)))
	}

	for _, e := range events {
		assert.Contains(t, buf.String(), e)
	}
}

func TestStdoutOutput_Close(t *testing.T) {
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
}

func TestStdoutOutput_CloseIdempotent(t *testing.T) {
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestStdoutOutput_WriteAfterClose(t *testing.T) {
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data\n"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestStdoutOutput_Name(t *testing.T) {
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.Equal(t, "stdout", out.Name())
}

func TestStdoutOutput_DefaultWriter(t *testing.T) {
	// When Writer is nil, NewStdoutOutput should default to os.Stdout.
	// We verify construction succeeds; we cannot easily assert the
	// internal writer is os.Stdout without exporting it, but we can
	// verify Name() works and the output implements the interface.
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	require.NoError(t, err)
	assert.Equal(t, "stdout", out.Name())

	// Verify it satisfies the Output interface.
	var _ audit.Output = out
}

func TestStdoutOutput_ConcurrentWrites(t *testing.T) {
	// StdoutOutput serialises writes internally, so a plain
	// bytes.Buffer is safe here — no external synchronisation needed.
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			data := fmt.Sprintf(`{"n":%d}`+"\n", n)
			_ = out.Write([]byte(data))
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, goroutines)
}

func TestStdoutOutput_WriteError(t *testing.T) {
	errFail := errors.New("write failed")
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &failWriter{err: errFail}})
	require.NoError(t, err)

	err = out.Write([]byte("data\n"))
	assert.ErrorIs(t, err, errFail)
}

func TestStdoutOutput_ImplementsOutput(t *testing.T) {
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &bytes.Buffer{}})
	require.NoError(t, err)

	var _ audit.Output = out
}

// failWriter is a test helper that always returns an error on Write.
type failWriter struct {
	err error
}

func (fw *failWriter) Write(_ []byte) (int, error) {
	return 0, fw.err
}

func TestStdoutOutput_WriteLargePayload(t *testing.T) {
	var buf bytes.Buffer
	out, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: &buf})
	require.NoError(t, err)

	// Write a large payload (~1MB).
	payload := strings.Repeat("x", 1<<20) + "\n"
	require.NoError(t, out.Write([]byte(payload)))
	assert.Equal(t, len(payload), buf.Len())
}
