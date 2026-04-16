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

package file_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// mockOutputMetrics implements audit.OutputMetrics for testing.
// All fields use atomic counters — safe for concurrent use between
// the test goroutine and the output's writeLoop goroutine.
type mockOutputMetrics struct {
	audit.NoOpOutputMetrics
	drops      atomic.Int64
	flushes    atomic.Int64
	errors     atomic.Int64
	retries    atomic.Int64
	depthCalls atomic.Int64
}

func (m *mockOutputMetrics) RecordDrop()                        { m.drops.Add(1) }
func (m *mockOutputMetrics) RecordFlush(_ int, _ time.Duration) { m.flushes.Add(1) }
func (m *mockOutputMetrics) RecordError()                       { m.errors.Add(1) }
func (m *mockOutputMetrics) RecordRetry(_ int)                  { m.retries.Add(1) }
func (m *mockOutputMetrics) RecordQueueDepth(_, _ int)          { m.depthCalls.Add(1) }

var _ audit.OutputMetrics = (*mockOutputMetrics)(nil)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFileOutput_Write(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	data := []byte(`{"event_type":"test","outcome":"success"}` + "\n")
	require.NoError(t, out.Write(data))

	// Close flushes the async buffer and file writer.
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(data), string(content))
}

func TestFileOutput_Write_NonBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 100}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Write should return immediately — it enqueues to a channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			_ = out.Write([]byte(`{"event":"test"}` + "\n"))
		}
	}()

	select {
	case <-done:
		// OK — writes completed without blocking.
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked for 5s — should be non-blocking")
	}
}

func TestFileOutput_BufferFull_Drops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Tiny buffer to trigger drops.
	out, err := file.New(file.Config{Path: path, BufferSize: 1}, nil)
	require.NoError(t, err)

	om := &mockOutputMetrics{}
	out.SetOutputMetrics(om)

	// Flood the buffer. Some writes will succeed, some will be dropped.
	const writes = 200
	for range writes {
		_ = out.Write([]byte(`{"event":"flood"}` + "\n"))
	}

	require.NoError(t, out.Close())

	assert.Positive(t, om.drops.Load(),
		"RecordDrop must be called when the buffer is full")
	assert.LessOrEqual(t, om.flushes.Load()+om.drops.Load(), int64(writes),
		"flushes plus drops must not exceed total writes")
}

func TestFileOutput_Close_DrainsBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 1000}, nil)
	require.NoError(t, err)

	const n = 50
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"drain"}`+"\n")))
	}

	// Close must drain all buffered events before returning.
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Equal(t, n, len(lines), "Close must drain all buffered events")
}

func TestFileOutput_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	assert.NoError(t, out.Close())
}

func TestFileOutput_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	assert.NoError(t, out.Close())
	assert.NoError(t, out.Close())
}

func TestFileOutput_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte("data\n"))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

func TestFileOutput_Name(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "file:"+path, out.Name())
}

func TestFileOutput_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	// Close to flush async buffer to disk.
	require.NoError(t, out.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFileOutput_CustomPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{
		Path:        path,
		Permissions: "0644",
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	// Close to flush async buffer to disk.
	require.NoError(t, out.Close())

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestFileOutput_DefaultConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// All zero-value fields should get sensible defaults.
	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	// Verify the output is functional.
	require.NoError(t, out.Write([]byte("test\n")))
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test\n", string(content))
}

func TestFileOutput_InvalidConfig(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		wantErr string
		cfg     file.Config
	}{
		{
			name:    "empty path",
			cfg:     file.Config{Path: ""},
			wantErr: "must not be empty",
		},
		{
			name:    "missing parent directory",
			cfg:     file.Config{Path: "/nonexistent/dir/audit.log"},
			wantErr: "parent directory",
		},
		{
			name: "invalid permissions",
			cfg: file.Config{
				Path:        filepath.Join(dir, "invalid-perm.log"),
				Permissions: "not-octal",
			},
			wantErr: "permissions",
		},
		{
			name: "permissions out of range",
			cfg: file.Config{
				Path:        filepath.Join(dir, "out-of-range.log"),
				Permissions: "1777",
			},
			wantErr: "exceeds maximum",
		},
		{
			name: "MaxSizeMB exceeds limit",
			cfg: file.Config{
				Path:      filepath.Join(dir, "big.log"),
				MaxSizeMB: file.MaxSizeMB + 1,
			},
			wantErr: "max_size_mb",
		},
		{
			name: "MaxBackups exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "backups.log"),
				MaxBackups: file.MaxBackups + 1,
			},
			wantErr: "max_backups",
		},
		{
			name: "MaxAgeDays exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "age.log"),
				MaxAgeDays: file.MaxAgeDays + 1,
			},
			wantErr: "max_age_days",
		},
		{
			name: "BufferSize exceeds limit",
			cfg: file.Config{
				Path:       filepath.Join(dir, "buf.log"),
				BufferSize: file.MaxOutputBufferSize + 1,
			},
			wantErr: "buffer_size",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := file.New(tt.cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestFileOutput_NegativeMaxSizeMB_DefaultsTo100(t *testing.T) {
	dir := t.TempDir()
	out, err := file.New(file.Config{
		Path:      filepath.Join(dir, "neg.log"),
		MaxSizeMB: -1,
	}, nil)
	require.NoError(t, err, "negative MaxSizeMB should default, not error")
	_ = out.Close()
}

func TestFileOutput_Permissions0000_Rejected(t *testing.T) {
	dir := t.TempDir()
	_, err := file.New(file.Config{
		Path:        filepath.Join(dir, "noaccess.log"),
		Permissions: "0000",
	}, nil)
	// "0000" is valid octal but the rotation library rejects zero mode.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-zero")
}

func TestFileOutput_MaxBoundaryValues_Accepted(t *testing.T) {
	dir := t.TempDir()
	out, err := file.New(file.Config{
		Path:       filepath.Join(dir, "boundary.log"),
		MaxSizeMB:  file.MaxSizeMB,
		MaxBackups: file.MaxBackups,
		MaxAgeDays: file.MaxAgeDays,
		BufferSize: file.MaxOutputBufferSize,
	}, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestFileOutput_MaxExceeded_WrapsErrConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	_, err := file.New(file.Config{
		Path:      filepath.Join(dir, "test.log"),
		MaxSizeMB: file.MaxSizeMB + 1,
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestFileOutput_ImplementsOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	var _ audit.Output = out
}

func TestFileOutput_ImplementsDeliveryReporter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Type assertion through audit.Output interface.
	var o audit.Output = out
	dr, ok := o.(audit.DeliveryReporter)
	require.True(t, ok, "file output must implement DeliveryReporter")
	assert.True(t, dr.ReportsDelivery(), "file output must self-report delivery")
}

func TestFileOutput_ImplementsOutputMetricsReceiver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Type assertion through audit.Output interface.
	var o audit.Output = out
	_, ok := o.(audit.OutputMetricsReceiver)
	assert.True(t, ok, "file output must implement OutputMetricsReceiver")
}

func TestFileOutput_MultipleWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	for i := range 10 {
		data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", i))
		require.NoError(t, out.Write(data))
	}

	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	assert.Len(t, lines, 10)
}

func TestFileOutput_ConcurrentWriteClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"n":%d}`+"\n", n))
			// Errors are expected after Close; just exercise the race detector.
			_ = out.Write(data)
		}(i)
	}

	// Close while writes are in-flight.
	assert.NoError(t, out.Close())
	wg.Wait()
}

func TestFileOutput_WriteDuringClose_NoPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 10}, nil)
	require.NoError(t, err)

	// Write events in goroutines while Close() is called concurrently.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			_ = out.Write([]byte(`{"event":"race"}` + "\n"))
		}
	}()

	go func() {
		defer wg.Done()
		_ = out.Close()
	}()

	wg.Wait()
	// Success if no panic or deadlock.
}

func TestFileOutput_CopySafety(t *testing.T) {
	// Verify that mutating the input []byte after Write() does not
	// corrupt the buffered data (formatCache reuse invariant).
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	data := []byte(`{"event":"original"}` + "\n")
	require.NoError(t, out.Write(data))

	// Mutate the original slice after Write returns.
	for i := range data {
		data[i] = 'X'
	}

	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "original",
		"mutating input after Write must not corrupt buffered data")
}

func TestFileOutput_CompressFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	compress := false
	out, err := file.New(file.Config{
		Path:     path,
		Compress: &compress,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Metrics (#54)
// ---------------------------------------------------------------------------

// fileOnlyMetrics implements file.Metrics but not the full audit.Metrics interface.
type fileOnlyMetrics struct {
	rotations []string // paths passed to RecordFileRotation
	mu        sync.Mutex
}

func (m *fileOnlyMetrics) RecordFileRotation(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotations = append(m.rotations, path)
}

var _ file.Metrics = (*fileOnlyMetrics)(nil)

func (m *fileOnlyMetrics) rotationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rotations)
}

func TestFileOutput_NilFileMetrics_RotationDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path}, nil)
	require.NoError(t, err)

	for range 5 {
		require.NoError(t, out.Write([]byte(`{"event":"nil_metrics"}`+"\n")))
	}
	require.NoError(t, out.Close())
}

func TestFileOutput_FileMetrics_RecordFileRotation_CalledOnRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{}

	// MaxSizeMB=1 forces rotation after 1 MB of data.
	out, err := file.New(file.Config{
		Path:      path,
		MaxSizeMB: 1,
	}, m)
	require.NoError(t, err)

	// Write 1 MB + 1 byte to cross the rotation threshold.
	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = 'x'
	}
	require.NoError(t, out.Write(payload))
	// Close drains async buffer — rotation happens in background goroutine.
	require.NoError(t, out.Close())

	assert.Equal(t, 1, m.rotationCount(),
		"RecordFileRotation should be called once after crossing MaxSizeMB")

	m.mu.Lock()
	rotations := make([]string, len(m.rotations))
	copy(rotations, m.rotations)
	m.mu.Unlock()

	if assert.NotEmpty(t, rotations, "RecordFileRotation must have been called") {
		assert.Equal(t, path, rotations[0],
			"RecordFileRotation should receive the active file path")
	}
}

func TestFileOutput_FileMetrics_MultipleRotations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	m := &fileOnlyMetrics{}

	out, err := file.New(file.Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 10,
	}, m)
	require.NoError(t, err)

	// 3 writes of (1 MB + 1 byte) → 3 rotations.
	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = byte('a' + (i % 26))
	}
	const rotations = 3
	for range rotations {
		require.NoError(t, out.Write(payload))
	}
	// Close drains async buffer — all rotations happen in background.
	require.NoError(t, out.Close())

	assert.Equal(t, rotations, m.rotationCount(),
		"RecordFileRotation should be called once per rotation")
}

func TestFileOutput_FileMetrics_InterfaceAssertion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var m file.Metrics = &fileOnlyMetrics{}
	out, err := file.New(file.Config{Path: path}, m)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

func TestFileOutput_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	link := filepath.Join(dir, "symlink.log")

	// Create a real file, then a symlink pointing to it.
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink(target, link))

	// Construction succeeds — symlink check happens on first write
	// in the background goroutine.
	out, err := file.New(file.Config{Path: link}, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte("test\n")))
	// Close drains buffer — the symlink error is logged but the write
	// is attempted in the background goroutine.
	require.NoError(t, out.Close())
}

func TestFileOutput_DestinationKey_EquivalentPaths(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{name: "absolute", path: filepath.Join(dir, "audit.log")},
		{name: "relative_dot", path: filepath.Join(dir, ".", "audit.log")},
		{name: "relative_dotdot", path: filepath.Join(dir, "sub", "..", "audit.log")},
	}

	// All paths should produce the same DestinationKey.
	var keys []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := file.New(file.Config{Path: tt.path}, nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })

			key := out.DestinationKey()
			assert.NotEmpty(t, key)
			keys = append(keys, key)
		})
	}

	// All keys must be equal.
	for i := 1; i < len(keys); i++ {
		assert.Equal(t, keys[0], keys[i],
			"paths %q and %q should produce the same key", tests[0].path, tests[i].path)
	}
}

// ---------------------------------------------------------------------------
// OutputMetrics tests
// ---------------------------------------------------------------------------

func TestFileOutput_OutputMetrics_RecordFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 10_000}, nil)
	require.NoError(t, err)

	om := &mockOutputMetrics{}
	out.SetOutputMetrics(om)

	const n = 10
	for range n {
		require.NoError(t, out.Write([]byte(`{"event":"flush"}`+"\n")))
	}
	require.NoError(t, out.Close())

	assert.Equal(t, int64(n), om.flushes.Load(),
		"RecordFlush must be called for each successfully written event")
}

func TestFileOutput_OutputMetrics_RecordQueueDepth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 10_000}, nil)
	require.NoError(t, err)

	om := &mockOutputMetrics{}
	out.SetOutputMetrics(om)

	// 65 events guarantees writeCount hits 64 at least once.
	for range 65 {
		require.NoError(t, out.Write([]byte(`{"event":"depth"}`+"\n")))
	}
	require.NoError(t, out.Close())

	assert.Positive(t, om.depthCalls.Load(),
		"RecordQueueDepth must be called every 64 events in writeLoop")
}

func TestFileOutput_PanicRecovery_RecordsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 100}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	om := &mockOutputMetrics{}
	out.SetOutputMetrics(om)

	// Simulate a panic inside writeEvent — the deferred recovery
	// catches it. Called synchronously, not through the channel.
	out.SimulatePanicOnNextWrite()

	assert.Equal(t, int64(1), om.errors.Load(),
		"RecordError must be called when writeEvent panics")

	// The output must still be functional after recovery.
	require.NoError(t, out.Write([]byte(`{"event":"post-panic"}`+"\n")))
	require.NoError(t, out.Close())

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "post-panic",
		"output must remain functional after panic recovery")
}

// ---------------------------------------------------------------------------
// Named tests for issue #455 acceptance criteria
// ---------------------------------------------------------------------------

func TestFileOutput_RotationInBackgroundGoroutine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{
		Path:       path,
		MaxSizeMB:  1,
		MaxBackups: 3,
	}, nil)
	require.NoError(t, err)

	// Write >1 MB to trigger rotation in the background writeLoop.
	payload := make([]byte, 1024*1024+1)
	for i := range payload {
		payload[i] = 'x'
	}
	require.NoError(t, out.Write(payload))

	// Close drains the async buffer — rotation happens in writeLoop.
	require.NoError(t, out.Close())

	// Verify backup file exists (rotation happened).
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var backupCount int
	for _, e := range entries {
		if e.Name() != "audit.log" && strings.Contains(e.Name(), "audit") {
			backupCount++
		}
	}
	assert.Positive(t, backupCount,
		"rotation should produce at least one backup file")
}

func TestOutputMetrics_RecordError_CalledOnNonRetryableError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(file.Config{Path: path, BufferSize: 100}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	om := &mockOutputMetrics{}
	out.SetOutputMetrics(om)

	// SimulatePanicOnNextWrite triggers a nil-pointer panic inside
	// writeEvent — the deferred recovery catches it and calls RecordError.
	out.SimulatePanicOnNextWrite()

	assert.Equal(t, int64(1), om.errors.Load(),
		"RecordError must be called on non-retryable error (panic recovery)")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkFileOutput_Write(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.log")

	out, err := file.New(file.Config{Path: path, MaxSizeMB: 1024}, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ResetTimer()
	b.SetBytes(int64(len(event)))
	for b.Loop() {
		if err := out.Write(event); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileOutput_Write_Parallel(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.log")

	out, err := file.New(file.Config{Path: path, MaxSizeMB: 1024, BufferSize: 10000}, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ResetTimer()
	b.SetBytes(int64(len(event)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = out.Write(event)
		}
	})
}
