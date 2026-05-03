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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

func TestRegisterOutputFactory_Success(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	factory := func(name string, _ []byte, _ audit.FrameworkContext) (audit.Output, error) {
		return testhelper.NewMockOutput(name), nil
	}
	require.NoError(t, audit.RegisterOutputFactory("test", factory))

	got := audit.LookupOutputFactory("test")
	require.NotNil(t, got)
}

func TestRegisterOutputFactory_Overwrite(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	first := func(_ string, _ []byte, _ audit.FrameworkContext) (audit.Output, error) {
		return testhelper.NewMockOutput("first"), nil
	}
	second := func(_ string, _ []byte, _ audit.FrameworkContext) (audit.Output, error) {
		return testhelper.NewMockOutput("second"), nil
	}

	require.NoError(t, audit.RegisterOutputFactory("test", first))
	require.NoError(t, audit.RegisterOutputFactory("test", second))

	got := audit.LookupOutputFactory("test")
	require.NotNil(t, got)

	// Verify the second factory is the one registered.
	out, err := got("check", nil, audit.FrameworkContext{})
	require.NoError(t, err)
	assert.Equal(t, "second", out.Name())
}

func TestLookupOutputFactory_NotRegistered_ReturnsNil(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	got := audit.LookupOutputFactory("nonexistent")
	assert.Nil(t, got)
}

func TestRegisteredOutputTypes_Sorted(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	dummy := func(string, []byte, audit.FrameworkContext) (audit.Output, error) {
		return nil, nil
	}
	require.NoError(t, audit.RegisterOutputFactory("webhook", dummy))
	require.NoError(t, audit.RegisterOutputFactory("file", dummy))
	require.NoError(t, audit.RegisterOutputFactory("syslog", dummy))

	types := audit.RegisteredOutputTypes()
	assert.Equal(t, []string{"file", "syslog", "webhook"}, types)
}

// TestRegisterOutputFactory_EmptyName_ReturnsError verifies that
// [audit.RegisterOutputFactory] now returns a non-nil error wrapping
// [audit.ErrValidation] instead of panicking on an empty type name
// (#590 part 2 of 2). The documented caller pattern is
// `panic-on-non-nil-error` inside the caller's own init(), preserving
// startup-fatal semantics while keeping the library panic-free.
func TestRegisterOutputFactory_EmptyName_ReturnsError(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	err := audit.RegisterOutputFactory("", func(string, []byte, audit.FrameworkContext) (audit.Output, error) {
		return nil, nil
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.Contains(t, err.Error(), "empty type name")
}

func TestRegisterOutputFactory_NilFactory_ReturnsError(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	err := audit.RegisterOutputFactory("test", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrValidation)
	assert.Contains(t, err.Error(), "nil factory")
}

func TestRegisteredOutputTypes_Empty(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	types := audit.RegisteredOutputTypes()
	assert.Empty(t, types)
}

func TestWrapOutput_OverridesName(t *testing.T) {
	inner := testhelper.NewMockOutput("file:/var/log/audit.log")
	wrapped := audit.WrapOutput(inner, "compliance_file")

	assert.Equal(t, "compliance_file", wrapped.Name())
}

func TestWrapOutput_PreservesDestinationKey(t *testing.T) {
	inner := &mockDestKeyer{
		MockOutput: *testhelper.NewMockOutput("file:/var/log/audit.log"),
		destKey:    "/var/log/audit.log",
	}
	wrapped := audit.WrapOutput(inner, "compliance_file")

	dk, ok := wrapped.(audit.DestinationKeyer)
	require.True(t, ok, "wrapped output should implement DestinationKeyer")
	assert.Equal(t, "/var/log/audit.log", dk.DestinationKey())
	// Name is overridden but destination key is from inner.
	assert.Equal(t, "compliance_file", wrapped.Name())
}

func TestWrapOutput_NoDestinationKeyer_ReturnsEmpty(t *testing.T) {
	// MockOutput does NOT implement DestinationKeyer.
	inner := testhelper.NewMockOutput("plain")
	wrapped := audit.WrapOutput(inner, "my_output")

	dk, ok := wrapped.(audit.DestinationKeyer)
	require.True(t, ok, "namedOutput always implements DestinationKeyer")
	assert.Equal(t, "", dk.DestinationKey())
}

func TestWrapOutput_PreservesDeliveryReporter(t *testing.T) {
	inner := &mockDeliveryReporter{
		MockOutput: *testhelper.NewMockOutput("webhook:example.com"),
	}
	wrapped := audit.WrapOutput(inner, "my_webhook")

	dr, ok := wrapped.(audit.DeliveryReporter)
	require.True(t, ok, "wrapped output should implement DeliveryReporter")
	assert.True(t, dr.ReportsDelivery())
}

func TestWrapOutput_NonDeliveryReporter_ReturnsFalse(t *testing.T) {
	inner := testhelper.NewMockOutput("file:/tmp/test.log")
	wrapped := audit.WrapOutput(inner, "my_file")

	dr, ok := wrapped.(audit.DeliveryReporter)
	require.True(t, ok, "namedOutput always implements DeliveryReporter")
	assert.False(t, dr.ReportsDelivery())
}

func TestWrapOutput_WriteDelegatesToInner(t *testing.T) {
	inner := testhelper.NewMockOutput("inner")
	wrapped := audit.WrapOutput(inner, "custom_name")

	err := wrapped.Write([]byte(`{"test":true}`))
	assert.NoError(t, err)
	assert.Equal(t, 1, inner.EventCount())
}

func TestWrapOutput_CloseDelegatesToInner(t *testing.T) {
	inner := testhelper.NewMockOutput("inner")
	wrapped := audit.WrapOutput(inner, "custom_name")

	err := wrapped.Close()
	assert.NoError(t, err)
	assert.True(t, inner.IsClosed())
}

func TestWrapOutput_PreservesMetadataWriter(t *testing.T) {
	inner := &mockMetadataWriter{
		MockOutput: *testhelper.NewMockOutput("syslog:localhost:514"),
	}
	wrapped := audit.WrapOutput(inner, "my_syslog")

	mw, ok := wrapped.(audit.MetadataWriter)
	require.True(t, ok, "wrapped output should implement MetadataWriter")

	meta := audit.EventMetadata{Severity: 8, EventType: "auth_failure"}
	err := mw.WriteWithMetadata([]byte(`{"test":true}`), meta)
	require.NoError(t, err)

	assert.Equal(t, 1, inner.metadataCalls, "WriteWithMetadata should forward to inner")
	assert.Equal(t, 8, inner.lastMeta.Severity, "severity should be forwarded")
}

func TestWrapOutput_NonMetadataWriter_FallsBackToWrite(t *testing.T) {
	inner := testhelper.NewMockOutput("file:/tmp/test.log")
	wrapped := audit.WrapOutput(inner, "my_file")

	mw, ok := wrapped.(audit.MetadataWriter)
	require.True(t, ok, "namedOutput always implements MetadataWriter")

	meta := audit.EventMetadata{Severity: 5}
	err := mw.WriteWithMetadata([]byte(`{"test":true}`), meta)
	require.NoError(t, err)

	assert.Equal(t, 1, inner.EventCount(), "should fall back to Write")
}

// TestWrapOutput_PreservesFrameworkFieldReceiver was removed in #696
// along with the FrameworkFieldReceiver interface. Framework fields
// now arrive at outputs via [audit.FrameworkContext] at construction
// time; the wrapper has no per-output forwarding to perform.

// TestWrapOutput_PreservesDiagnosticLoggerReceiver was removed in #696
// along with the DiagnosticLoggerReceiver interface. The diagnostic
// logger arrives at outputs via [audit.FrameworkContext] at
// construction time.

// TestWrapOutput_PreservesLastDeliveryReporter verifies that when the
// inner output implements [LastDeliveryReporter], the wrapper forwards
// LastDeliveryNanos to the inner. Without delegation,
// [Auditor.LastDeliveryAge] would always see 0 for YAML-named outputs
// (#753).
func TestWrapOutput_PreservesLastDeliveryReporter(t *testing.T) {
	inner := &mockLastDeliveryReporter{
		MockOutput: *testhelper.NewMockOutput("syslog:localhost:514"),
		nanos:      1_700_000_000_000_000_000,
	}
	wrapped := audit.WrapOutput(inner, "my_syslog")

	r, ok := wrapped.(audit.LastDeliveryReporter)
	require.True(t, ok, "wrapped output should implement LastDeliveryReporter")
	assert.Equal(t, int64(1_700_000_000_000_000_000), r.LastDeliveryNanos(),
		"wrapper must forward the inner reporter's timestamp")
}

// TestWrapOutput_NonLastDeliveryReporter_ReturnsZero verifies the
// inner-does-not-implement branch: the wrapper itself satisfies the
// interface (via the compile-time assertion), but reports 0 because
// the inner output cannot answer (#753).
func TestWrapOutput_NonLastDeliveryReporter_ReturnsZero(t *testing.T) {
	// MockOutput does NOT implement LastDeliveryReporter.
	inner := testhelper.NewMockOutput("plain")
	wrapped := audit.WrapOutput(inner, "my_output")

	r, ok := wrapped.(audit.LastDeliveryReporter)
	require.True(t, ok, "namedOutput always implements LastDeliveryReporter")
	assert.Equal(t, int64(0), r.LastDeliveryNanos(),
		"non-reporter inner must surface as 0 (no telemetry)")
}

// --- Test helper types ---

// mockDestKeyer wraps MockOutput with DestinationKeyer.
type mockDestKeyer struct { //nolint:govet // fieldalignment: test struct, readability preferred
	testhelper.MockOutput
	destKey string
}

func (m *mockDestKeyer) DestinationKey() string { return m.destKey }

// mockDeliveryReporter wraps MockOutput with DeliveryReporter.
type mockDeliveryReporter struct {
	testhelper.MockOutput
}

func (m *mockDeliveryReporter) ReportsDelivery() bool { return true }

// mockMetadataWriter wraps MockOutput with MetadataWriter.
type mockMetadataWriter struct { //nolint:govet // fieldalignment: readability preferred
	testhelper.MockOutput
	lastMeta      audit.EventMetadata
	metadataCalls int
}

func (m *mockMetadataWriter) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	m.metadataCalls++
	m.lastMeta = meta
	return m.Write(data)
}

// mockLastDeliveryReporter wraps MockOutput with LastDeliveryReporter,
// returning a fixed timestamp so the test asserts forwarding rather
// than wall-clock semantics.
type mockLastDeliveryReporter struct {
	testhelper.MockOutput
	nanos int64
}

func (m *mockLastDeliveryReporter) LastDeliveryNanos() int64 { return m.nanos }
