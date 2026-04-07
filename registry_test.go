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

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/internal/testhelper"
)

func TestRegisterOutputFactory_Success(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	factory := func(name string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return testhelper.NewMockOutput(name), nil
	}
	audit.RegisterOutputFactory("test", factory)

	got := audit.LookupOutputFactory("test")
	require.NotNil(t, got)
}

func TestRegisterOutputFactory_Overwrite(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	first := func(name string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return testhelper.NewMockOutput("first"), nil
	}
	second := func(name string, _ []byte, _ audit.Metrics) (audit.Output, error) {
		return testhelper.NewMockOutput("second"), nil
	}

	audit.RegisterOutputFactory("test", first)
	audit.RegisterOutputFactory("test", second)

	got := audit.LookupOutputFactory("test")
	require.NotNil(t, got)

	// Verify the second factory is the one registered.
	out, err := got("check", nil, nil)
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

	dummy := func(string, []byte, audit.Metrics) (audit.Output, error) { return nil, nil }
	audit.RegisterOutputFactory("webhook", dummy)
	audit.RegisterOutputFactory("file", dummy)
	audit.RegisterOutputFactory("syslog", dummy)

	types := audit.RegisteredOutputTypes()
	assert.Equal(t, []string{"file", "syslog", "webhook"}, types)
}

func TestRegisterOutputFactory_EmptyName_Panics(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	assert.Panics(t, func() {
		audit.RegisterOutputFactory("", func(string, []byte, audit.Metrics) (audit.Output, error) {
			return nil, nil
		})
	})
}

func TestRegisterOutputFactory_NilFactory_Panics(t *testing.T) {
	t.Cleanup(audit.SaveAndResetRegistryForTest())

	assert.Panics(t, func() {
		audit.RegisterOutputFactory("test", nil)
	})
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

func TestWrapOutput_PreservesFrameworkFieldReceiver(t *testing.T) {
	inner := &mockFrameworkFieldReceiver{
		MockOutput: *testhelper.NewMockOutput("loki:localhost:3100"),
	}
	wrapped := audit.WrapOutput(inner, "my_loki")

	fr, ok := wrapped.(audit.FrameworkFieldReceiver)
	require.True(t, ok, "wrapped output should implement FrameworkFieldReceiver")

	fr.SetFrameworkFields("my-app", "my-host", "UTC", 12345)
	assert.Equal(t, "my-app", inner.appName, "appName should be forwarded")
	assert.Equal(t, "my-host", inner.host, "host should be forwarded")
	assert.Equal(t, "UTC", inner.timezone, "timezone should be forwarded")
	assert.Equal(t, 12345, inner.pid, "pid should be forwarded")
}

func TestWrapOutput_NonFrameworkFieldReceiver_NoOp(t *testing.T) {
	inner := testhelper.NewMockOutput("file:/tmp/test.log")
	wrapped := audit.WrapOutput(inner, "my_file")

	fr, ok := wrapped.(audit.FrameworkFieldReceiver)
	require.True(t, ok, "namedOutput always implements FrameworkFieldReceiver")

	// Should not panic.
	fr.SetFrameworkFields("app", "host", "UTC", 1)
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

// mockFrameworkFieldReceiver wraps MockOutput with FrameworkFieldReceiver.
type mockFrameworkFieldReceiver struct { //nolint:govet // fieldalignment: test struct
	testhelper.MockOutput
	appName  string
	host     string
	timezone string
	pid      int
}

func (m *mockFrameworkFieldReceiver) SetFrameworkFields(appName, host, timezone string, pid int) {
	m.appName = appName
	m.host = host
	m.timezone = timezone
	m.pid = pid
}
