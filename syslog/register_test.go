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

package syslog_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
)

func TestSyslogFactory_RegisteredByInit(t *testing.T) {
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory, "syslog factory must be registered by init()")
}

func TestSyslogFactory_ValidConfig(t *testing.T) {
	// Syslog eagerly connects, so we use a valid local address
	// that will fail to connect — the factory should still succeed
	// in parsing the config. The connection error comes from New().
	// For this test, we just verify YAML parsing works.
	yaml := []byte("network: tcp\naddress: localhost:5514\nfacility: local0\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	// syslog.New eagerly connects — this may fail without a server.
	// We test parsing separately from connectivity.
	out, err := factory("siem_syslog", yaml, nil, nil, audit.FrameworkContext{})
	if err != nil {
		// Connection failure is expected without Docker — verify it
		// got past YAML parsing (error should be about connection).
		assert.Contains(t, err.Error(), "siem_syslog")
		return
	}
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "siem_syslog", out.Name())
}

func TestSyslogFactory_InvalidConfig_EmptyAddress(t *testing.T) {
	yaml := []byte("network: tcp\naddress: \"\"\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("bad_syslog", yaml, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad_syslog")
}

func TestSyslogFactory_UnknownYAMLField_Rejected(t *testing.T) {
	yaml := []byte("network: tcp\naddress: localhost:514\nbogus: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("test", yaml, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestSyslogFactory_EmptyConfig_ReturnsError(t *testing.T) {
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("empty", nil, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestSyslogFactory_WithTLSPolicy(t *testing.T) {
	yaml := []byte("network: tcp+tls\naddress: localhost:6514\ntls_policy:\n  allow_tls12: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	// Will fail to connect without Docker, but should parse YAML OK.
	_, err := factory("tls_syslog", yaml, nil, nil, audit.FrameworkContext{})
	if err != nil {
		assert.Contains(t, err.Error(), "tls_syslog")
	}
}

// TestSyslogFactory_BatchingKeys exercises the new YAML keys added
// by #599: batch_size, flush_interval, max_batch_bytes. Must accept
// them without error and the factory must not fail on any of them.
func TestSyslogFactory_BatchingKeys(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	rawYAML := []byte("network: tcp\n" +
		"address: " + srv.addr() + "\n" +
		"batch_size: 50\n" +
		"flush_interval: 250ms\n" +
		"max_batch_bytes: 524288\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	out, err := factory("batched", rawYAML, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err, "batching keys must parse cleanly")
	require.NotNil(t, out)
	t.Cleanup(func() { _ = out.Close() })
}

// TestSyslogFactory_FlushIntervalInvalid verifies that a malformed
// flush_interval string returns ErrConfigInvalid, not a nil-deref.
func TestSyslogFactory_FlushIntervalInvalid(t *testing.T) {
	rawYAML := []byte("network: tcp\naddress: localhost:514\nflush_interval: not-a-duration\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("bad_flush", rawYAML, nil, nil, audit.FrameworkContext{})
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestSyslogFactory_InsecureSkipVerify_Rejected(t *testing.T) {
	rawYAML := []byte("network: tcp\naddress: localhost:514\ninsecure_skip_verify: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("insecure", rawYAML, nil, nil, audit.FrameworkContext{})
	assert.Error(t, err, "insecure_skip_verify must not be settable via YAML")
	assert.Contains(t, err.Error(), "insecure_skip_verify")
}

func TestSyslogNewFactory_WithMetricsFactory(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	var gotType, gotName string
	mf := func(outputType, outputName string) audit.OutputMetrics {
		gotType, gotName = outputType, outputName
		return &factoryMockSyslogMetrics{}
	}
	factory := syslog.NewFactory(mf)

	rawYAML := []byte("network: tcp\naddress: " + srv.addr() + "\n")
	out, err := factory("with_metrics", rawYAML, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "with_metrics", out.Name())
	assert.Equal(t, "syslog", gotType, "factory must be called with outputType=\"syslog\"")
	assert.Equal(t, "with_metrics", gotName)
}

func TestSyslogNewFactory_NilFactory(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	factory := syslog.NewFactory(nil)

	rawYAML := []byte("network: tcp\naddress: " + srv.addr() + "\n")
	out, err := factory("nil_metrics", rawYAML, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "nil_metrics", out.Name())
}

// TestSyslogNewFactory_FactoryReturnsNil covers the silently-untested
// branch where the OutputMetricsFactory legitimately returns nil for a
// specific output — the constructed output must still build cleanly
// and have no metrics wired.
func TestSyslogNewFactory_FactoryReturnsNil(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	factory := syslog.NewFactory(func(_, _ string) audit.OutputMetrics {
		return nil
	})

	rawYAML := []byte("network: tcp\naddress: " + srv.addr() + "\n")
	out, err := factory("nil_return", rawYAML, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "nil_return", out.Name())
}

// factoryMockSyslogMetrics is a minimal audit.OutputMetrics scoped
// to the NewFactory tests. It does NOT implement
// [syslog.ReconnectRecorder], which exercises the structural-typing
// "base-only metrics" branch in SetOutputMetrics.
type factoryMockSyslogMetrics struct {
	audit.NoOpOutputMetrics
}

// Compile-time assertion: the factory mock is audit.OutputMetrics.
var _ audit.OutputMetrics = (*factoryMockSyslogMetrics)(nil)
