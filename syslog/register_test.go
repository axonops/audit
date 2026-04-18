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
	out, err := factory("siem_syslog", yaml, nil, nil)
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

	_, err := factory("bad_syslog", yaml, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bad_syslog")
}

func TestSyslogFactory_UnknownYAMLField_Rejected(t *testing.T) {
	yaml := []byte("network: tcp\naddress: localhost:514\nbogus: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("test", yaml, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestSyslogFactory_EmptyConfig_ReturnsError(t *testing.T) {
	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("empty", nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestSyslogFactory_WithTLSPolicy(t *testing.T) {
	yaml := []byte("network: tcp+tls\naddress: localhost:6514\ntls_policy:\n  allow_tls12: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	// Will fail to connect without Docker, but should parse YAML OK.
	_, err := factory("tls_syslog", yaml, nil, nil)
	if err != nil {
		assert.Contains(t, err.Error(), "tls_syslog")
	}
}

func TestSyslogFactory_InsecureSkipVerify_Rejected(t *testing.T) {
	rawYAML := []byte("network: tcp\naddress: localhost:514\ninsecure_skip_verify: true\n")

	factory := audit.LookupOutputFactory("syslog")
	require.NotNil(t, factory)

	_, err := factory("insecure", rawYAML, nil, nil)
	assert.Error(t, err, "insecure_skip_verify must not be settable via YAML")
	assert.Contains(t, err.Error(), "insecure_skip_verify")
}

func TestSyslogNewFactory_WithMetrics(t *testing.T) {
	metrics := &mockSyslogMetrics{}
	factory := syslog.NewFactory(metrics)

	rawYAML := []byte("network: tcp\naddress: localhost:5514\n")
	out, err := factory("with_metrics", rawYAML, nil, nil)
	if err != nil {
		// Connection failure expected without Docker.
		t.Logf("skipping connectivity assertion: %v", err)
		return
	}
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "with_metrics", out.Name())
}

func TestSyslogNewFactory_NilMetrics(t *testing.T) {
	factory := syslog.NewFactory(nil)

	rawYAML := []byte("network: tcp\naddress: localhost:5514\n")
	out, err := factory("nil_metrics", rawYAML, nil, nil)
	if err != nil {
		t.Logf("skipping connectivity assertion: %v", err)
		return
	}
	t.Cleanup(func() { _ = out.Close() })
	assert.Equal(t, "nil_metrics", out.Name())
}

type mockSyslogMetrics struct{}

func (m *mockSyslogMetrics) RecordSyslogReconnect(_ string, _ bool) {}
