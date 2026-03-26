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

//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startRsyslogContainer starts an rsyslog container listening on TCP 514.
// It returns the mapped host:port and a cleanup function.
func startRsyslogContainer(t *testing.T) (string, testcontainers.Container) {
	t.Helper()
	ctx := context.Background()

	// Use a minimal rsyslog image. The rsyslog container listens on
	// TCP 514 by default and writes to /var/log/messages.
	req := testcontainers.ContainerRequest{
		Image:        "jumanjiman/rsyslog:latest",
		ExposedPorts: []string{"514/tcp"},
		WaitingFor:   wait.ForListeningPort("514/tcp").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "514/tcp")
	require.NoError(t, err)

	addr := fmt.Sprintf("%s:%s", host, port.Port())
	return addr, container
}

// readContainerLog reads the syslog messages from the container by
// trying common log file paths.
func readContainerLog(t *testing.T, container testcontainers.Container) string {
	t.Helper()
	ctx := context.Background()

	// Try common log paths used by different rsyslog images.
	paths := []string{
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/audit.log",
	}

	for _, path := range paths {
		code, reader, err := container.Exec(ctx, []string{"cat", path})
		if err != nil {
			t.Logf("exec cat %s: err=%v", path, err)
			continue
		}
		data, _ := io.ReadAll(reader)
		t.Logf("cat %s: code=%d len=%d", path, code, len(data))
		if code == 0 && len(data) > 0 {
			return string(data)
		}
	}

	// Fall back to container logs (stdout/stderr).
	logs, err := container.Logs(ctx)
	if err != nil {
		t.Logf("container.Logs: %v", err)
		return ""
	}
	data, _ := io.ReadAll(logs)
	t.Logf("container logs: len=%d", len(data))
	return string(data)
}

func TestSyslogIntegration_TCP_SendAndReceive(t *testing.T) {
	addr, container := startRsyslogContainer(t)
	defer func() { _ = container.Terminate(context.Background()) }()

	out, err := audit.NewSyslogOutput(audit.SyslogConfig{
		Network:  "tcp",
		Address:  addr,
		Facility: "local0",
		AppName:  "go-audit-test",
	})
	require.NoError(t, err)

	// Send a known event.
	payload := `{"event_type":"user_create","outcome":"success","actor_id":"alice"}`
	require.NoError(t, out.Write([]byte(payload)))

	// Give rsyslog time to flush.
	time.Sleep(2 * time.Second)
	require.NoError(t, out.Close())

	// Read the log from the container and verify our message arrived.
	log := readContainerLog(t, container)
	assert.Contains(t, log, "user_create",
		"syslog should contain the event type")
	assert.Contains(t, log, "alice",
		"syslog should contain the actor_id")
}

func TestSyslogIntegration_TCP_MultipleEvents(t *testing.T) {
	addr, container := startRsyslogContainer(t)
	defer func() { _ = container.Terminate(context.Background()) }()

	out, err := audit.NewSyslogOutput(audit.SyslogConfig{
		Network:  "tcp",
		Address:  addr,
		Facility: "local0",
		AppName:  "go-audit-test",
	})
	require.NoError(t, err)

	events := []string{
		`{"event":"event_1","marker":"FIRST"}`,
		`{"event":"event_2","marker":"SECOND"}`,
		`{"event":"event_3","marker":"THIRD"}`,
	}
	for _, e := range events {
		require.NoError(t, out.Write([]byte(e)))
	}

	time.Sleep(2 * time.Second)
	require.NoError(t, out.Close())

	log := readContainerLog(t, container)
	for _, marker := range []string{"FIRST", "SECOND", "THIRD"} {
		assert.Contains(t, log, marker,
			"syslog should contain marker %s", marker)
	}
}

func TestSyslogIntegration_TCP_RFC5424Format(t *testing.T) {
	addr, container := startRsyslogContainer(t)
	defer func() { _ = container.Terminate(context.Background()) }()

	out, err := audit.NewSyslogOutput(audit.SyslogConfig{
		Network:  "tcp",
		Address:  addr,
		Facility: "local0",
		AppName:  "go-audit-test",
	})
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"rfc5424_check"}`)))

	time.Sleep(2 * time.Second)
	require.NoError(t, out.Close())

	log := readContainerLog(t, container)
	t.Logf("log content: %s", log)
	// Verify the message payload arrived intact.
	assert.Contains(t, log, "rfc5424_check",
		"syslog should contain the event payload")
	// Verify the syslog line has a timestamp.
	assert.Contains(t, log, time.Now().Format("2006-"),
		"syslog should contain a timestamp")
}
