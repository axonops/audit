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

package ssrf_test

import (
	"net"
	"testing"

	"github.com/axonops/go-audit/internal/ssrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIP_Blocked(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"loopback IPv4", "127.0.0.1"},
		{"loopback IPv4 other", "127.0.0.2"},
		{"loopback IPv6", "::1"},
		{"link-local IPv4", "169.254.1.1"},
		{"link-local IPv6", "fe80::1"},
		{"cloud metadata", "169.254.169.254"},
		{"private 10.x", "10.0.0.1"},
		{"private 10.255", "10.255.255.255"},
		{"private 172.16.x", "172.16.0.1"},
		{"private 172.31.x", "172.31.255.255"},
		{"private 192.168.x", "192.168.1.1"},
		{"private IPv6 ULA", "fc00::1"},
		{"multicast IPv4", "224.0.0.1"},
		{"multicast IPv6", "ff02::1"},
		{"unspecified IPv4", "0.0.0.0"},
		{"unspecified IPv6", "::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse %q", tt.ip)
			err := ssrf.CheckIP(ip, false)
			assert.Error(t, err, "IP %s should be blocked", tt.ip)
		})
	}
}

func TestCheckIP_Allowed(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"public IPv4", "8.8.8.8"},
		{"public IPv4 other", "1.1.1.1"},
		{"public IPv4 high", "203.0.113.1"},
		{"public IPv6", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse %q", tt.ip)
			err := ssrf.CheckIP(ip, false)
			assert.NoError(t, err, "IP %s should be allowed", tt.ip)
		})
	}
}

func TestCheckIP_AllowPrivateRanges(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"loopback allowed", "127.0.0.1", false},
		{"private 10.x allowed", "10.0.0.1", false},
		{"private 172.16 allowed", "172.16.0.1", false},
		{"private 192.168 allowed", "192.168.1.1", false},
		{"cloud metadata still blocked", "169.254.169.254", true},
		{"link-local still blocked", "169.254.1.1", true},
		{"multicast still blocked", "224.0.0.1", true},
		{"unspecified still blocked", "0.0.0.0", true},
		{"public still allowed", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)
			err := ssrf.CheckIP(ip, true)
			if tt.blocked {
				assert.Error(t, err, "%s should be blocked", tt.ip)
			} else {
				assert.NoError(t, err, "%s should be allowed", tt.ip)
			}
		})
	}
}

func TestCheckAddress(t *testing.T) {
	err := ssrf.CheckAddress("127.0.0.1:443", false)
	assert.Error(t, err, "loopback should be blocked")

	err = ssrf.CheckAddress("8.8.8.8:443", false)
	assert.NoError(t, err, "public IP should be allowed")
}

func TestCheckAddress_Invalid(t *testing.T) {
	err := ssrf.CheckAddress("not-valid", false)
	assert.Error(t, err, "invalid address should error")

	err = ssrf.CheckAddress("not-an-ip:443", false)
	assert.Error(t, err, "non-IP host should error")
}

func TestNewDialControl_ReturnsFunction(t *testing.T) {
	// Verify the returned function has the correct signature.
	fn := ssrf.NewDialControl()
	require.NotNil(t, fn)

	fn2 := ssrf.NewDialControl(ssrf.AllowPrivateRanges())
	require.NotNil(t, fn2)
}
