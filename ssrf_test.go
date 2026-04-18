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
	"errors"
	"net"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckSSRFIP_Blocked(t *testing.T) {
	t.Parallel()
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
		{"cgnat bottom", "100.64.0.0"},
		{"cgnat mid", "100.64.0.1"},
		{"cgnat top", "100.127.255.254"},
		{"multicast IPv4", "224.0.0.1"},
		{"multicast IPv6", "ff02::1"},
		{"unspecified IPv4", "0.0.0.0"},
		{"unspecified IPv6", "::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse %q", tt.ip)
			err := audit.CheckSSRFIP(ip, false)
			assert.Error(t, err, "IP %s should be blocked", tt.ip)
		})
	}
}

func TestCheckSSRFIP_Allowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
	}{
		{"public IPv4", "8.8.8.8"},
		{"public IPv4 other", "1.1.1.1"},
		{"public IPv4 high", "203.0.113.1"},
		{"public IPv6", "2001:db8::1"},
		{"just below cgnat", "100.63.255.255"},
		{"just above cgnat", "100.128.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse %q", tt.ip)
			err := audit.CheckSSRFIP(ip, false)
			assert.NoError(t, err, "IP %s should be allowed", tt.ip)
		})
	}
}

func TestCheckSSRFIP_AllowPrivateRanges(t *testing.T) {
	t.Parallel()
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
		{"cgnat still blocked", "100.64.0.1", true},
		{"link-local still blocked", "169.254.1.1", true},
		{"multicast still blocked", "224.0.0.1", true},
		{"unspecified still blocked", "0.0.0.0", true},
		{"public still allowed", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)
			err := audit.CheckSSRFIP(ip, true)
			if tt.blocked {
				assert.Error(t, err, "%s should be blocked", tt.ip)
			} else {
				assert.NoError(t, err, "%s should be allowed", tt.ip)
			}
		})
	}
}

func TestCheckSSRFIP_IPv4MappedIPv6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"mapped loopback", "::ffff:127.0.0.1", true},
		{"mapped private 10.x", "::ffff:10.0.0.1", true},
		{"mapped private 192.168", "::ffff:192.168.1.1", true},
		{"mapped metadata", "::ffff:169.254.169.254", true},
		{"mapped public", "::ffff:8.8.8.8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)
			err := audit.CheckSSRFIP(ip, false)
			if tt.blocked {
				assert.Error(t, err, "%s should be blocked", tt.ip)
			} else {
				assert.NoError(t, err, "%s should be allowed", tt.ip)
			}
		})
	}
}

func TestCheckSSRFAddress(t *testing.T) {
	t.Parallel()
	err := audit.CheckSSRFAddress("127.0.0.1:443", false)
	assert.Error(t, err, "loopback should be blocked")

	err = audit.CheckSSRFAddress("8.8.8.8:443", false)
	assert.NoError(t, err, "public IP should be allowed")
}

func TestCheckSSRFAddress_Invalid(t *testing.T) {
	t.Parallel()
	err := audit.CheckSSRFAddress("not-valid", false)
	assert.Error(t, err, "invalid address should error")

	err = audit.CheckSSRFAddress("not-an-ip:443", false)
	assert.Error(t, err, "non-IP host should error")
}

func TestNewSSRFDialControl_ReturnsFunction(t *testing.T) {
	t.Parallel()
	fn := audit.NewSSRFDialControl()
	require.NotNil(t, fn)

	fn2 := audit.NewSSRFDialControl(audit.AllowPrivateRanges())
	require.NotNil(t, fn2)
}

// TestCheckSSRFIP_BlocksAllKnownMetadataEndpoints is the named
// contract test from #480 Testing Requirements. Every published
// cloud instance metadata endpoint MUST be blocked regardless of
// AllowPrivateRanges. IPv6 variants (AWS IMDSv2) and IPv4-mapped-
// IPv6 aliases of the same must also be blocked.
func TestCheckSSRFIP_BlocksAllKnownMetadataEndpoints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
	}{
		{"aws_imds_ipv4", "169.254.169.254"},
		{"aws_imdsv2_ipv6", "fd00:ec2::254"},
		{"aws_imds_ipv4_mapped_as_ipv6", "::ffff:169.254.169.254"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "parse %s", tt.ip)

			// Must be blocked with AllowPrivateRanges OFF.
			err1 := audit.CheckSSRFIP(ip, false)
			require.Error(t, err1)

			// MUST be blocked even when AllowPrivateRanges is ON —
			// metadata endpoints are not subject to the
			// private-range bypass.
			err2 := audit.CheckSSRFIP(ip, true)
			require.Error(t, err2,
				"metadata address %s must be blocked even when AllowPrivateRanges is set", tt.ip)

			// Typed error contract: wraps ErrSSRFBlocked and has
			// Reason == SSRFReasonCloudMetadata.
			assert.ErrorIs(t, err2, audit.ErrSSRFBlocked)
			var ssrfErr *audit.SSRFBlockedError
			require.ErrorAs(t, err2, &ssrfErr)
			assert.Equal(t, audit.SSRFReasonCloudMetadata, ssrfErr.Reason)
		})
	}
}

// TestCheckSSRFAddress_IPv6MappedIPv4Private is the named contract
// test from #480 Testing Requirements. An attacker cannot bypass the
// private-address block by bracketing an IPv4 private address as an
// IPv6 literal. Applies to every private-range variant.
func TestCheckSSRFAddress_IPv6MappedIPv4Private(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		address string
	}{
		{"mapped_10_slash_8", "[::ffff:10.0.0.1]:443"},
		{"mapped_172_16_slash_12", "[::ffff:172.16.0.1]:443"},
		{"mapped_192_168_slash_16", "[::ffff:192.168.1.1]:443"},
		{"mapped_loopback", "[::ffff:127.0.0.1]:443"},
		{"mapped_metadata", "[::ffff:169.254.169.254]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := audit.CheckSSRFAddress(tt.address, false)
			require.Error(t, err, "%s should be blocked", tt.address)
			assert.ErrorIs(t, err, audit.ErrSSRFBlocked)
		})
	}
}

// TestCheckSSRFIP_BlocksDeprecatedSiteLocalIPv6 covers the fec0::/10
// range (RFC 3879 deprecated but still routable on some legacy
// stacks). Go's net.IP.IsPrivate() does NOT classify this range;
// #480 adds an explicit CIDR check.
func TestCheckSSRFIP_BlocksDeprecatedSiteLocalIPv6(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("fec0::1")
	require.NotNil(t, ip)

	// ALWAYS blocked regardless of AllowPrivateRanges.
	err := audit.CheckSSRFIP(ip, true)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrSSRFBlocked)

	var ssrfErr *audit.SSRFBlockedError
	require.ErrorAs(t, err, &ssrfErr)
	assert.Equal(t, audit.SSRFReasonDeprecatedSiteLocal, ssrfErr.Reason)
}

// TestSSRFBlockedError_TypedAccessPattern verifies the consumer
// discrimination contract — every block reason must be distinguishable
// via errors.As on the typed error.
func TestSSRFBlockedError_TypedAccessPattern(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		ip     string
		reason audit.SSRFReason
	}{
		{"cloud_metadata_ipv4", "169.254.169.254", audit.SSRFReasonCloudMetadata},
		{"cloud_metadata_ipv6", "fd00:ec2::254", audit.SSRFReasonCloudMetadata},
		{"cgnat", "100.64.0.1", audit.SSRFReasonCGNAT},
		{"deprecated_site_local", "fec0::1", audit.SSRFReasonDeprecatedSiteLocal},
		{"link_local_ipv4", "169.254.0.1", audit.SSRFReasonLinkLocal},
		{"link_local_ipv6", "fe80::1", audit.SSRFReasonLinkLocal},
		{"multicast_ipv4", "224.1.1.1", audit.SSRFReasonMulticast},
		{"multicast_ipv6", "ff0e::1", audit.SSRFReasonMulticast},
		{"unspecified_ipv4", "0.0.0.0", audit.SSRFReasonUnspecified},
		{"unspecified_ipv6", "::", audit.SSRFReasonUnspecified},
		{"loopback_ipv4", "127.0.0.1", audit.SSRFReasonLoopback},
		{"loopback_ipv6", "::1", audit.SSRFReasonLoopback},
		{"private_rfc1918_10", "10.0.0.1", audit.SSRFReasonPrivate},
		{"private_ula_ipv6", "fd12:3456::1", audit.SSRFReasonPrivate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "parse %s", tt.ip)
			err := audit.CheckSSRFIP(ip, false)
			require.Error(t, err, "%s must be blocked", tt.ip)

			// Sentinel match via errors.Is.
			assert.True(t, errors.Is(err, audit.ErrSSRFBlocked),
				"must wrap ErrSSRFBlocked")

			// Typed access via errors.As.
			var ssrfErr *audit.SSRFBlockedError
			require.ErrorAs(t, err, &ssrfErr)
			assert.Equal(t, tt.reason, ssrfErr.Reason,
				"wrong reason for %s", tt.ip)
			assert.True(t, ssrfErr.IP.IsValid(),
				"IP field must be a valid netip.Addr")
		})
	}
}

// TestCheckSSRFAddress_ScopedIPv6 ensures scoped addresses
// (fe80::1%eth0) do not bypass the check. Today ParseIP returns nil
// on zoned strings, which produces the "could not parse IP" error —
// lock that in so a future refactor stripping zone IDs doesn't
// silently weaken the guard.
func TestCheckSSRFAddress_ScopedIPv6(t *testing.T) {
	t.Parallel()
	err := audit.CheckSSRFAddress("[fe80::1%eth0]:443", false)
	require.Error(t, err,
		"scoped IPv6 address must not bypass SSRF (zone ID is not stripped)")
	// This is a parse error, not a typed SSRFBlockedError — the
	// check fails before reason classification. Must not wrap
	// ErrSSRFBlocked because we're rejecting on parse failure, not
	// on block policy.
	assert.NotErrorIs(t, err, audit.ErrSSRFBlocked,
		"parse errors must NOT wrap ErrSSRFBlocked — they are a different failure class")
}
