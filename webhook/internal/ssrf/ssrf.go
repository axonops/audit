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

// Package ssrf provides a net.Dialer Control function that prevents
// server-side request forgery by blocking connections to private,
// loopback, link-local, and cloud metadata IP addresses.
package ssrf

import (
	"fmt"
	"net"
	"syscall"
)

// config holds SSRF protection options.
type config struct {
	allowPrivate bool
}

// Option configures SSRF protection behaviour.
type Option func(*config)

// AllowPrivateRanges permits connections to RFC 1918 private address
// ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv6 ULA
// (fc00::/7), and loopback (127.0.0.0/8, ::1). This is intended for
// private network deployments where webhook receivers run on internal
// infrastructure, and for testing with [net/http/httptest] which binds
// to 127.0.0.1.
//
// Cloud metadata addresses (169.254.169.254) remain blocked even when
// private ranges are allowed.
func AllowPrivateRanges() Option {
	return func(c *config) {
		c.allowPrivate = true
	}
}

// NewDialControl returns a [net.Dialer] Control function that checks
// every resolved IP address before a connection is established. Use it
// with [net/http.Transport]:
//
//	transport := &http.Transport{
//	    DialContext: (&net.Dialer{
//	        Control: ssrf.NewDialControl(),
//	    }).DialContext,
//	}
//
// The Control function blocks connections to:
//   - Loopback addresses (127.0.0.0/8, ::1)
//   - Link-local addresses (169.254.0.0/16, fe80::/10)
//   - Cloud metadata endpoints (169.254.169.254)
//   - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - IPv6 unique local addresses (fc00::/7)
//   - Multicast addresses (224.0.0.0/4, ff00::/8)
//   - Unspecified addresses (0.0.0.0, ::)
//
// Use [AllowPrivateRanges] to permit private and loopback addresses.
func NewDialControl(opts ...Option) func(string, string, syscall.RawConn) error {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return func(_, address string, _ syscall.RawConn) error {
		return CheckAddress(address, cfg.allowPrivate)
	}
}

// CheckAddress validates that a resolved address is not blocked by
// SSRF policy. The address must be in host:port format. This function
// is exported for direct testing.
func CheckAddress(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf: invalid address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf: could not parse IP %q", host)
	}

	return CheckIP(ip, allowPrivate)
}

// CheckIP validates that an IP address is not blocked by SSRF policy.
// This function is exported for direct unit testing of IP classification.
func CheckIP(ip net.IP, allowPrivate bool) error {
	// Cloud metadata — ALWAYS blocked regardless of config.
	// AWS, GCP, and Azure all use 169.254.169.254.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return fmt.Errorf("ssrf: cloud metadata address %s blocked", ip)
	}

	// Link-local — always blocked (includes metadata range).
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("ssrf: link-local address %s blocked", ip)
	}

	// Multicast — always blocked.
	if ip.IsMulticast() {
		return fmt.Errorf("ssrf: multicast address %s blocked", ip)
	}

	// Unspecified (0.0.0.0, ::) — always blocked.
	if ip.IsUnspecified() {
		return fmt.Errorf("ssrf: unspecified address %s blocked", ip)
	}

	// Private and loopback — blocked unless AllowPrivateRanges.
	if !allowPrivate {
		if ip.IsLoopback() {
			return fmt.Errorf("ssrf: loopback address %s blocked", ip)
		}
		if ip.IsPrivate() {
			return fmt.Errorf("ssrf: private address %s blocked", ip)
		}
	}

	return nil
}
