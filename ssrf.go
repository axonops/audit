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

package audit

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// mustParseCIDR parses a hardcoded CIDR literal and panics at init if
// the parse fails. The input strings below are package constants —
// a parse failure indicates a corrupted source constant (or an
// unexpected stdlib regression), not a runtime input, so failing
// loudly at package load is safer than a silent nil-deref on every
// SSRF check later (#488).
func mustParseCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("audit: SSRF init: failed to parse hardcoded CIDR " + cidr + ": " + err.Error())
	}
	return n
}

// mustParseIP parses a hardcoded IP literal and panics at init if the
// parse fails. Same rationale as [mustParseCIDR] (#488).
func mustParseIP(ip string) net.IP {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic("audit: SSRF init: failed to parse hardcoded IP " + ip)
	}
	return parsed
}

// cgnatBlock is the RFC 6598 Shared Address Space (100.64.0.0/10),
// used by CGNAT and some cloud providers for internal routing.
// Always blocked regardless of AllowPrivateRanges.
var cgnatBlock = mustParseCIDR("100.64.0.0/10")

// deprecatedSiteLocalBlock is RFC 3513 site-local IPv6 (fec0::/10).
// RFC 3879 deprecated this range, but some legacy stacks still route
// it — Go's net.IP.IsPrivate() does NOT classify it, so we block it
// explicitly. Always blocked regardless of AllowPrivateRanges.
var deprecatedSiteLocalBlock = mustParseCIDR("fec0::/10")

// awsIPv6MetadataIP is the AWS IMDSv2 over-IPv6 endpoint, documented
// at https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html.
// An explicit Equal check is required (not relying on IsPrivate) so
// AllowPrivateRanges cannot open a metadata-exfiltration hole.
var awsIPv6MetadataIP = mustParseIP("fd00:ec2::254")

// Azure IPv6 IMDS is not yet blocked: no authoritative Microsoft
// Learn citation was identified during #480. Tracked in #643;
// shipping an unverified literal would imply coverage we don't have.

// SSRFOption configures SSRF protection behaviour for
// [NewSSRFDialControl].
type SSRFOption func(*ssrfConfig)

type ssrfConfig struct {
	allowPrivate bool
}

// AllowPrivateRanges permits connections to RFC 1918 private address
// ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv6 ULA
// (fc00::/7), and loopback (127.0.0.0/8, ::1). This is intended for
// private network deployments where output receivers run on internal
// infrastructure, and for testing with [net/http/httptest] which binds
// to 127.0.0.1.
//
// Cloud metadata (169.254.169.254, fd00:ec2::254), RFC 6598 Shared
// Address Space (100.64.0.0/10, CGNAT), and deprecated site-local
// IPv6 (fec0::/10) remain blocked even when private ranges are
// allowed.
func AllowPrivateRanges() SSRFOption {
	return func(c *ssrfConfig) {
		c.allowPrivate = true
	}
}

// SSRFReason identifies the classification that caused an address to
// be blocked by SSRF protection. String values are stable and
// suitable for metric-label use.
type SSRFReason string

// SSRFReason constants. String values are stable for use as metric
// labels (snake_case per Prometheus convention).
const (
	// SSRFReasonCloudMetadata — a published cloud instance metadata
	// endpoint (AWS IMDS at 169.254.169.254, AWS IMDSv2 over IPv6 at
	// fd00:ec2::254). Blocked even when [AllowPrivateRanges] is set.
	SSRFReasonCloudMetadata SSRFReason = "cloud_metadata"

	// SSRFReasonCGNAT — RFC 6598 Shared Address Space (100.64.0.0/10).
	// Used by CGNAT and some cloud providers for internal routing.
	// Blocked even when [AllowPrivateRanges] is set.
	SSRFReasonCGNAT SSRFReason = "cgnat"

	// SSRFReasonDeprecatedSiteLocal — deprecated RFC 3513 IPv6
	// site-local range (fec0::/10). Not classified by Go's
	// [net.IP.IsPrivate]; blocked explicitly. Always blocked.
	SSRFReasonDeprecatedSiteLocal SSRFReason = "deprecated_site_local"

	// SSRFReasonLinkLocal — IPv4 169.254.0.0/16 or IPv6 fe80::/10.
	// Always blocked.
	SSRFReasonLinkLocal SSRFReason = "link_local"

	// SSRFReasonMulticast — IPv4 224.0.0.0/4 or IPv6 ff00::/8.
	// Always blocked.
	SSRFReasonMulticast SSRFReason = "multicast"

	// SSRFReasonUnspecified — 0.0.0.0 or ::. Always blocked.
	SSRFReasonUnspecified SSRFReason = "unspecified"

	// SSRFReasonLoopback — 127.0.0.0/8 or ::1. Blocked unless
	// [AllowPrivateRanges] is set.
	SSRFReasonLoopback SSRFReason = "loopback"

	// SSRFReasonPrivate — RFC 1918 private ranges or IPv6 ULA
	// (fc00::/7). Blocked unless [AllowPrivateRanges] is set.
	SSRFReasonPrivate SSRFReason = "private"
)

// SSRFBlockedError is returned by [CheckSSRFIP] and
// [CheckSSRFAddress] when an address matches the SSRF block list.
// It wraps [ErrSSRFBlocked] for broad discrimination via [errors.Is]
// and exposes structured fields for per-reason metrics via
// [errors.As]:
//
//	var ssrfErr *audit.SSRFBlockedError
//	if errors.As(err, &ssrfErr) {
//	    metricSSRFBlocked.With("reason", string(ssrfErr.Reason)).Inc()
//	    log.Warn("blocked", "ip", ssrfErr.IP, "reason", ssrfErr.Reason)
//	}
type SSRFBlockedError struct {
	// IP is the address that was blocked. Uses [netip.Addr] (not
	// [net.IP]) for value-comparable, zero-alloc semantics —
	// mutating it is impossible.
	IP netip.Addr

	// Reason classifies why the address was blocked. Stable string
	// value; suitable for use as a metric label.
	Reason SSRFReason

	// wrapped pre-allocates the error slice returned by Unwrap to
	// avoid per-Unwrap heap allocation.
	wrapped [1]error

	msg string
}

// Error returns the human-readable error message. The text is
// identical to the pre-typed-error format for backwards
// compatibility.
func (e *SSRFBlockedError) Error() string { return e.msg }

// Unwrap returns [ErrSSRFBlocked] so [errors.Is] matches the
// sentinel. Returns a slice to match the [errors.Join] contract and
// to mirror [ValidationError]'s shape for consistency.
func (e *SSRFBlockedError) Unwrap() []error {
	return e.wrapped[:]
}

// newSSRFBlockedError constructs an [SSRFBlockedError] with the given
// IP, reason, and pre-formatted message.
func newSSRFBlockedError(ip net.IP, reason SSRFReason, format string, args ...any) *SSRFBlockedError {
	addr, _ := netip.AddrFromSlice(ip)
	addr = addr.Unmap() // normalise ::ffff:v4 → v4 for stable display
	e := &SSRFBlockedError{
		IP:     addr,
		Reason: reason,
		msg:    fmt.Sprintf(format, args...),
	}
	e.wrapped[0] = ErrSSRFBlocked
	return e
}

// NewSSRFDialControl returns a [net.Dialer] Control function that
// checks every resolved IP address before a connection is established.
// Use it with [net/http.Transport]:
//
//	transport := &http.Transport{
//	    DialContext: (&net.Dialer{
//	        Control: audit.NewSSRFDialControl(),
//	    }).DialContext,
//	}
//
// The Control function blocks connections to:
//   - Loopback addresses (127.0.0.0/8, ::1)
//   - Link-local addresses (169.254.0.0/16, fe80::/10)
//   - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
//   - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - IPv6 unique local addresses (fc00::/7)
//   - RFC 6598 Shared Address Space (100.64.0.0/10, CGNAT)
//   - Deprecated IPv6 site-local (fec0::/10)
//   - Multicast addresses (224.0.0.0/4, ff00::/8)
//   - Unspecified addresses (0.0.0.0, ::)
//   - IPv4-mapped IPv6 forms of all of the above (e.g.
//     ::ffff:10.0.0.1 is treated as 10.0.0.1).
//
// Returned errors are [*SSRFBlockedError] (wrapping [ErrSSRFBlocked]).
//
// Use [AllowPrivateRanges] to permit private and loopback addresses.
func NewSSRFDialControl(opts ...SSRFOption) func(string, string, syscall.RawConn) error {
	cfg := &ssrfConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return func(_, address string, _ syscall.RawConn) error {
		return CheckSSRFAddress(address, cfg.allowPrivate)
	}
}

// CheckSSRFAddress validates that a resolved address is not blocked by
// SSRF policy. The address must be in host:port format.
//
// On rejection, returns [*SSRFBlockedError] wrapping
// [ErrSSRFBlocked]. Parse errors (bad address format, unparseable IP)
// return plain errors and do NOT wrap [ErrSSRFBlocked].
func CheckSSRFAddress(address string, allowPrivate bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("audit: ssrf: invalid address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("audit: ssrf: could not parse IP %q", host)
	}

	return CheckSSRFIP(ip, allowPrivate)
}

// CheckSSRFIP validates that an IP address is not blocked by SSRF
// policy. Exported for direct unit testing of IP classification.
//
// On rejection, returns [*SSRFBlockedError] wrapping
// [ErrSSRFBlocked]. IPv4-mapped IPv6 forms (e.g. ::ffff:10.0.0.1) are
// normalised to their IPv4 equivalent before classification — a
// consumer cannot bypass the block list by bracketing an IPv4
// address as an IPv6 literal.
//
//nolint:gocyclo,cyclop // linear classification chain; splitting reduces readability
func CheckSSRFIP(ip net.IP, allowPrivate bool) error {
	// Normalise IPv4-mapped IPv6 (::ffff:a.b.c.d) to IPv4 before
	// classification. net.IP.Equal already normalises for the
	// metadata literal, but explicit unwrap guards every downstream
	// check (IsPrivate in particular does not cover the mapped form
	// for all cases).
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Cloud metadata IPv4 (AWS IMDS, GCP, Azure, most others) —
	// ALWAYS blocked regardless of config.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return newSSRFBlockedError(ip, SSRFReasonCloudMetadata,
			"audit: ssrf: cloud metadata address %s blocked", ip)
	}

	// Cloud metadata IPv6 (AWS IMDSv2 over IPv6) — ALWAYS blocked.
	// CRITICAL: fd00:ec2::254 is inside fc00::/7 (ULA), which
	// Go's net.IP.IsPrivate() classifies as private. If this Equal
	// check ran AFTER the !allowPrivate branch, setting
	// AllowPrivateRanges(true) would silently open a metadata-exfil
	// hole. Keep this check ABOVE the allowPrivate gate.
	if ip.Equal(awsIPv6MetadataIP) {
		return newSSRFBlockedError(ip, SSRFReasonCloudMetadata,
			"audit: ssrf: cloud metadata address %s blocked", ip)
	}

	// RFC 6598 Shared Address Space (100.64.0.0/10) — ALWAYS blocked.
	// Used by CGNAT and some cloud providers for internal routing.
	if cgnatBlock.Contains(ip) {
		return newSSRFBlockedError(ip, SSRFReasonCGNAT,
			"audit: ssrf: shared address space (RFC 6598) %s blocked", ip)
	}

	// Deprecated IPv6 site-local (fec0::/10) — ALWAYS blocked.
	// Go's IsPrivate() does not classify it; add explicit CIDR check.
	if deprecatedSiteLocalBlock.Contains(ip) {
		return newSSRFBlockedError(ip, SSRFReasonDeprecatedSiteLocal,
			"audit: ssrf: deprecated site-local address %s blocked", ip)
	}

	// Link-local — always blocked (includes metadata range).
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return newSSRFBlockedError(ip, SSRFReasonLinkLocal,
			"audit: ssrf: link-local address %s blocked", ip)
	}

	// Multicast — always blocked.
	if ip.IsMulticast() {
		return newSSRFBlockedError(ip, SSRFReasonMulticast,
			"audit: ssrf: multicast address %s blocked", ip)
	}

	// Unspecified (0.0.0.0, ::) — always blocked.
	if ip.IsUnspecified() {
		return newSSRFBlockedError(ip, SSRFReasonUnspecified,
			"audit: ssrf: unspecified address %s blocked", ip)
	}

	// Private and loopback — blocked unless AllowPrivateRanges.
	if !allowPrivate {
		if ip.IsLoopback() {
			return newSSRFBlockedError(ip, SSRFReasonLoopback,
				"audit: ssrf: loopback address %s blocked", ip)
		}
		if ip.IsPrivate() {
			return newSSRFBlockedError(ip, SSRFReasonPrivate,
				"audit: ssrf: private address %s blocked", ip)
		}
	}

	return nil
}
