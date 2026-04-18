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

// Internal tests for ssrf.go package-level variables initialised via
// [mustParseCIDR] and [mustParseIP]. Lives in package audit so it can
// observe the unexported cgnatBlock / deprecatedSiteLocalBlock /
// awsIPv6MetadataIP symbols directly (#488).

package audit

import (
	"net"
	"strings"
	"testing"
)

// TestSSRFInit_CGNATBlockNotNil asserts that the CGNAT block variable
// was populated at init. If mustParseCIDR were ever to silently fail
// (for example after a future stdlib regression) and the init fell
// back to a nil *net.IPNet, every SSRF check would nil-deref on
// cgnatBlock.Contains. The mustParseCIDR wrapper panics at load
// instead, but this test guards against a refactor that re-introduces
// the silent-failure pattern (#488).
func TestSSRFInit_CGNATBlockNotNil(t *testing.T) {
	t.Parallel()
	if cgnatBlock == nil {
		t.Fatal("cgnatBlock is nil — init failed silently")
	}
	// Sanity: 100.64.0.1 lies inside 100.64.0.0/10.
	if !cgnatBlock.Contains(net.ParseIP("100.64.0.1")) {
		t.Fatal("cgnatBlock does not contain 100.64.0.1 — wrong CIDR parsed")
	}
	// Sanity: 10.0.0.1 lies outside.
	if cgnatBlock.Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("cgnatBlock unexpectedly contains 10.0.0.1")
	}
}

// TestSSRFInit_DeprecatedSiteLocalBlockNotNil is the companion guard
// for the fec0::/10 block, which shares the same mustParseCIDR
// wrapper (#488).
func TestSSRFInit_DeprecatedSiteLocalBlockNotNil(t *testing.T) {
	t.Parallel()
	if deprecatedSiteLocalBlock == nil {
		t.Fatal("deprecatedSiteLocalBlock is nil — init failed silently")
	}
	if !deprecatedSiteLocalBlock.Contains(net.ParseIP("fec0::1")) {
		t.Fatal("deprecatedSiteLocalBlock does not contain fec0::1")
	}
	if deprecatedSiteLocalBlock.Contains(net.ParseIP("fc00::1")) {
		t.Fatal("deprecatedSiteLocalBlock unexpectedly contains fc00::1")
	}
}

// TestSSRFInit_AWSIPv6MetadataIPNotNil is the companion guard for the
// AWS IPv6 IMDS endpoint, initialised via [mustParseIP] (#488).
func TestSSRFInit_AWSIPv6MetadataIPNotNil(t *testing.T) {
	t.Parallel()
	if awsIPv6MetadataIP == nil {
		t.Fatal("awsIPv6MetadataIP is nil — init failed silently")
	}
	if !awsIPv6MetadataIP.Equal(net.ParseIP("fd00:ec2::254")) {
		t.Fatalf("awsIPv6MetadataIP = %v; want fd00:ec2::254", awsIPv6MetadataIP)
	}
}

// TestMustParseCIDR_PanicsOnInvalid verifies the wrapper panics on a
// malformed literal so a future edit that breaks a CIDR constant
// fails at package load rather than silently nil-deref'ing on every
// SSRF check (#488).
func TestMustParseCIDR_PanicsOnInvalid(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("mustParseCIDR did not panic on invalid input")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("mustParseCIDR panic value type = %T; want string", r)
		}
		const want = "audit: SSRF init: failed to parse hardcoded CIDR"
		if !strings.Contains(msg, want) {
			t.Fatalf("mustParseCIDR panic %q does not contain %q", msg, want)
		}
	}()
	mustParseCIDR("not-a-cidr")
}

// TestMustParseIP_PanicsOnInvalid is the companion for [mustParseIP].
func TestMustParseIP_PanicsOnInvalid(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("mustParseIP did not panic on invalid input")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("mustParseIP panic value type = %T; want string", r)
		}
		const want = "audit: SSRF init: failed to parse hardcoded IP"
		if !strings.Contains(msg, want) {
			t.Fatalf("mustParseIP panic %q does not contain %q", msg, want)
		}
	}()
	mustParseIP("not-an-ip")
}
