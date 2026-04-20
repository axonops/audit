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

//go:build linux

package iouring

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// skipIfKernelBelow skips t if the running kernel is below the
// given major.minor. Pattern borrowed from giouring's kernel.go.
// Tests that require a specific kernel feature call this first.
func skipIfKernelBelow(t *testing.T, major, minor int) {
	t.Helper()
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		t.Skipf("skipIfKernelBelow: uname failed: %v", err)
		return
	}
	release := unameToString(unameField(unsafe.Pointer(&uname.Release)))
	rmajor, rminor, ok := parseKernelVersion(release)
	if !ok {
		t.Skipf("skipIfKernelBelow: cannot parse release %q", release)
		return
	}
	if rmajor < major || (rmajor == major && rminor < minor) {
		t.Skipf("skipIfKernelBelow: kernel %d.%d < required %d.%d", rmajor, rminor, major, minor)
	}
}

// unameToString converts a [syscall.Utsname] Release (or similar)
// field into a Go string. The field is NUL-terminated and is typed
// as either [N]int8 (linux/amd64) or [N]uint8 (linux/arm64); we
// use an unsafe.Slice over the underlying byte bits to avoid per-
// arch build tags.
func unameToString(field *[65]byte) string {
	// The caller casts whatever architecture-specific type it has
	// into a *[65]byte via unsafe.Pointer. We read up to the first
	// NUL terminator.
	n := 0
	for n < len(field) && field[n] != 0 {
		n++
	}
	return string(field[:n])
}

// unameField provides a portable view of a [65]int8 or [65]uint8
// field as a byte array via unsafe reinterpretation.
func unameField(arr unsafe.Pointer) *[65]byte {
	return (*[65]byte)(arr)
}

// parseKernelVersion parses a "major.minor..." release string such
// as "5.15.0-89-generic" into (major, minor, true). Returns false
// on parse failure.
func parseKernelVersion(release string) (major, minor int, ok bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	// Strip any non-digit suffix on the minor part.
	minorStr := parts[1]
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err = strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// TestParseKernelVersion exercises the parser directly so the helper
// itself has coverage.
func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		in            string
		major, minor  int
		ok            bool
	}{
		{"5.15.0-89-generic", 5, 15, true},
		{"6.1.0", 6, 1, true},
		{"5.4", 5, 4, true},
		{"5.4.0-rc1", 5, 4, true},
		{"5", 0, 0, false},
		{"", 0, 0, false},
		{"not-a-version", 0, 0, false},
	}
	for _, tc := range cases {
		major, minor, ok := parseKernelVersion(tc.in)
		if ok != tc.ok || major != tc.major || minor != tc.minor {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tc.in, major, minor, ok, tc.major, tc.minor, tc.ok)
		}
	}
}
