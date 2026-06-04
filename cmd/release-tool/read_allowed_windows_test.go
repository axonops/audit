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

//go:build windows

package main

import (
	"strings"
	"testing"
)

// TestReadAllowedFile_Windows_ReturnsUnsupported locks the contract
// that the Windows build refuses the symlink-safe read explicitly,
// rather than silently degrading to a follows-symlinks read.
// A Windows operator who somehow runs release-tool must get an
// immediate refusal — not a security-degraded best-effort read.
func TestReadAllowedFile_Windows_ReturnsUnsupported(t *testing.T) {
	t.Parallel()
	_, err := readAllowedFile("workdir", "go.mod")
	if err == nil {
		t.Fatal("Windows readAllowedFile must refuse")
	}
	if !strings.Contains(err.Error(), "not implemented on Windows") {
		t.Errorf("error must name the Windows restriction: %q", err.Error())
	}
}
