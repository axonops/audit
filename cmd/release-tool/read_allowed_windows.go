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

import "errors"

// readAllowedFile on Windows: release-tool is a Linux-only release
// automation binary. The release workflow runs on ubuntu-latest;
// no path in the release flow reads files on Windows. We keep the
// build green on windows-latest by surfacing an explicit
// unsupported error rather than silently bypassing the O_NOFOLLOW
// guarantee — a Windows operator who somehow runs this would get
// an immediate refusal, not a security-degraded read.
//
// If we ever need Windows support, replace this stub with a
// CreateFile call using FILE_FLAG_OPEN_REPARSE_POINT and an
// explicit reparse-tag check. Until then: refuse.
func readAllowedFile(_, _ string) ([]byte, error) {
	return nil, errors.New("readAllowedFile: release-tool's symlink-safe path-read is not implemented on Windows; run the release flow on Linux")
}
