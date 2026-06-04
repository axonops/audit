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

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readAllowedFile opens an already-allowlisted path with O_NOFOLLOW
// and reads its full contents. This collapses the lstat + open dance
// into a single syscall, closing the TOCTOU window where an
// attacker could swap the regular file for a symlink between the
// lstat and the read (#910 threat-model B2).
//
// The error returns errSymlinkRefused when the operating system
// refuses to traverse the final path component because it is a
// symlink. Linux and Darwin both surface this as syscall.ELOOP;
// the predicate isSymlinkOpenError checks for it explicitly.
// Defence in depth: even if a future BSD kernel returned a
// different errno, the path drops through to "open: %w" and the
// caller exits operational — no commit is sent.
func readAllowedFile(workdir, path string) ([]byte, error) {
	full := filepath.Join(workdir, path)
	// O_NOFOLLOW on the final component is the kernel-level
	// guarantee. O_RDONLY because we never mutate; mode 0 because
	// we never create.
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // path is allowlist-screened above
	if err != nil {
		if isSymlinkOpenError(err) {
			return nil, errSymlinkRefused
		}
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Defence in depth: stat the open fd and refuse anything that
	// is not a regular file (sockets, FIFOs, devices). O_NOFOLLOW
	// already refuses symlinks; this catches everything else the
	// allowlist might inadvertently let through if the path
	// happens to be a special file.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file (mode=%v)", info.Mode())
	}

	body, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return body, nil
}

// isSymlinkOpenError reports whether err looks like an
// O_NOFOLLOW-rejected symlink (ELOOP on Linux/macOS).
func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}
