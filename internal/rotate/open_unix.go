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

//go:build unix

package rotate

import (
	"fmt"
	"os"
	"syscall"
)

// safeOpen opens a file with O_NOFOLLOW to prevent following symlinks,
// then enforces the configured permissions via Chmod on the file
// descriptor.
func safeOpen(name string, flag int, mode os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(name, flag|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, fmt.Errorf("rotate: open %q: %w", name, err)
	}

	// Enforce configured permissions on every open — even for existing
	// files that may have been created with different permissions.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close() // close on error path
		return nil, fmt.Errorf("rotate: chmod %q: %w", name, err)
	}

	return f, nil
}

// safeStat stats a file, rejecting symlinks.
func safeStat(name string) (os.FileInfo, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err //nolint:wrapcheck // callers depend on os.IsNotExist matching
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("rotate: %q is a symlink", name)
	}
	return info, nil
}
