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

//go:build !unix

package rotate

import (
	"fmt"
	"os"
)

// safeOpen opens a file after checking that the path is not a symlink.
// On non-Unix platforms O_NOFOLLOW is unavailable, so we fall back to
// an Lstat check. This is best-effort: a TOCTOU window exists between
// the Lstat and OpenFile calls. On Unix, O_NOFOLLOW closes this window
// atomically.
func safeOpen(name string, flag int, mode os.FileMode) (*os.File, error) {
	if _, err := safeStat(name); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	f, err := os.OpenFile(name, flag, mode)
	if err != nil {
		return nil, fmt.Errorf("rotate: open %q: %w", name, err)
	}

	// Enforce configured permissions — mirrors the Unix safeOpen behaviour.
	if err := f.Chmod(mode); err != nil {
		_ = f.Close() //nolint:errcheck // close on error path
		return nil, fmt.Errorf("rotate: chmod %q: %w", name, err)
	}

	return f, nil
}

// safeStat stats a file, rejecting symlinks via Lstat.
func safeStat(name string) (os.FileInfo, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("rotate: %q is a symlink", name)
	}
	return info, nil
}
