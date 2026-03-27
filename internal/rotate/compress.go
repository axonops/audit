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

package rotate

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
)

// compressFile gzip-compresses src into dst with the given file mode.
// Both source and destination paths are checked for symlinks via
// [safeStat] and [safeOpen] to prevent symlink-based redirection
// attacks on backup files.
//
// On success the source file is removed. On failure any partial
// destination file is removed and the source is left intact.
func compressFile(src, dst string, mode os.FileMode) error {
	// Reject symlinks on the source path before reading.
	if _, err := safeStat(src); err != nil {
		return fmt.Errorf("rotate: compress source %q: %w", src, err)
	}

	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("rotate: compress open source %q: %w", src, err)
	}
	defer in.Close() //nolint:errcheck // read-only

	// Use safeOpen for the destination to enforce symlink protection
	// and configured permissions.
	out, err := safeOpen(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("rotate: compress create dest %q: %w", dst, err)
	}

	gz := gzip.NewWriter(out)

	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()  //nolint:errcheck // error path
		out.Close() //nolint:errcheck // error path
		os.Remove(dst)
		return fmt.Errorf("rotate: compress copy: %w", err)
	}

	if err := gz.Close(); err != nil {
		out.Close() //nolint:errcheck // error path
		os.Remove(dst)
		return fmt.Errorf("rotate: compress gzip close: %w", err)
	}

	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("rotate: compress close dest: %w", err)
	}

	if err := os.Remove(src); err != nil {
		return fmt.Errorf("rotate: compress remove source %q: %w", src, err)
	}

	return nil
}
