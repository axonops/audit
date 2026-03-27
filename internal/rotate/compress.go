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

// gzipCopy reads from src and writes gzip-compressed data to dst.
// It closes the gzip writer but does not close src or dst.
func gzipCopy(dst io.Writer, src io.Reader) error {
	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		gz.Close() //nolint:errcheck // error path
		return fmt.Errorf("rotate: compress copy: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("rotate: compress gzip close: %w", err)
	}
	return nil
}

// compressFile gzip-compresses src into dst with the given file mode.
// Both source and destination paths are checked for symlinks via
// [safeStat] and [safeOpen] to prevent symlink-based redirection
// attacks on backup files.
//
// On success the source file is removed. On failure any partial
// destination file is removed and the source is left intact.
func compressFile(src, dst string, mode os.FileMode) error {
	// Use safeOpen for the source to enforce O_NOFOLLOW on Unix,
	// preventing a TOCTOU race between stat and open.
	in, err := safeOpen(src, os.O_RDONLY, mode)
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

	if copyErr := gzipCopy(out, in); copyErr != nil {
		out.Close()    //nolint:errcheck // error path
		os.Remove(dst) //nolint:errcheck // best-effort cleanup of partial dest on error path
		return copyErr
	}

	if closeErr := out.Close(); closeErr != nil {
		os.Remove(dst) //nolint:errcheck // best-effort cleanup of partial dest on error path
		return fmt.Errorf("rotate: compress close dest: %w", closeErr)
	}

	if err := os.Remove(src); err != nil {
		return fmt.Errorf("rotate: compress remove source %q: %w", src, err)
	}

	return nil
}
