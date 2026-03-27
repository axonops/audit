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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// mill signals the mill goroutine to run a cleanup cycle.
func (w *Writer) mill() {
	w.millOnce.Do(func() {
		w.millCh = make(chan struct{}, 1)
		w.millDone = make(chan struct{})
		go w.millRun()
	})
	select {
	case w.millCh <- struct{}{}:
	default:
	}
}

// millRun is the background goroutine that processes cleanup signals.
func (w *Writer) millRun() {
	defer close(w.millDone)
	for range w.millCh {
		w.millRunOnce()
	}
}

// millRunOnce performs a single cleanup pass: compress, enforce
// MaxBackups, enforce MaxAge.
func (w *Writer) millRunOnce() {
	files, err := w.oldLogFiles()
	if err != nil {
		w.reportError(err)
		return
	}

	if w.cfg.Compress {
		files = w.millCompress(files)
	}

	w.millEnforceMaxBackups(files)
	w.millEnforceMaxAge(files)
}

// millCompress compresses uncompressed backups and returns the
// refreshed file list.
func (w *Writer) millCompress(files []os.DirEntry) []os.DirEntry {
	for _, f := range files {
		if strings.HasSuffix(f.Name(), w.ext+".gz") {
			continue
		}
		src := filepath.Join(w.dir, f.Name())
		dst := src + ".gz"
		if compressErr := compressFile(src, dst, w.cfg.Mode); compressErr != nil {
			w.reportError(fmt.Errorf("rotate: compress backup %q: %w", f.Name(), compressErr))
			continue
		}
	}
	// Re-read after compression to get updated file list.
	refreshed, readErr := w.oldLogFiles()
	if readErr != nil {
		w.reportError(readErr)
		return nil
	}
	return refreshed
}

// millEnforceMaxBackups removes excess backups beyond the configured limit.
func (w *Writer) millEnforceMaxBackups(files []os.DirEntry) {
	if w.cfg.MaxBackups <= 0 || len(files) <= w.cfg.MaxBackups {
		return
	}
	for _, f := range files[w.cfg.MaxBackups:] {
		if removeErr := os.Remove(filepath.Join(w.dir, f.Name())); removeErr != nil {
			w.reportError(fmt.Errorf("rotate: remove excess backup %q: %w", f.Name(), removeErr))
		}
	}
}

// millEnforceMaxAge removes backups older than the configured age limit.
func (w *Writer) millEnforceMaxAge(files []os.DirEntry) {
	if w.cfg.MaxAge <= 0 {
		return
	}
	cutoff := w.now().Add(-w.cfg.MaxAge)
	for _, f := range files {
		ts, ok := w.parseTimestamp(f.Name())
		if !ok {
			continue
		}
		if ts.Before(cutoff) {
			if removeErr := os.Remove(filepath.Join(w.dir, f.Name())); removeErr != nil {
				w.reportError(fmt.Errorf("rotate: remove expired backup %q: %w", f.Name(), removeErr))
			}
		}
	}
}

// backupName generates a unique timestamped backup filename. If the
// base name already exists (same-millisecond collision), a counter
// suffix is appended: name-1.ext, name-2.ext, etc. Returns an error
// if no free name can be found after 1000 attempts.
func (w *Writer) backupName(t time.Time) (string, error) {
	ts := t.Format("2006-01-02T15-04-05.000")
	base := filepath.Join(w.dir, w.prefix+ts)

	// Try without counter first (common case).
	name := base + w.ext
	if _, err := os.Lstat(name); os.IsNotExist(err) {
		return name, nil
	}

	// Collision — append counter suffix.
	for i := 1; i < 1000; i++ {
		name = fmt.Sprintf("%s-%d%s", base, i, w.ext)
		if _, err := os.Lstat(name); os.IsNotExist(err) {
			return name, nil
		}
	}

	return "", fmt.Errorf("rotate: backup name collision limit exceeded for %s", base+w.ext)
}

// oldLogFiles returns all backup files in the directory sorted by
// timestamp descending (newest first).
func (w *Writer) oldLogFiles() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("rotate: read dir %q: %w", w.dir, err)
	}

	backups := make([]os.DirEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, w.prefix) {
			continue
		}
		// Must end with our extension or extension.gz
		if !strings.HasSuffix(name, w.ext) && !strings.HasSuffix(name, w.ext+".gz") {
			continue
		}
		if _, ok := w.parseTimestamp(name); !ok {
			continue
		}
		backups = append(backups, e)
	}

	// Sort newest first.
	sort.Slice(backups, func(i, j int) bool {
		ti, _ := w.parseTimestamp(backups[i].Name())
		tj, _ := w.parseTimestamp(backups[j].Name())
		return ti.After(tj)
	})

	return backups, nil
}

// parseTimestamp extracts the timestamp from a backup filename.
// It handles optional collision counter suffixes: name-1.ext, name-2.ext.
func (w *Writer) parseTimestamp(name string) (time.Time, bool) {
	// Strip .gz suffix if present.
	name = strings.TrimSuffix(name, ".gz")
	// Strip extension.
	name = strings.TrimSuffix(name, w.ext)
	// Strip prefix.
	name = strings.TrimPrefix(name, w.prefix)

	// Strip optional collision counter suffix: "-1", "-2", etc.
	// The timestamp ends with ".000" (milliseconds), so the last
	// hyphen after that is the counter separator.
	if idx := strings.LastIndex(name, "-"); idx > 0 {
		if isDigits(name[idx+1:]) {
			name = name[:idx]
		}
	}

	t, err := time.Parse("2006-01-02T15-04-05.000", name)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// isDigits reports whether s is a non-empty string of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
