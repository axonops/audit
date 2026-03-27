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
		return
	}

	// Compress uncompressed backups if enabled.
	if w.cfg.Compress {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), w.ext+".gz") {
				continue
			}
			src := filepath.Join(w.dir, f.Name())
			dst := src + ".gz"
			if err := compressFile(src, dst, w.cfg.Mode); err != nil {
				continue
			}
		}
		// Re-read after compression to get updated file list.
		files, err = w.oldLogFiles()
		if err != nil {
			return
		}
	}

	// Enforce MaxBackups.
	if w.cfg.MaxBackups > 0 && len(files) > w.cfg.MaxBackups {
		for _, f := range files[w.cfg.MaxBackups:] {
			_ = os.Remove(filepath.Join(w.dir, f.Name())) //nolint:errcheck // best-effort cleanup
		}
	}

	// Enforce MaxAge.
	if w.cfg.MaxAge > 0 {
		cutoff := w.now().Add(-w.cfg.MaxAge)
		for _, f := range files {
			ts, ok := w.parseTimestamp(f.Name())
			if !ok {
				continue
			}
			if ts.Before(cutoff) {
				_ = os.Remove(filepath.Join(w.dir, f.Name())) //nolint:errcheck // best-effort cleanup
			}
		}
	}
}

// backupName generates a timestamped backup filename.
func (w *Writer) backupName(t time.Time) string {
	ts := t.Format("2006-01-02T15-04-05.000")
	return filepath.Join(w.dir, w.prefix+ts+w.ext)
}

// oldLogFiles returns all backup files in the directory sorted by
// timestamp descending (newest first).
func (w *Writer) oldLogFiles() ([]os.DirEntry, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("rotate: read dir %q: %w", w.dir, err)
	}

	var backups []os.DirEntry
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
func (w *Writer) parseTimestamp(name string) (time.Time, bool) {
	// Strip .gz suffix if present.
	name = strings.TrimSuffix(name, ".gz")
	// Strip extension.
	name = strings.TrimSuffix(name, w.ext)
	// Strip prefix.
	name = strings.TrimPrefix(name, w.prefix)

	t, err := time.Parse("2006-01-02T15-04-05.000", name)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
