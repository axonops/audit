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

// Package gitstatus parses the NUL-delimited output of
// `git status -z --porcelain --untracked-files=no`.
//
// The bash version of this parser (#907) captured the porcelain via
// shell command substitution (`var=$(git status -z ...)`), which
// silently strips NUL bytes. With 35 staged files that produced the
// single garbled record `M go.modM webhook/go.modM ...` and the
// release flow opened an empty commit. This package consumes an
// `io.Reader` directly and never round-trips through a stringly-
// typed variable.
//
// Each parsed [Entry] carries the raw XY status pair (per Porcelain
// v1 — `git status` man page) plus the typed path. Renames carry an
// extra OldPath field.
package gitstatus

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// Entry is one porcelain record.
type Entry struct {
	// Status is the two-byte XY status code (e.g. "M ", " M", "RM").
	Status string
	// Path is the current path. For renames, this is the new name.
	Path string
	// OldPath is set only for rename / copy records (Status starts
	// with 'R' or 'C'); empty otherwise.
	OldPath string
}

// IsRename reports whether the entry is a rename or copy record.
func (e Entry) IsRename() bool {
	if e.Status == "" {
		return false
	}
	return e.Status[0] == 'R' || e.Status[0] == 'C'
}

// Parse reads NUL-delimited porcelain output from r and returns the
// typed entries. Rename / copy records are recognised and OldPath is
// populated. Returns an error if the stream ends mid-record or if any
// record is malformed (status shorter than 3 bytes including the
// `XY space` triple).
func Parse(r io.Reader) ([]Entry, error) {
	if r == nil {
		return nil, errors.New("gitstatus: nil reader")
	}
	// Each record is "XY path\0", except renames which emit
	// "RX new\0old\0". The records are NUL-separated; the standard
	// trick is bufio.Scanner with a split function.
	br := bufio.NewReader(r)
	var out []Entry
	for {
		rec, err := readUntilNUL(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gitstatus: read record: %w", err)
		}
		if rec == "" {
			// Empty record — trailing NUL after the final entry, or
			// an empty stream. Either way, stop cleanly.
			break
		}
		if len(rec) < 3 {
			return nil, fmt.Errorf("gitstatus: malformed record %q (need XY<space>path)", rec)
		}
		entry := Entry{
			Status: rec[:2],
			Path:   rec[3:],
		}
		if entry.IsRename() {
			// The next NUL-delimited record is the old path.
			oldPath, err := readUntilNUL(br)
			if err != nil {
				return nil, fmt.Errorf("gitstatus: read rename old-path: %w", err)
			}
			entry.OldPath = oldPath
		}
		out = append(out, entry)
	}
	return out, nil
}

// readUntilNUL reads bytes from r up to (and consuming) the next NUL
// byte. Returns the bytes before the NUL as a string. On stream end
// before any byte is read, returns io.EOF. On stream end after some
// bytes but before a NUL, returns io.ErrUnexpectedEOF.
func readUntilNUL(br *bufio.Reader) (string, error) {
	bs, err := br.ReadBytes(0x00)
	if err != nil {
		if errors.Is(err, io.EOF) && len(bs) == 0 {
			return "", io.EOF
		}
		if errors.Is(err, io.EOF) {
			return "", io.ErrUnexpectedEOF
		}
		return "", fmt.Errorf("gitstatus: read: %w", err)
	}
	// Trim the trailing NUL.
	return string(bs[:len(bs)-1]), nil
}
