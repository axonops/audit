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

package gitstatus_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/gitstatus"
)

func TestParse_HappyPath_TwoModified(t *testing.T) {
	t.Parallel()
	input := "M  go.mod\x00M  webhook/go.mod\x00"
	got, err := gitstatus.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0].Status != "M " || got[0].Path != "go.mod" {
		t.Errorf("entry 0: %+v", got[0])
	}
	if got[1].Status != "M " || got[1].Path != "webhook/go.mod" {
		t.Errorf("entry 1: %+v", got[1])
	}
}

func TestParse_NULInFilename(t *testing.T) {
	t.Parallel()
	// A NUL inside a filename can't actually occur on POSIX FS, but
	// the parser must treat any 0x00 as the record terminator and
	// not try to interpret embedded ones.
	input := "M  foo\x00M  bar\x00"
	got, err := gitstatus.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 entries, got %d", len(got))
	}
}

func TestParse_CRLFInFilename(t *testing.T) {
	t.Parallel()
	// CRLF in filenames is rare but legal. The parser must NOT split
	// records on newlines.
	input := "M  weird\r\nname/go.mod\x00"
	got, err := gitstatus.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if got[0].Path != "weird\r\nname/go.mod" {
		t.Errorf("CRLF stripped: %q", got[0].Path)
	}
}

func TestParse_RenameWithOldPath(t *testing.T) {
	t.Parallel()
	// Rename record: "RX new\0old\0"
	input := "R  new/go.mod\x00old/go.mod\x00"
	got, err := gitstatus.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 entry, got %d", len(got))
	}
	if !got[0].IsRename() {
		t.Error("must be a rename")
	}
	if got[0].Path != "new/go.mod" || got[0].OldPath != "old/go.mod" {
		t.Errorf("rename paths wrong: %+v", got[0])
	}
}

func TestParse_UnicodeFilename(t *testing.T) {
	t.Parallel()
	input := "M  sécréts/go.mod\x00M  日本/go.sum\x00"
	got, err := gitstatus.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[0].Path != "sécréts/go.mod" {
		t.Errorf("unicode path 0: %q", got[0].Path)
	}
	if got[1].Path != "日本/go.sum" {
		t.Errorf("unicode path 1: %q", got[1].Path)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	t.Parallel()
	got, err := gitstatus.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty input must yield zero entries, got %d", len(got))
	}
}

func TestParse_TrailingNULOnly(t *testing.T) {
	t.Parallel()
	got, err := gitstatus.Parse(strings.NewReader("\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("lone NUL must yield zero entries, got %d", len(got))
	}
}

func TestParse_NilReader(t *testing.T) {
	t.Parallel()
	_, err := gitstatus.Parse(nil)
	if err == nil {
		t.Error("nil reader must produce an error")
	}
}

func TestParse_MalformedShortRecord(t *testing.T) {
	t.Parallel()
	// Two bytes, no path — invalid porcelain.
	_, err := gitstatus.Parse(bytes.NewReader([]byte("M\x00")))
	if err == nil {
		t.Error("short record must produce an error")
	}
}

func TestParse_TruncatedAfterStatus(t *testing.T) {
	t.Parallel()
	// "M  foo" with NO terminating NUL — unexpected EOF.
	_, err := gitstatus.Parse(strings.NewReader("M  foo"))
	if err == nil {
		t.Error("truncated record must produce an error")
	}
}
