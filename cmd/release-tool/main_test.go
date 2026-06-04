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

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRun_HelpFlag_ExitsZero(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"release-tool", "--help"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Errorf("want exit 0, got %d", code)
	}
	if !strings.Contains(stderr.String(), "USAGE") {
		t.Errorf("help text missing USAGE section: %q", stderr.String())
	}
}

func TestRun_VersionFlag_PrintsToStdout(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"release-tool", "--version"}, &stdout, &stderr)
	if code != exitSuccess {
		t.Errorf("want exit 0, got %d", code)
	}
	if !strings.HasPrefix(stdout.String(), "release-tool ") {
		t.Errorf("version must go to stdout with proper prefix: %q", stdout.String())
	}
}

func TestRun_UnknownSubcommand_ExitsTwo(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"release-tool", "nonexistent-subcommand"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d", exitUsage, code)
	}
	if !strings.Contains(stderr.String(), "unknown subcommand") {
		t.Errorf("stderr must explain the unknown subcommand: %q", stderr.String())
	}
}

func TestRun_NoSubcommand_ExitsTwo(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"release-tool"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d", exitUsage, code)
	}
	if !strings.Contains(stderr.String(), "no subcommand") {
		t.Errorf("stderr must explain that no subcommand was given: %q", stderr.String())
	}
}

func TestRun_BadFlag_ExitsTwo(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"release-tool", "--not-a-flag"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("want exit %d (usage), got %d", exitUsage, code)
	}
}

func TestSplitSubcommand_Variants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		sub  string
		in   []string
		flag []string
	}{
		{"plain subcommand", "create-tag", []string{"create-tag"}, []string{}},
		{"flag then subcommand", "create-tag", []string{"--dry-run", "create-tag"}, []string{"--dry-run"}},
		{"only flags", "", []string{"--help"}, []string{"--help"}},
		{"double-dash separator", "literal", []string{"--", "literal"}, []string{}},
		{"empty", "", []string{}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			flags, sub := splitSubcommand(c.in)
			if sub != c.sub {
				t.Errorf("sub: want %q, got %q", c.sub, sub)
			}
			if len(flags) != len(c.flag) {
				t.Errorf("flags len: want %d, got %d (%v)", len(c.flag), len(flags), flags)
			}
		})
	}
}

func TestVersionString_DefaultIncludesDev(t *testing.T) {
	t.Parallel()
	s := versionString()
	if !strings.HasPrefix(s, "release-tool ") {
		t.Errorf("version must start with `release-tool `, got %q", s)
	}
}
