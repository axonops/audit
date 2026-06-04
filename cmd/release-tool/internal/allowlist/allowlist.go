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

// Package allowlist enforces the file-path allowlist for
// release-tool's commit-pinned-deps subcommand.
//
// The release flow updates only Go module manifests (go.mod / go.sum)
// across the published module tree. Anything else appearing in the
// staged tree at PR-open time is a bug — either update-deps.sh
// accidentally touched something, a stray artefact leaked in, or a
// caller is trying to abuse the App's commit identity to push
// unauthorised changes. The allowlist refuses to forward those.
//
// The grammar is deliberately narrow: only top-level, first-level, and
// second-level go.mod/go.sum files are permitted. Symlinks are
// rejected outright via [IsSymlink]; expand the allowlist only after
// considering supply-chain implications.
package allowlist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// allowedPatterns is the closed set of file path globs the release
// flow may commit. Order does not matter; matching is single-pass.
var allowedPatterns = []string{
	"go.mod",
	"go.sum",
	"*/go.mod",
	"*/go.sum",
	"*/*/go.mod",
	"*/*/go.sum",
}

// deniedFirstSegments is the set of repo-root subdirectories where
// a go.mod is structurally invalid for the release flow. Even though
// `vendor/go.mod` matches `*/go.mod`, vendor trees are forbidden in
// release commits (the release uses module-graph resolution; vendor
// directories indicate a misconfigured build).
var deniedFirstSegments = map[string]struct{}{
	"vendor":       {},
	".github":      {},
	".git":         {},
	"node_modules": {},
}

// IsAllowed reports whether p (a forward-slash-separated, relative
// path as produced by `git status -z`) is in the allowlist.
//
// p MUST be cleaned (no `.`, `..`, or duplicate separators) — callers
// receive paths directly from git, which guarantees that shape.
// Absolute paths are rejected. Paths containing backslashes are
// rejected (the script-side allowlist was bash-glob-based; this
// implementation matches forward-slash-only semantics).
func IsAllowed(p string) bool {
	if !structurallyValid(p) {
		return false
	}
	if firstSegmentDenied(p) {
		return false
	}
	return matchesAnyPattern(p)
}

// structurallyValid rejects empty, absolute, backslash-containing,
// or traversal-laden paths up-front.
func structurallyValid(p string) bool {
	if p == "" {
		return false
	}
	if strings.ContainsAny(p, `\`) {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

// firstSegmentDenied reports whether p lives under a forbidden
// repo-root subdirectory (vendor, .github, etc.).
func firstSegmentDenied(p string) bool {
	first, _, found := strings.Cut(p, "/")
	if !found {
		return false
	}
	_, denied := deniedFirstSegments[first]
	return denied
}

// matchesAnyPattern reports whether p matches one of the allowlist
// globs.
func matchesAnyPattern(p string) bool {
	for _, pat := range allowedPatterns {
		ok, err := filepath.Match(pat, p)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// IsSymlink reports whether p (a path relative to root) refers to a
// symlink on disk. Use this BEFORE committing — even if [IsAllowed]
// accepts the path, a symlinked go.mod could exfiltrate arbitrary
// file contents into the release commit.
func IsSymlink(root, p string) (bool, error) {
	info, err := os.Lstat(filepath.Join(root, p))
	if err != nil {
		return false, fmt.Errorf("allowlist: lstat %q: %w", p, err)
	}
	return info.Mode()&os.ModeSymlink != 0, nil
}
