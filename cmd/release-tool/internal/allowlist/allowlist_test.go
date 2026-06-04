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

package allowlist_test

import (
	"testing"

	"github.com/axonops/audit/cmd/release-tool/internal/allowlist"
)

func TestIsAllowed_TopLevelGoMod(t *testing.T) {
	t.Parallel()
	if !allowlist.IsAllowed("go.mod") {
		t.Error("top-level go.mod must be allowed")
	}
}

func TestIsAllowed_TopLevelGoSum(t *testing.T) {
	t.Parallel()
	if !allowlist.IsAllowed("go.sum") {
		t.Error("top-level go.sum must be allowed")
	}
}

func TestIsAllowed_FirstLevelGoMod(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"webhook/go.mod", "syslog/go.mod", "secrets/go.mod"} {
		if !allowlist.IsAllowed(p) {
			t.Errorf("first-level %s must be allowed", p)
		}
	}
}

func TestIsAllowed_SecondLevelGoMod(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"secrets/vault/go.mod", "secrets/openbao/go.sum", "cmd/audit-gen/go.mod"} {
		if !allowlist.IsAllowed(p) {
			t.Errorf("second-level %s must be allowed", p)
		}
	}
}

func TestIsAllowed_RejectVendor(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"vendor/go.mod", "vendor/github.com/foo/go.mod"} {
		if allowlist.IsAllowed(p) {
			t.Errorf("vendor path %s must NOT be allowed", p)
		}
	}
}

func TestIsAllowed_RejectExamplesGoMod(t *testing.T) {
	t.Parallel()
	// examples/<name>/go.mod is third-level on this repo's layout
	// (examples/21-capstone/go.mod). The allowlist intentionally tops
	// out at second-level to keep the surface tight.
	if allowlist.IsAllowed("examples/21-capstone/foo/go.mod") {
		t.Error("third-level go.mod must NOT be allowed")
	}
}

func TestIsAllowed_RejectGithub(t *testing.T) {
	t.Parallel()
	for _, p := range []string{".github/workflows/release.yml", ".github/actions/setup-audit/action.yml"} {
		if allowlist.IsAllowed(p) {
			t.Errorf("github config path %s must NOT be allowed", p)
		}
	}
}

func TestIsAllowed_RejectAbsolute(t *testing.T) {
	t.Parallel()
	if allowlist.IsAllowed("/etc/passwd") {
		t.Error("absolute path must NOT be allowed")
	}
}

func TestIsAllowed_RejectEmpty(t *testing.T) {
	t.Parallel()
	if allowlist.IsAllowed("") {
		t.Error("empty path must NOT be allowed")
	}
}

func TestIsAllowed_RejectParentTraversal(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"../go.mod", "foo/../go.mod", "./go.mod"} {
		if allowlist.IsAllowed(p) {
			t.Errorf("traversal path %s must NOT be allowed", p)
		}
	}
}

func TestIsAllowed_RejectBackslash(t *testing.T) {
	t.Parallel()
	if allowlist.IsAllowed(`webhook\go.mod`) {
		t.Error("backslash-separated path must NOT be allowed (forward-slash only)")
	}
}

// Symlink rejection moved out of allowlist into
// cmd_commit_pinned_deps.go readAllowedFile, which uses O_NOFOLLOW
// on open(2) — atomic, no TOCTOU window. The dedicated test for
// the production symlink-refused path is
// TestRun_CommitPinnedDeps_Symlink_Rejected in
// cmd_commit_pinned_deps_test.go.
