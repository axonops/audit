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

// Package sumdb queries Go's checksum-database transparency log
// (sum.golang.org by default) directly so the preflight-tidy gate
// in cmd/release-tool/cmd_preflight_tidy_check.go can verify a
// freshly-tidied go.sum line against the public log rather than
// trusting the module proxy.
//
// Security note: this package intentionally talks to the sumdb over
// HTTPS using the system trust store. It does NOT verify the sumdb's
// own signed-note signature (which would require pinning the sumdb's
// public key). The threat model is: a malicious or skewed proxy
// returns checksum lines for a release version. Without an
// independent check, those lines get auto-committed to main. By
// fetching the SAME (module, version) directly from sum.golang.org
// — bypassing the proxy entirely — and byte-comparing the h1: hashes,
// we catch any proxy-only divergence.
//
// The transparency log itself can still be compromised (e.g. via
// the sumdb's signing key), but that's a single-source-of-truth Go
// ecosystem risk shared by every Go consumer; defending against it
// is out of scope for preflight-tidy.
package sumdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultEndpoint is the public Go checksum database.
const DefaultEndpoint = "https://sum.golang.org"

// ErrNotFound is returned when the sumdb has no record for the
// requested module@version. Distinct from network/transport errors
// so callers can decide whether to abort or treat as "module not
// yet in the log".
var ErrNotFound = errors.New("sumdb: module@version not found in checksum database")

// Lookup is the result of a successful sumdb lookup. Both Hash and
// ModHash are h1:-prefixed dirhash values matching the format used
// in go.sum lines:
//
//	<module> <version> h1:<base64>           — Hash
//	<module> <version>/go.mod h1:<base64>    — ModHash
type Lookup struct {
	Module  string
	Version string
	Hash    string // h1:... for the module zip
	ModHash string // h1:... for the module's go.mod
}

// Client queries a sumdb endpoint with a configurable per-request
// timeout. Zero-value Client uses DefaultEndpoint, a fresh
// http.Client, and a 30-second timeout.
type Client struct {
	// HTTP overrides the default http.Client. Useful for tests.
	HTTP *http.Client

	// Endpoint is the sumdb base URL (no trailing slash). Defaults
	// to DefaultEndpoint.
	Endpoint string

	// Timeout is the per-request deadline. Defaults to 30s.
	Timeout time.Duration
}

func (c *Client) endpoint() string {
	if c.Endpoint != "" {
		return strings.TrimRight(c.Endpoint, "/")
	}
	return DefaultEndpoint
}

// httpClient returns the caller-supplied http.Client or, on the
// zero-value path, a fresh one. Per security-reviewer #967 MEDIUM-2,
// we do NOT fall back to http.DefaultClient — that would leak
// connections across unrelated callers and contradicts the project's
// http.DefaultClient prohibition.
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: c.timeout()}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

// Lookup performs a GET against `<endpoint>/lookup/<module>@<version>`.
// The response is a signed note whose text section contains two
// hash lines (one for the module, one for go.mod). The signature
// section is intentionally NOT verified — see package godoc for the
// threat-model rationale.
//
// On success returns a *Lookup with both h1: hashes populated.
// On a 404 response returns ErrNotFound (wrap with errors.Is).
// On any other transport error, status, or parse failure returns a
// descriptive error.
func (c *Client) Lookup(ctx context.Context, module, version string) (*Lookup, error) {
	if module == "" {
		return nil, errors.New("sumdb: module is required")
	}
	if version == "" {
		return nil, errors.New("sumdb: version is required")
	}

	// Sumdb paths use the lowercase-escaped module path per
	// https://go.dev/ref/mod#serving-from-proxy. For our consumers
	// (axonops/audit + sub-modules) the path contains no uppercase
	// or escape-required characters so a literal join is correct,
	// but the percent-encoded form is still strictly more defensive
	// — preserves behaviour if someone introduces a path with
	// uppercase letters in future.
	url := fmt.Sprintf("%s/lookup/%s@%s", c.endpoint(), escapeModulePath(module), version)

	rctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("sumdb: build request: %w", err)
	}
	req.Header.Set("User-Agent", "audit-release-tool/preflight-tidy")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("sumdb: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Fall through.
	case http.StatusNotFound, http.StatusGone:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("sumdb: GET %s returned %d %s", url, resp.StatusCode, resp.Status)
	}

	// 1 MiB response cap. A real sumdb response is <1 KiB; the cap
	// prevents a malicious endpoint from streaming an unbounded
	// body into memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("sumdb: read response: %w", err)
	}

	return parseSumdbResponse(module, version, body)
}

// parseSumdbResponse parses a sumdb /lookup response. Format:
//
//	<id>
//	<module> <version> h1:<hash>
//	<module> <version>/go.mod h1:<hash>
//
//	— signed-note signature lines —
//
// The leading id line is a numeric log index; we don't use it. The
// two hash lines are what go.sum is keyed against. Anything after a
// blank line is the note signature, which is parsed by callers that
// want to verify against a pinned sumdb key — out of scope here.
// Line-by-line validator: one branch per expected line shape.
// Flatter as one switch than nested helpers.
//
//nolint:gocognit,gocyclo,cyclop // see godoc above
func parseSumdbResponse(wantModule, wantVersion string, body []byte) (*Lookup, error) {
	lookup := &Lookup{Module: wantModule, Version: wantVersion}

	scanner := scanLines(body)
	// Skip the leading id line. Treat a missing id as a parse error
	// — the response was either truncated or not a sumdb /lookup
	// payload at all.
	if !scanner.next() {
		return nil, errors.New("sumdb: empty response")
	}
	// Subsequent lines are the hash records until the first blank
	// line.
	for scanner.next() {
		line := scanner.text()
		if line == "" {
			break
		}
		fields := strings.Fields(line)
		// Expected shapes:
		//   `<module> <version> h1:<hash>`           (3 fields)
		//   `<module> <version>/go.mod h1:<hash>`    (3 fields, /go.mod suffix on field[1])
		if len(fields) != 3 {
			return nil, fmt.Errorf("sumdb: unexpected line %q (want 3 fields)", line)
		}
		if fields[0] != wantModule {
			return nil, fmt.Errorf("sumdb: line module mismatch: got %q want %q", fields[0], wantModule)
		}
		if !strings.HasPrefix(fields[2], "h1:") {
			return nil, fmt.Errorf("sumdb: line %q missing h1: prefix on hash field", line)
		}

		switch fields[1] {
		case wantVersion:
			if lookup.Hash != "" {
				return nil, fmt.Errorf("sumdb: duplicate module hash for %s@%s", wantModule, wantVersion)
			}
			lookup.Hash = fields[2]
		case wantVersion + "/go.mod":
			if lookup.ModHash != "" {
				return nil, fmt.Errorf("sumdb: duplicate go.mod hash for %s@%s", wantModule, wantVersion)
			}
			lookup.ModHash = fields[2]
		default:
			return nil, fmt.Errorf("sumdb: line version mismatch: got %q want %q or %q/go.mod",
				fields[1], wantVersion, wantVersion)
		}
	}

	if lookup.Hash == "" {
		return nil, fmt.Errorf("sumdb: no module hash line for %s@%s", wantModule, wantVersion)
	}
	if lookup.ModHash == "" {
		return nil, fmt.Errorf("sumdb: no go.mod hash line for %s@%s", wantModule, wantVersion)
	}
	return lookup, nil
}

// escapeModulePath converts a module path's uppercase letters to
// their proxy-escaped lowercase form (`A` → `!a`). For the audit
// project's published modules there's nothing to escape, but the
// helper exists so the lookup URL is correct for any future
// module path that introduces uppercase.
func escapeModulePath(module string) string {
	var b strings.Builder
	b.Grow(len(module))
	for _, r := range module {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// scanLines is a small wrapper that yields lines of body without
// pulling bufio.Scanner's MaxScanTokenSize ceiling. Sumdb responses
// are tiny but the cap is defensive.
type lineScanner struct {
	cur  string
	body []byte
	pos  int
}

func scanLines(body []byte) *lineScanner { return &lineScanner{body: body} }

// maxLineBytes caps a single sumdb response line. Real sumdb lines
// are ~80 bytes; the 8 KiB cap is defence-in-depth per #967
// security-reviewer MEDIUM-3. Without it, a malicious endpoint
// could stream one ~1 MiB line within the body-level cap and force
// strings.Fields to allocate ~1 MiB.
const maxLineBytes = 8192

func (s *lineScanner) next() bool {
	if s.pos >= len(s.body) {
		return false
	}
	end := s.pos
	for end < len(s.body) && s.body[end] != '\n' {
		end++
		if end-s.pos > maxLineBytes {
			// Truncate the line at the cap. The caller's
			// validators see a malformed line and reject; this
			// avoids the unbounded-allocation risk while still
			// terminating cleanly.
			s.cur = string(s.body[s.pos:end])
			s.pos = end
			return true
		}
	}
	s.cur = string(s.body[s.pos:end])
	if end < len(s.body) {
		s.pos = end + 1
	} else {
		s.pos = end
	}
	return true
}

func (s *lineScanner) text() string { return s.cur }
