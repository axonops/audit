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

// Package rfc5424 is a minimal RFC 5424 syslog parser used by the
// audit BDD harness to drive structural assertions on received
// messages (#572). It is test-only — the audit library encodes
// via srslog and does not need an inbound parser.
//
// Supported subset:
//
//   - PRI ∈ [0, 191], VERSION must be 1.
//   - TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, STRUCTURED-DATA
//     all parsed as space-delimited tokens (the nilvalue "-" is
//     accepted and surfaces as the empty string in the parsed
//     Message).
//   - MSG is everything after the STRUCTURED-DATA token and the
//     following space.
//   - The optional RFC 5425 octet-count framing prefix (e.g.
//     "135 <134>1 ...") is stripped if present.
//
// Out-of-scope: full STRUCTURED-DATA element parsing (we keep the
// raw token), Unicode BOM handling in MSG, SD-PARAM escape rules.
// If a future test needs any of these, extend deliberately —
// silently mis-parsing is forbidden.
package rfc5424

import (
	"fmt"
	"strconv"
)

// Message is a parsed RFC 5424 syslog message.
type Message struct {
	Timestamp      string // unparsed; RFC 3339-ish, "-" surfaces as ""
	Hostname       string
	AppName        string
	ProcID         string
	MsgID          string
	StructuredData string // raw token — "-" or [ID PARAM="VAL"]...
	Message        string // remaining bytes after STRUCTURED-DATA + SP
	Priority       int    // 0..191
	Facility       int    // Priority / 8
	Severity       int    // Priority % 8
	Version        int    // always 1
}

// Parse parses an RFC 5424 message. The optional RFC 5425
// octet-count prefix (e.g., "135 <134>1 ...") is stripped if
// present. Returns (*Message, nil) on success or (nil, err) on
// malformed input.
//
// On parse failure, the returned error includes the byte offset
// of the failure point so BDD assertion diagnostics can show
// the operator exactly where the wire format diverged from
// expectations.
//
//nolint:gocognit,gocyclo,cyclop // sequential RFC 5424 grammar walk; splitting hurts readability.
func Parse(line []byte) (*Message, error) {
	s := line
	off := 0

	// Optional RFC 5425 octet-count framing: "<digits> ".
	if i := indexAfterFraming(s); i > 0 {
		s = s[i:]
		off += i
	}

	// PRI: <digits>
	if len(s) == 0 || s[0] != '<' {
		return nil, fmt.Errorf("rfc5424: expected '<' at offset %d, got %q", off, peek(s, 4))
	}
	end, pri, err := parseAngleNumber(s[1:])
	if err != nil {
		return nil, fmt.Errorf("rfc5424: PRI at offset %d: %w", off, err)
	}
	if pri < 0 || pri > 191 {
		return nil, fmt.Errorf("rfc5424: PRI %d out of range 0..191 at offset %d", pri, off)
	}
	s = s[1+end+1:] // skip '<', digits, '>'
	off += 1 + end + 1

	// VERSION: digits up to first SP.
	verEnd := indexSP(s)
	if verEnd <= 0 {
		return nil, fmt.Errorf("rfc5424: missing VERSION at offset %d", off)
	}
	ver, err := strconv.Atoi(string(s[:verEnd]))
	if err != nil {
		return nil, fmt.Errorf("rfc5424: VERSION at offset %d: %w", off, err)
	}
	if ver != 1 {
		return nil, fmt.Errorf("rfc5424: VERSION %d unsupported (expected 1) at offset %d", ver, off)
	}
	s = s[verEnd+1:] // skip digits + SP
	off += verEnd + 1

	// TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID — five
	// space-delimited tokens.
	timestamp, s, err := readToken(s, &off, "TIMESTAMP")
	if err != nil {
		return nil, err
	}
	hostname, s, err := readToken(s, &off, "HOSTNAME")
	if err != nil {
		return nil, err
	}
	appName, s, err := readToken(s, &off, "APP-NAME")
	if err != nil {
		return nil, err
	}
	procID, s, err := readToken(s, &off, "PROCID")
	if err != nil {
		return nil, err
	}
	msgID, s, err := readToken(s, &off, "MSGID")
	if err != nil {
		return nil, err
	}

	// STRUCTURED-DATA: either "-" or "[...]..." (one or more
	// SD-ELEMENT). The minimal parser keeps the raw token.
	structuredData, s, err := readStructuredData(s, &off)
	if err != nil {
		return nil, err
	}

	// Optional MSG: everything after the SP that follows
	// STRUCTURED-DATA. The trailing newline (if present) is
	// trimmed so callers that inspect the body do not see line
	// terminators as content.
	msg := ""
	if len(s) > 0 {
		if s[0] != ' ' {
			return nil, fmt.Errorf("rfc5424: expected SP before MSG at offset %d, got %q", off, peek(s, 4))
		}
		msg = string(s[1:])
		// Trim a single trailing newline.
		if l := len(msg); l > 0 && msg[l-1] == '\n' {
			msg = msg[:l-1]
		}
	}

	return &Message{
		Priority:       pri,
		Facility:       pri / 8,
		Severity:       pri % 8,
		Version:        ver,
		Timestamp:      nilvalue(timestamp),
		Hostname:       nilvalue(hostname),
		AppName:        nilvalue(appName),
		ProcID:         nilvalue(procID),
		MsgID:          nilvalue(msgID),
		StructuredData: structuredData,
		Message:        msg,
	}, nil
}

// MustParse is the test-only convenience wrapper. Panics on
// parse failure — only suitable inside a t.Helper test path
// where the test author has already validated the wire format
// independently.
func MustParse(line []byte) *Message {
	m, err := Parse(line)
	if err != nil {
		panic(err)
	}
	return m
}

// --- helpers ---

//nolint:gocognit,gocyclo,cyclop // small linear scan; further splitting hurts clarity.
func indexAfterFraming(s []byte) int {
	// Detect a leading "<digits> " frame prefix. Distinguishes
	// from a bare "<PRI>" (which has no preceding digits).
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '<' && i == 0 {
			return 0 // no framing prefix
		}
		if c == ' ' && i > 0 {
			// Only treat the space as a framing terminator if
			// every preceding byte was a digit.
			for j := 0; j < i; j++ {
				if s[j] < '0' || s[j] > '9' {
					return 0
				}
			}
			return i + 1
		}
		if c < '0' || c > '9' {
			return 0
		}
	}
	return 0
}

func parseAngleNumber(s []byte) (end, val int, err error) {
	for i := 0; i < len(s); i++ {
		if s[i] == '>' {
			if i == 0 {
				return 0, 0, fmt.Errorf("empty PRI")
			}
			n, perr := strconv.Atoi(string(s[:i]))
			if perr != nil {
				return 0, 0, fmt.Errorf("PRI digit parse: %w", perr)
			}
			return i, n, nil
		}
		if s[i] < '0' || s[i] > '9' {
			return 0, 0, fmt.Errorf("non-digit in PRI: %q", s[i])
		}
	}
	return 0, 0, fmt.Errorf("missing '>' in PRI")
}

func indexSP(s []byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return i
		}
	}
	return -1
}

func readToken(s []byte, off *int, fieldName string) (token string, rest []byte, err error) {
	end := indexSP(s)
	if end < 0 {
		return "", nil, fmt.Errorf("rfc5424: missing %s (no SP) at offset %d", fieldName, *off)
	}
	if end == 0 {
		return "", nil, fmt.Errorf("rfc5424: empty %s at offset %d", fieldName, *off)
	}
	*off += end + 1
	return string(s[:end]), s[end+1:], nil
}

//nolint:gocognit,gocyclo,cyclop // bracket-balanced scan over SD-ELEMENT(s); single linear pass.
func readStructuredData(s []byte, off *int) (sd string, rest []byte, err error) {
	if len(s) == 0 {
		return "", nil, fmt.Errorf("rfc5424: missing STRUCTURED-DATA at offset %d", *off)
	}
	// Nilvalue.
	if s[0] == '-' {
		// Single '-' followed by SP or EOL.
		if len(s) == 1 {
			*off++
			return "-", nil, nil
		}
		if s[1] != ' ' {
			return "", nil, fmt.Errorf("rfc5424: STRUCTURED-DATA '-' must be followed by SP at offset %d", *off)
		}
		*off++ // consume the '-'; caller sees SP at s[1]
		return "-", s[1:], nil
	}
	// SD-ELEMENT(s): one or more "[...]" — consume until SP that is
	// outside any element. The minimal parser does not attempt to
	// validate SD-ID or SD-PARAM; it just balances brackets.
	if s[0] != '[' {
		return "", nil, fmt.Errorf("rfc5424: STRUCTURED-DATA must start with '-' or '[' at offset %d, got %q", *off, peek(s, 4))
	}
	depth := 0
	end := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth < 0 {
				return "", nil, fmt.Errorf("rfc5424: unbalanced ']' in STRUCTURED-DATA at offset %d", *off+i)
			}
			if depth == 0 {
				// End of an SD-ELEMENT. The next char is either
				// '[' (next element), SP (end of S-D), or EOL.
				if i+1 == len(s) || s[i+1] == ' ' {
					end = i + 1
					break
				}
				if s[i+1] != '[' {
					return "", nil, fmt.Errorf("rfc5424: invalid char %q after SD-ELEMENT at offset %d", s[i+1], *off+i+1)
				}
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", nil, fmt.Errorf("rfc5424: unterminated STRUCTURED-DATA at offset %d", *off)
	}
	*off += end
	return string(s[:end]), s[end:], nil
}

// nilvalue translates the RFC 5424 nilvalue marker "-" to the
// empty string for ergonomic field access in tests.
func nilvalue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func peek(s []byte, n int) string {
	if n > len(s) {
		n = len(s)
	}
	return string(s[:n])
}
