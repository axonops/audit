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

package rfc5424_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/tests/bdd/steps/rfc5424"
)

func TestParse_RealSyslogNgLine(t *testing.T) {
	t.Parallel()
	// Real bytes from `docker exec bdd-syslog-ng-1 cat /var/log/syslog-ng/audit.log`.
	raw := []byte(`<133>1 2026-04-27T17:29:19+02:00 linuxworkstation /tmp/go-build2861046914/b001/bdd.test 4046174 bdd-fanout - {"timestamp":"2026-04-27T17:29:19.120891563+02:00","event_type":"user_create","marker":"BDD_dac2f152beb4bfd6"}`)

	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, 133, m.Priority)
	assert.Equal(t, 16, m.Facility) // 133 / 8 = 16 (local0)
	assert.Equal(t, 5, m.Severity)  // 133 % 8 = 5 (notice)
	assert.Equal(t, 1, m.Version)
	assert.Equal(t, "2026-04-27T17:29:19+02:00", m.Timestamp)
	assert.Equal(t, "linuxworkstation", m.Hostname)
	assert.Equal(t, "/tmp/go-build2861046914/b001/bdd.test", m.AppName)
	assert.Equal(t, "4046174", m.ProcID)
	assert.Equal(t, "bdd-fanout", m.MsgID)
	assert.Equal(t, "-", m.StructuredData)
	assert.Contains(t, m.Message, "BDD_dac2f152beb4bfd6")
}

func TestParse_With5425Framing(t *testing.T) {
	t.Parallel()
	raw := []byte("135 <134>1 2026-04-27T17:00:00Z host app proc msgid - body")
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, 134, m.Priority)
	assert.Equal(t, "host", m.Hostname)
	assert.Equal(t, "body", m.Message)
}

func TestParse_NilvalueFields(t *testing.T) {
	t.Parallel()
	// All optional fields set to "-" (RFC 5424 nilvalue). The
	// parser surfaces nilvalue as the empty string for ergonomic
	// test assertions.
	raw := []byte("<13>1 - - - - - - body")
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Empty(t, m.Timestamp)
	assert.Empty(t, m.Hostname)
	assert.Empty(t, m.AppName)
	assert.Empty(t, m.ProcID)
	assert.Empty(t, m.MsgID)
	assert.Equal(t, "-", m.StructuredData) // S-D nilvalue is preserved as raw token
	assert.Equal(t, "body", m.Message)
}

func TestParse_StructuredData(t *testing.T) {
	t.Parallel()
	raw := []byte(`<13>1 - - - - - [exampleSDID@32473 iut="3" eventSource="App"] body`)
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, `[exampleSDID@32473 iut="3" eventSource="App"]`, m.StructuredData)
	assert.Equal(t, "body", m.Message)
}

func TestParse_StructuredData_MultipleElements(t *testing.T) {
	t.Parallel()
	raw := []byte(`<13>1 - - - - - [id1 k="v"][id2 a="b"] body`)
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, `[id1 k="v"][id2 a="b"]`, m.StructuredData)
	assert.Equal(t, "body", m.Message)
}

func TestParse_EmptyMessage(t *testing.T) {
	t.Parallel()
	raw := []byte(`<13>1 2026-04-27T00:00:00Z h a p m -`)
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Empty(t, m.Message)
}

func TestParse_MessageWithTrailingNewline(t *testing.T) {
	t.Parallel()
	raw := []byte("<13>1 - - - - - - body\n")
	m, err := rfc5424.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "body", m.Message,
		"trailing newline must be trimmed for ergonomic body assertions")
}

func TestParse_PriorityBoundaries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  []byte
		want int
	}{
		{[]byte("<0>1 - - - - - - x"), 0},
		{[]byte("<7>1 - - - - - - x"), 7},
		{[]byte("<191>1 - - - - - - x"), 191},
	} {
		m, err := rfc5424.Parse(tc.raw)
		require.NoError(t, err, "boundary PRI %d must parse", tc.want)
		assert.Equal(t, tc.want, m.Priority)
	}
}

func TestParse_FacilitySeverity(t *testing.T) {
	t.Parallel()
	// <165> = facility 20 (local4) * 8 + severity 5 (notice).
	m, err := rfc5424.Parse([]byte("<165>1 - - - - - - x"))
	require.NoError(t, err)
	assert.Equal(t, 20, m.Facility)
	assert.Equal(t, 5, m.Severity)
}

func TestParse_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		wantSub string
		raw     []byte
	}{
		{name: "missing-bracket", raw: []byte("13>1 - - - - - - x"), wantSub: "expected '<'"},
		{name: "non-digit-pri", raw: []byte("<1a>1 - - - - - - x"), wantSub: "non-digit"},
		{name: "empty-pri", raw: []byte("<>1 - - - - - - x"), wantSub: "empty PRI"},
		{name: "unterminated-pri", raw: []byte("<13 1 - - - - - - x"), wantSub: "non-digit"},
		{name: "pri-too-large", raw: []byte("<999>1 - - - - - - x"), wantSub: "out of range"},
		{name: "version-not-1", raw: []byte("<13>2 - - - - - - x"), wantSub: "VERSION 2 unsupported"},
		{name: "missing-version", raw: []byte("<13>"), wantSub: "missing VERSION"},
		{name: "missing-hostname", raw: []byte("<13>1 ts"), wantSub: "missing"},
		{name: "sd-bad-start", raw: []byte("<13>1 - - - - - x body"), wantSub: "must start with '-' or '['"},
		{name: "sd-unbalanced", raw: []byte("<13>1 - - - - - [id"), wantSub: "unterminated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := rfc5424.Parse(tc.raw)
			require.Error(t, err)
			assert.Truef(t, strings.Contains(err.Error(), tc.wantSub),
				"error %q must contain %q", err, tc.wantSub)
		})
	}
}

func TestMustParse_PanicsOnError(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		assert.NotNil(t, r, "MustParse must panic on bad input")
	}()
	rfc5424.MustParse([]byte("not valid"))
}

func TestMustParse_OK(t *testing.T) {
	t.Parallel()
	m := rfc5424.MustParse([]byte("<13>1 - - - - - - x"))
	require.NotNil(t, m)
	assert.Equal(t, 13, m.Priority)
}
