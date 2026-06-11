// Copyright 2026 AxonOps Limited.
// SPDX-License-Identifier: Apache-2.0

package sumdb_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/axonops/audit/cmd/release-tool/internal/sumdb"
)

func TestLookup_Success(t *testing.T) {
	t.Parallel()
	body := strings.Join([]string{
		"123456",
		"github.com/axonops/audit v0.2.2 h1:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ=",
		"github.com/axonops/audit v0.2.2/go.mod h1:ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210abcdef=",
		"",
		"— sum.golang.org Az3grg+signaturecontent=",
		"",
	}, "\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lookup/github.com/axonops/audit@v0.2.2" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("User-Agent"); got == "" {
			t.Error("missing User-Agent header")
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL}
	lookup, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v0.2.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := lookup.Module, "github.com/axonops/audit"; got != want {
		t.Errorf("Module: got %q want %q", got, want)
	}
	if got, want := lookup.Version, "v0.2.2"; got != want {
		t.Errorf("Version: got %q want %q", got, want)
	}
	if got, want := lookup.Hash, "h1:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ="; got != want {
		t.Errorf("Hash: got %q want %q", got, want)
	}
	if got, want := lookup.ModHash, "h1:ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210abcdef="; got != want {
		t.Errorf("ModHash: got %q want %q", got, want)
	}
}

func TestLookup_NotFound(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL}
	_, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v9.9.9")
	if !errors.Is(err, sumdb.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestLookup_Gone(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL}
	_, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v0.0.0-retracted")
	if !errors.Is(err, sumdb.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound (Gone should map to ErrNotFound)", err)
	}
}

func TestLookup_Non2xxStatusReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL}
	_, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v0.2.2")
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if errors.Is(err, sumdb.ErrNotFound) {
		t.Errorf("500 should NOT map to ErrNotFound: %v", err)
	}
}

func TestLookup_TimeoutAborts(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL, Timeout: 50 * time.Millisecond}
	_, err := c.Lookup(context.Background(), "github.com/axonops/audit", "v0.2.2")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLookup_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	c := &sumdb.Client{Endpoint: "http://unused"}
	if _, err := c.Lookup(context.Background(), "", "v0.2.2"); err == nil {
		t.Error("expected error on empty module")
	}
	if _, err := c.Lookup(context.Background(), "github.com/axonops/audit", ""); err == nil {
		t.Error("expected error on empty version")
	}
}

func TestParseSumdbResponse_TableCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		module    string
		version   string
		body      string
		wantHash  string
		wantMod   string
		wantError string
	}{
		{
			name:     "well-formed response",
			module:   "github.com/axonops/audit",
			version:  "v0.2.2",
			body:     "1\ngithub.com/axonops/audit v0.2.2 h1:AAA=\ngithub.com/axonops/audit v0.2.2/go.mod h1:BBB=\n\n",
			wantHash: "h1:AAA=",
			wantMod:  "h1:BBB=",
		},
		{
			name:      "missing leading id line",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "",
			wantError: "empty response",
		},
		{
			name:      "module mismatch in line",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/evil/audit v0.2.2 h1:AAA=\n",
			wantError: "line module mismatch",
		},
		{
			name:      "version mismatch in line",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.3.0 h1:AAA=\n",
			wantError: "line version mismatch",
		},
		{
			name:      "missing h1 prefix",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.2.2 sha256:bare=\n",
			wantError: "missing h1: prefix",
		},
		{
			name:      "wrong field count",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.2.2 h1:AAA= EXTRA\n",
			wantError: "want 3 fields",
		},
		{
			name:      "no module hash line",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.2.2/go.mod h1:BBB=\n",
			wantError: "no module hash line",
		},
		{
			name:      "no go.mod hash line",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.2.2 h1:AAA=\n",
			wantError: "no go.mod hash line",
		},
		{
			name:      "duplicate module hash rejected",
			module:    "github.com/axonops/audit",
			version:   "v0.2.2",
			body:      "1\ngithub.com/axonops/audit v0.2.2 h1:AAA=\ngithub.com/axonops/audit v0.2.2 h1:CCC=\n",
			wantError: "duplicate module hash",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			c := &sumdb.Client{Endpoint: srv.URL}
			lookup, err := c.Lookup(context.Background(), tc.module, tc.version)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("got err=%v want substring %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := lookup.Hash, tc.wantHash; got != want {
				t.Errorf("Hash: got %q want %q", got, want)
			}
			if got, want := lookup.ModHash, tc.wantMod; got != want {
				t.Errorf("ModHash: got %q want %q", got, want)
			}
		})
	}
}

func TestLookup_EscapesUppercaseModulePath(t *testing.T) {
	t.Parallel()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := &sumdb.Client{Endpoint: srv.URL}
	_, _ = c.Lookup(context.Background(), "github.com/AxonOps/Audit", "v0.2.2")
	want := "/lookup/github.com/!axon!ops/!audit@v0.2.2"
	if gotPath != want {
		t.Errorf("escaped path: got %q want %q", gotPath, want)
	}
}
