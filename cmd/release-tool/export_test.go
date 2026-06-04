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
	"flag"
	"io"
	"log/slog"
	"net/http"

	"github.com/axonops/audit/cmd/release-tool/internal/ghclient"
)

// runCreateTagTestHook drives doCreateTag against a httptest server
// without going through the production GH_TOKEN / api.github.com
// path. It parses the same flag surface runCreateTag does so we
// exercise the real validation gate.
//
// Parameter order: (baseURL, stdout, stderr, args) — deliberately
// different from production runCreateTag(ctx, args, stdout, stderr,
// persistent), because the hook has no ctx (uses Background) and
// no rootFlags (baseURL is the only thing tests need to inject).
// The runCreateTag → doCreateTag split keeps the validation gate
// and API dance in sync between both paths.
func runCreateTagTestHook(baseURL string, stdout, stderr *bytes.Buffer, args []string) int {
	fs := flag.NewFlagSet("create-tag", flag.ContinueOnError)
	fs.SetOutput(stderr)

	in := createTagArgs{}
	var dryRun bool
	fs.BoolVar(&dryRun, "dry-run", false, "")
	fs.StringVar(&in.owner, "owner", "", "")
	fs.StringVar(&in.repo, "repo", "", "")
	fs.StringVar(&in.tag, "tag", "", "")
	fs.StringVar(&in.commit, "sha", "", "")
	fs.StringVar(&in.message, "message", "", "")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	in.dryRun = dryRun

	if code := validateCreateTagArgs(&in, stderr); code != exitSuccess {
		return code
	}

	client, err := ghclient.New("stub-token",
		ghclient.WithBaseURL(baseURL),
		ghclient.WithHTTPClient(&http.Client{}),
		ghclient.WithLogger(silentLogger()),
	)
	if err != nil {
		return exitOperational
	}
	return doCreateTag(context.Background(), client, &in, stdout, stderr)
}

// runCommitPinnedDepsTestHook drives doCommitPinnedDeps against a
// httptest server. The caller supplies a workdir that already
// contains the staged go.mod/go.sum files (in a real git repo).
func runCommitPinnedDepsTestHook(baseURL, workdir string, dryRun bool, stdout, stderr *bytes.Buffer, args []string) int {
	fs := flag.NewFlagSet("commit-pinned-deps", flag.ContinueOnError)
	fs.SetOutput(stderr)

	in := commitPinnedDepsArgs{}
	fs.StringVar(&in.owner, "owner", "", "")
	fs.StringVar(&in.repo, "repo", "", "")
	fs.StringVar(&in.branch, "branch", "", "")
	fs.StringVar(&in.message, "message", "", "")
	fs.BoolVar(&in.autoCreateBranch, "auto-create-branch", false, "")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	in.workdir = workdir
	in.dryRun = dryRun

	if err := requireCommitFlags(in.owner, in.repo, in.branch, in.message); err != nil {
		return exitUsage
	}
	if code := validateCommitPinnedDepsArgs(&in, stderr); code != exitSuccess {
		return code
	}

	client, err := ghclient.New("stub-token",
		ghclient.WithBaseURL(baseURL),
		ghclient.WithHTTPClient(&http.Client{}),
		ghclient.WithLogger(silentLogger()),
	)
	if err != nil {
		return exitOperational
	}
	return doCommitPinnedDeps(context.Background(), client, &in, stdout, stderr)
}

// silentLogger drops every log line — tests should not pollute the
// terminal with API-call info logs.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
