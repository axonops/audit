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

// Package readme_snippets contains compile-only tests that lift the
// Quick Start examples out of each submodule README and run them
// against the current public API. The Quick Starts in v0.2.0 carried
// signatures that did not compile against `audit.New` because no
// such guard existed; this test prevents the same drift in v0.2.x+.
//
// Each `compileXxxQuickStart` function mirrors the README code block.
// Keep the snippets here byte-for-byte aligned with the README — when
// the README changes, this file changes in the same commit.
package readme_snippets_test

import (
	"testing"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
	"github.com/axonops/audit/loki"
	"github.com/axonops/audit/splunk"
	"github.com/axonops/audit/syslog"
	"github.com/axonops/audit/webhook"
)

// devTaxonomyYAML is the minimal taxonomy used to satisfy the
// `audit.ParseTaxonomyYAML(taxonomyYAML)` call shown in every Quick
// Start. Real consumers embed their taxonomy via `go:embed`; the
// snippet does not show that bit.
const devTaxonomyYAML = `
version: 1
categories:
  write: [user_create]
events:
  user_create:
    fields:
      actor_id: {required: true}
      outcome: {required: true}
`

// TestFileQuickStart mirrors file/README.md Quick Start.
func TestFileQuickStart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	out, err := file.New(&file.Config{
		Path:       dir + "/events.log",
		MaxSizeMB:  100,
		MaxBackups: 5,
		MaxAgeDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(devTaxonomyYAML))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("my-service"),
		audit.WithHost("host-01"),
		audit.WithOutputs(out),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Emit one event so the auditor lifecycle (init + queue + close)
	// is exercised — mirrors what a real Quick Start consumer would do
	// after the snippet ends.
	_ = auditor.AuditEvent(audit.MustNewEventKV("user_create",
		"actor_id", "alice",
		"outcome", "success",
	))
}

// TestSyslogQuickStart mirrors syslog/README.md Quick Start.
func TestSyslogQuickStart(t *testing.T) {
	t.Parallel()
	out, err := syslog.New(&syslog.Config{
		Network: "udp",
		Address: "127.0.0.1:0",
	})
	if err != nil {
		t.Skipf("syslog dial unavailable in this environment: %v", err)
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(devTaxonomyYAML))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("my-service"),
		audit.WithHost("host-01"),
		audit.WithOutputs(out),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Emit one event so the auditor lifecycle (init + queue + close)
	// is exercised — mirrors what a real Quick Start consumer would do
	// after the snippet ends.
	_ = auditor.AuditEvent(audit.MustNewEventKV("user_create",
		"actor_id", "alice",
		"outcome", "success",
	))
}

// TestWebhookQuickStart mirrors webhook/README.md Quick Start.
func TestWebhookQuickStart(t *testing.T) {
	t.Parallel()
	out, err := webhook.New(&webhook.Config{
		URL:                        "http://127.0.0.1:0/audit",
		DisableStartupVerification: true,
		AllowInsecureHTTP:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(devTaxonomyYAML))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("my-service"),
		audit.WithHost("host-01"),
		audit.WithOutputs(out),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Emit one event so the auditor lifecycle (init + queue + close)
	// is exercised — mirrors what a real Quick Start consumer would do
	// after the snippet ends.
	_ = auditor.AuditEvent(audit.MustNewEventKV("user_create",
		"actor_id", "alice",
		"outcome", "success",
	))
}

// TestLokiQuickStart mirrors loki/README.md Quick Start.
func TestLokiQuickStart(t *testing.T) {
	t.Parallel()
	out, err := loki.New(&loki.Config{
		URL:                        "http://127.0.0.1:0/loki/api/v1/push",
		DisableStartupVerification: true,
		AllowInsecureHTTP:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(devTaxonomyYAML))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("my-service"),
		audit.WithHost("host-01"),
		audit.WithOutputs(out),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Emit one event so the auditor lifecycle (init + queue + close)
	// is exercised — mirrors what a real Quick Start consumer would do
	// after the snippet ends.
	_ = auditor.AuditEvent(audit.MustNewEventKV("user_create",
		"actor_id", "alice",
		"outcome", "success",
	))
}

// TestSplunkQuickStart mirrors splunk/README.md Quick Start.
func TestSplunkQuickStart(t *testing.T) {
	t.Parallel()
	out, err := splunk.New(&splunk.Config{
		URL:                        "http://127.0.0.1:0",
		Token:                      "dev-token",
		DisableStartupVerification: true,
		AllowInsecureHTTP:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tax, err := audit.ParseTaxonomyYAML([]byte(devTaxonomyYAML))
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("my-service"),
		audit.WithHost("host-01"),
		audit.WithOutputs(out),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditor.Close() }()

	// Emit one event so the auditor lifecycle (init + queue + close)
	// is exercised — mirrors what a real Quick Start consumer would do
	// after the snippet ends.
	_ = auditor.AuditEvent(audit.MustNewEventKV("user_create",
		"actor_id", "alice",
		"outcome", "success",
	))
}
