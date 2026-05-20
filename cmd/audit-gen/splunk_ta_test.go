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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// taTestTaxonomy returns a small but representative Taxonomy used by
// the splunk-ta tests. Two categories — one "write" (Change-only)
// and one "security" (Change + Authentication tags).
func taTestTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create", "user_update"}},
			"security": {Events: []string{"login", "logout"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {Categories: []string{"write"}},
			"user_update": {Categories: []string{"write"}},
			"login":       {Categories: []string{"security"}},
			"logout":      {Categories: []string{"security"}},
		},
	}
}

// runSplunkTA is a helper that writes the TA into a per-test temp
// directory and returns the directory.
func runSplunkTA(t *testing.T, opts splunkTAOptions) string { //nolint:gocritic // hugeParam: test helper that mirrors the by-value production signature
	t.Helper()
	dir := t.TempDir()
	tax := taTestTaxonomy()
	require.NoError(t, generateSplunkTA(dir, tax, opts))
	return dir
}

// TestSplunkTA_GeneratesAllExpectedFiles verifies every file the
// TA spec requires exists after a generate run.
func TestSplunkTA_GeneratesAllExpectedFiles(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})

	expected := []string{
		"default/app.conf",
		"default/props.conf",
		"default/eventtypes.conf",
		"default/tags.conf",
		"default/data/ui/views/audit_events.xml",
		"metadata/default.meta",
	}
	for _, rel := range expected {
		path := filepath.Join(dir, rel)
		info, err := os.Stat(path)
		require.NoError(t, err, "expected file %s", rel)
		assert.False(t, info.IsDir(), "%s must be a file", rel)
		assert.Greater(t, info.Size(), int64(0), "%s must not be empty", rel)
	}
}

// TestSplunkTA_PropsConf_FieldAliasesMatchCIMChange anchors the
// props.conf contract: INDEXED_EXTRACTIONS=json, TIMESTAMP_FIELDS,
// TIME_FORMAT, EVAL-vendor_product, EVAL-dvc.
func TestSplunkTA_PropsConf_FieldAliasesMatchCIMChange(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{VendorProduct: "TestVendor:Product"})
	body := mustRead(t, filepath.Join(dir, "default", "props.conf"))

	assert.Contains(t, body, "[axonops:audit]",
		"sourcetype stanza must use the default axonops:audit name")
	assert.Contains(t, body, "INDEXED_EXTRACTIONS = json",
		"INDEXED_EXTRACTIONS = json is the load-bearing CIM extraction directive")
	assert.Contains(t, body, "KV_MODE = none",
		"KV_MODE = none avoids double-extraction (mutually exclusive with INDEXED_EXTRACTIONS)")
	assert.Contains(t, body, "TIMESTAMP_FIELDS = _time")
	assert.Contains(t, body, "TIME_FORMAT = %s.%3N",
		"epoch seconds with ms precision (CIM canonical timestamp)")
	assert.Contains(t, body, `EVAL-vendor_product = "TestVendor:Product"`,
		"vendor_product must be a per-TA constant, not a per-event value")
	assert.Contains(t, body, "EVAL-dvc = if(isnotnull(dvc), dvc, host)",
		"dvc fallback ensures CIM Change required field is always populated")
}

// TestSplunkTA_EventtypesConf_OnePerCategory verifies the
// eventtypes.conf has exactly one stanza per (category, event) pair.
// The test taxonomy has 2 categories × 2 events = 4 pairs.
func TestSplunkTA_EventtypesConf_OnePerCategory(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})
	body := mustRead(t, filepath.Join(dir, "default", "eventtypes.conf"))

	// Four expected stanzas, one per (cat, ev) pair, named
	// <category>_<event>.
	expected := []string{
		"[security_login]",
		"[security_logout]",
		"[write_user_create]",
		"[write_user_update]",
	}
	for _, stanza := range expected {
		assert.Contains(t, body, stanza,
			"eventtypes.conf must contain stanza %s", stanza)
	}
	// And each stanza's search line targets the right event_type.
	assert.Contains(t, body, `search = sourcetype="axonops:audit" event_type="login"`)
	assert.Contains(t, body, `search = sourcetype="axonops:audit" event_type="user_create"`)

	// Verify exactly 4 stanzas — count the lines starting with `[`.
	stanzaCount := strings.Count(body, "\n[") + 1 // +1 for the first stanza (no preceding newline)
	if !strings.HasPrefix(body, "[") {
		stanzaCount--
	}
	assert.Equal(t, 4, stanzaCount,
		"expected exactly 4 (cat × event) stanzas — taxonomy has 2 cats × 2 events")
}

// TestSplunkTA_TagsConf_CIMTagsAppliedCorrectly verifies that:
// every eventtype gets `change = enabled`, and security-category
// eventtypes also get `authentication = enabled`.
func TestSplunkTA_TagsConf_CIMTagsAppliedCorrectly(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})
	body := mustRead(t, filepath.Join(dir, "default", "tags.conf"))

	// Every (cat, event) gets [eventtype=<name>] + change=enabled.
	for _, name := range []string{"security_login", "security_logout", "write_user_create", "write_user_update"} {
		assert.Contains(t, body, "[eventtype="+name+"]",
			"tags.conf must contain stanza for %s", name)
	}
	// All 4 get change=enabled.
	changeCount := strings.Count(body, "change = enabled")
	assert.Equal(t, 4, changeCount,
		"every eventtype must have change=enabled (CIM Change root tag)")

	// Only the 2 security eventtypes get authentication=enabled.
	authCount := strings.Count(body, "authentication = enabled")
	assert.Equal(t, 2, authCount,
		"only security-category eventtypes (2 of 4) should have authentication=enabled")
}

// TestSplunkTA_FieldsConf_OmittedForJSONExtractions — fields.conf is
// NOT generated because INDEXED_EXTRACTIONS=json supplies all field
// extractions automatically. Test pins the omission so a future
// refactor can't silently start emitting it without a code review.
func TestSplunkTA_FieldsConf_OmittedForJSONExtractions(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})
	_, err := os.Stat(filepath.Join(dir, "default", "fields.conf"))
	assert.True(t, os.IsNotExist(err),
		"fields.conf must NOT be generated — INDEXED_EXTRACTIONS=json handles all field extractions")
}

// TestSplunkTA_SavedSearches_OmittedForMinimalTA — savedsearches.conf
// (risk modifiers, scheduled searches) is intentionally OMITTED from
// the minimal TA. Operators add it themselves in their app's
// local/savedsearches.conf based on their own threat model.
func TestSplunkTA_SavedSearches_OmittedForMinimalTA(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})
	_, err := os.Stat(filepath.Join(dir, "default", "savedsearches.conf"))
	assert.True(t, os.IsNotExist(err),
		"savedsearches.conf must NOT be in the minimal TA — operators provide their own")
}

// TestSplunkTA_AppConf_Skeleton — app.conf has the five required
// stanzas and the configurable fields reflect the options.
func TestSplunkTA_AppConf_Skeleton(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{
		AppName:     "TA-test-app",
		AppVersion:  "1.2.3",
		Author:      "Test Author",
		Description: "Test description",
	})
	body := mustRead(t, filepath.Join(dir, "default", "app.conf"))

	for _, stanza := range []string{"[install]", "[ui]", "[launcher]", "[package]", "[id]"} {
		assert.Contains(t, body, stanza, "app.conf must contain %s stanza", stanza)
	}
	// Configurable fields reflect the options.
	assert.Contains(t, body, "version = 1.2.3")
	assert.Contains(t, body, "id = TA-test-app")
	assert.Contains(t, body, "name = TA-test-app")
	assert.Contains(t, body, "author = Test Author")
	assert.Contains(t, body, "description = Test description")
	// TAs ship as non-visible UI elements (no [ui] is_visible=true).
	assert.Contains(t, body, "is_visible = false")
}

// TestSplunkTA_DashboardXML_StarterView — the starter dashboard
// targets the configured sourcetype and includes the three expected
// panels (events by type, status pie, recent table).
func TestSplunkTA_DashboardXML_StarterView(t *testing.T) {
	dir := runSplunkTA(t, splunkTAOptions{})
	body := mustRead(t, filepath.Join(dir, "default", "data", "ui", "views", "audit_events.xml"))

	assert.Contains(t, body, `<form theme="light"`, "dashboard must be a form view")
	assert.Contains(t, body, "<label>Audit Events</label>", "dashboard label is fixed")
	assert.Contains(t, body, `sourcetype="axonops:audit"`,
		"every panel search must target the configured sourcetype")
	// Three panels: count by action, count by status, recent table.
	assert.Contains(t, body, "stats count by action")
	assert.Contains(t, body, "stats count by status")
	assert.Contains(t, body, "table _time action user_name object")
}

// TestSplunkTA_PassesAppInspect_Basic — runs splunk-appinspect if
// available on PATH; otherwise t.Skip. CI installs splunk-appinspect
// so this runs for real there; locally, developers can skip.
func TestSplunkTA_PassesAppInspect_Basic(t *testing.T) {
	if _, err := exec.LookPath("splunk-appinspect"); err != nil {
		t.Skip("splunk-appinspect not installed; skipping (CI installs it)")
	}
	dir := runSplunkTA(t, splunkTAOptions{})
	out, err := exec.Command("splunk-appinspect", "inspect",
		"--mode", "precert",
		"--included-tags", "cloud",
		dir).CombinedOutput()
	if err != nil {
		t.Fatalf("splunk-appinspect failed:\n%s", out)
	}
}

// --- Deterministic / output-stability tests ---

// TestSplunkTA_DeterministicOutput — running the generator twice
// against the same input produces byte-identical files. Critical for
// `make check-ta-diff` to be meaningful.
func TestSplunkTA_DeterministicOutput(t *testing.T) {
	tax := taTestTaxonomy()
	d1 := t.TempDir()
	d2 := t.TempDir()
	opts := splunkTAOptions{VendorProduct: "Determinism:Test"}
	require.NoError(t, generateSplunkTA(d1, tax, opts))
	require.NoError(t, generateSplunkTA(d2, tax, opts))

	for _, rel := range []string{
		"default/app.conf",
		"default/props.conf",
		"default/eventtypes.conf",
		"default/tags.conf",
		"default/data/ui/views/audit_events.xml",
		"metadata/default.meta",
	} {
		b1 := mustRead(t, filepath.Join(d1, rel))
		b2 := mustRead(t, filepath.Join(d2, rel))
		assert.Equal(t, b1, b2,
			"file %s must be byte-identical across runs (deterministic)", rel)
	}
}

// TestSplunkTA_SanitiseConfName — taxonomy names with non-ASCII
// characters get sanitised to ASCII-safe `.conf` stanza names.
func TestSplunkTA_SanitiseConfName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ok_name", "ok_name"},
		{"User Create", "User_Create"},
		{"weird-event!", "weird_event_"},
		{"empty.dotted.name", "empty_dotted_name"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitiseConfName(tc.in))
		})
	}
}

// TestSplunkTA_OptionsWithDefaults — every zero field falls back to
// the canonical default.
func TestSplunkTA_OptionsWithDefaults(t *testing.T) {
	got := splunkTAOptionsWithDefaults(splunkTAOptions{})
	assert.Equal(t, "TA-axonops-audit", got.AppName)
	assert.Equal(t, "0.1.0", got.AppVersion)
	assert.Equal(t, "AxonOps:Audit", got.VendorProduct)
	assert.Equal(t, "axonops:audit", got.Sourcetype)
	assert.Equal(t, "AxonOps", got.Author)
	assert.NotEmpty(t, got.Description)
}

// TestSplunkTA_OptionsOverride — explicit options are honoured.
func TestSplunkTA_OptionsOverride(t *testing.T) {
	got := splunkTAOptionsWithDefaults(splunkTAOptions{
		AppName:    "custom-name",
		AppVersion: "9.9.9",
	})
	assert.Equal(t, "custom-name", got.AppName)
	assert.Equal(t, "9.9.9", got.AppVersion)
	// Untouched fields still default.
	assert.Equal(t, "AxonOps:Audit", got.VendorProduct)
}

// --- CLI integration ---

// TestRun_SplunkTAFormat_GeneratesDirectory — the audit-gen CLI's
// --format=splunk-ta path produces the expected directory tree.
func TestRun_SplunkTAFormat_GeneratesDirectory(t *testing.T) {
	inputFile := writeTempTaxonomy(t, taTestTaxonomyYAML)
	outDir := filepath.Join(t.TempDir(), "ta")

	code := run([]string{
		"-format=splunk-ta",
		"-input", inputFile,
		"-output", outDir,
		"-vendor-product", "Test:Vendor",
	}, &strings.Builder{}, &strings.Builder{})
	require.Equal(t, exitSuccess, code, "audit-gen --format=splunk-ta must exit 0")

	for _, rel := range []string{"default/app.conf", "default/props.conf", "default/eventtypes.conf", "default/tags.conf", "metadata/default.meta"} {
		_, err := os.Stat(filepath.Join(outDir, rel))
		require.NoError(t, err, "%s must exist", rel)
	}
}

// TestRun_SplunkTAFormat_StdoutRejected — `-output=-` is not
// supported for the splunk-ta format (it writes a directory tree).
func TestRun_SplunkTAFormat_StdoutRejected(t *testing.T) {
	inputFile := writeTempTaxonomy(t, taTestTaxonomyYAML)
	var stderr strings.Builder
	code := run([]string{
		"-format=splunk-ta",
		"-input", inputFile,
		"-output", "-",
	}, &strings.Builder{}, &stderr)
	require.Equal(t, exitInvalidArgs, code)
	assert.Contains(t, stderr.String(), "splunk-ta")
}

// taTestTaxonomyYAML is the YAML body that taTestTaxonomy() returns
// in Go form. Used by run() integration tests.
const taTestTaxonomyYAML = `version: 1
categories:
  write:
    events: [user_create, user_update]
  security:
    events: [login, logout]
events:
  user_create:
    description: "create user"
    fields:
      actor_id: {required: true}
      outcome: {required: true}
  user_update:
    description: "update user"
    fields:
      actor_id: {required: true}
      outcome: {required: true}
  login:
    description: "user login"
    fields:
      actor_id: {required: true}
      outcome: {required: true}
  logout:
    description: "user logout"
    fields:
      actor_id: {required: true}
      outcome: {required: true}
`

// writeTempTaxonomy writes a YAML body to a temp file and returns
// its path.
func writeTempTaxonomy(t *testing.T, yamlBody string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "taxonomy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlBody), 0o644))
	return path
}

// mustRead reads a file and returns its contents as a string;
// fails the test on error.
func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}
