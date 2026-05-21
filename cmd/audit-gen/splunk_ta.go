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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/axonops/audit"
)

// splunkTAOptions configures the [generateSplunkTA] entry point.
type splunkTAOptions struct {
	// AppName is the Splunk app id (the basename of the output
	// directory MUST match this — AppInspect rejects mismatched
	// ids). Defaults to "TA-axonops-audit".
	AppName string

	// AppVersion is the version stamped into app.conf. Format
	// MAJOR.MINOR.PATCH (Splunkbase convention). Defaults to "0.1.0".
	AppVersion string

	// VendorProduct is the CIM `vendor_product` identifier. Stamped
	// into props.conf as an EVAL constant so every indexed event
	// carries the same vendor_product value. Defaults to
	// "AxonOps:Audit".
	VendorProduct string

	// Sourcetype is the Splunk sourcetype that the TA's props.conf
	// stanza targets. MUST match the value the consumer's splunk
	// output is configured with (default "axonops:audit" — the same
	// value [audit/splunk] uses by default).
	Sourcetype string

	// Author is the contact line stamped into app.conf [launcher].
	// Defaults to the AxonOps audit project.
	Author string

	// Description is the human-readable line in app.conf [launcher].
	Description string
}

// splunkTAOptionsWithDefaults returns o with any zero fields filled
// in with the canonical defaults.
func splunkTAOptionsWithDefaults(o splunkTAOptions) splunkTAOptions { //nolint:gocritic // hugeParam: option pattern is by-value for value-type clarity
	if o.AppName == "" {
		o.AppName = "TA-axonops-audit"
	}
	if o.AppVersion == "" {
		o.AppVersion = "0.1.0"
	}
	if o.VendorProduct == "" {
		o.VendorProduct = "AxonOps:Audit"
	}
	if o.Sourcetype == "" {
		o.Sourcetype = "axonops:audit"
	}
	if o.Author == "" {
		o.Author = "AxonOps"
	}
	if o.Description == "" {
		o.Description = "CIM Change-aligned Technology Add-on for audit events emitted by the github.com/axonops/audit library."
	}
	return o
}

// generateSplunkTA writes a minimal Splunk Technology Add-on into
// outDir. The TA is structured as:
//
//	outDir/
//	├── default/
//	│   ├── app.conf
//	│   ├── props.conf
//	│   ├── eventtypes.conf
//	│   ├── tags.conf
//	│   └── data/ui/views/audit_events.xml
//	└── metadata/
//	    └── default.meta
//
// The output is reproducible: identical input always produces
// byte-identical files (no timestamps in the file bodies). This is
// load-bearing for the `make check-ta-diff` consistency target.
//
// Returns an error if the output directory cannot be created or any
// file write fails. Existing files are overwritten without warning.
func generateSplunkTA(outDir string, tax audit.Taxonomy, opts splunkTAOptions) error { //nolint:gocritic // hugeParam: opts is by-value to mirror the option pattern in this command
	opts = splunkTAOptionsWithDefaults(opts)

	// Splunk TA files are public-by-design (apps install into
	// $SPLUNK_HOME/etc/apps/ where they need to be readable by the
	// splunkd user). 0o755 dirs / 0o644 files via writeFileAtomic
	// matches the Splunkbase publishing convention.
	if err := os.MkdirAll(filepath.Join(outDir, "default"), 0o755); err != nil { //nolint:gosec // Splunk TA convention; G301 expects 0o750 — too restrictive here
		return fmt.Errorf("create default/: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "default", "data", "ui", "views"), 0o755); err != nil { //nolint:gosec // Splunk TA convention
		return fmt.Errorf("create default/data/ui/views/: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "metadata"), 0o755); err != nil { //nolint:gosec // Splunk TA convention
		return fmt.Errorf("create metadata/: %w", err)
	}

	data := buildTASpec(tax, opts)

	files := []struct { //nolint:govet // fieldalignment: readability preferred for this short table
		path string
		tmpl *template.Template
	}{
		{filepath.Join(outDir, "default", "app.conf"), appConfTmpl},
		{filepath.Join(outDir, "default", "props.conf"), propsConfTmpl},
		{filepath.Join(outDir, "default", "eventtypes.conf"), eventtypesConfTmpl},
		{filepath.Join(outDir, "default", "tags.conf"), tagsConfTmpl},
		{filepath.Join(outDir, "metadata", "default.meta"), defaultMetaTmpl},
		{filepath.Join(outDir, "default", "data", "ui", "views", "audit_events.xml"), dashboardTmpl},
	}
	for _, f := range files {
		var buf bytes.Buffer
		if err := f.tmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("render %s: %w", f.path, err)
		}
		if err := writeFileAtomic(f.path, buf.Bytes()); err != nil {
			return fmt.Errorf("write %s: %w", f.path, err)
		}
	}
	return nil
}

// taSpec is the data model passed to every TA template. Pre-computed
// so each template is a pure function of stable inputs.
type taSpec struct {
	AppName       string
	AppVersion    string
	VendorProduct string
	Sourcetype    string
	Author        string
	Description   string
	// Eventtypes is a sorted list of (category, event_type) pairs
	// derived from the taxonomy. One stanza per pair in
	// eventtypes.conf and tags.conf.
	Eventtypes []taEventtype
}

type taEventtype struct {
	Name             string // <category>_<event_type> (sanitised)
	Category         string
	EventType        string
	IsAuthentication bool // true for security-category events; adds tags.conf authentication=enabled
}

// buildTASpec enumerates the taxonomy and builds the [taSpec]
// payload. Stable ordering is enforced by sorting categories then
// event types alphabetically — re-runs against the same taxonomy
// produce identical bytes.
func buildTASpec(tax audit.Taxonomy, opts splunkTAOptions) taSpec { //nolint:gocritic // hugeParam: opts is by-value to mirror the option pattern in this command
	// Sort categories alphabetically for deterministic output.
	categoryNames := make([]string, 0, len(tax.Categories))
	for name := range tax.Categories {
		categoryNames = append(categoryNames, name)
	}
	sort.Strings(categoryNames)

	var eventtypes []taEventtype
	for _, catName := range categoryNames {
		cat := tax.Categories[catName]
		if cat == nil {
			continue
		}
		// Each category lists its events; sort for determinism.
		events := append([]string(nil), cat.Events...)
		sort.Strings(events)
		isAuth := isAuthenticationCategory(catName)
		for _, ev := range events {
			eventtypes = append(eventtypes, taEventtype{
				Name:             sanitiseConfName(catName + "_" + ev),
				Category:         catName,
				EventType:        ev,
				IsAuthentication: isAuth,
			})
		}
	}

	return taSpec{
		AppName:       opts.AppName,
		AppVersion:    opts.AppVersion,
		VendorProduct: opts.VendorProduct,
		Sourcetype:    opts.Sourcetype,
		Author:        opts.Author,
		Description:   opts.Description,
		Eventtypes:    eventtypes,
	}
}

// isAuthenticationCategory reports whether a category name signals
// authentication-related events. The CIM Authentication data model
// expects these events to be tagged so dashboards keyed off
// `tag=authentication` find them.
//
// The current rule is a conservative substring match — only
// taxonomy categories named exactly "auth", "authentication",
// "security", or "access" qualify. Consumers who need different
// criteria can edit the generated tags.conf directly (the generator
// is a starting point, not a constraint).
func isAuthenticationCategory(name string) bool {
	switch strings.ToLower(name) {
	case "auth", "authentication", "security", "access":
		return true
	}
	return false
}

// sanitiseConfName turns a taxonomy name into a Splunk .conf-safe
// identifier. Replaces any character outside [a-zA-Z0-9_] with `_`.
// Conservative — Splunk's actual stanza-name rules are more
// permissive, but the audit field-name regex (already enforced at
// taxonomy parse time) limits the inputs to ASCII alphanumerics
// plus underscore, so the sanitiser is a defensive belt-and-braces.
func sanitiseConfName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// --- Templates --------------------------------------------------------------

// All template strings end with a trailing newline. The output is
// canonical Splunk .conf format: blank line between stanzas, key=value
// (no quotes), one continuation per line.

var appConfTmpl = template.Must(template.New("app.conf").Parse(`# Generated by audit-gen --format=splunk-ta — DO NOT EDIT by hand.
# Regenerate with: audit-gen --format=splunk-ta --input <taxonomy.yaml> --output <dir>

[install]
state = enabled
is_configured = true
build = 1

[ui]
is_visible = false
label = {{.AppName}}

[launcher]
author = {{.Author}}
description = {{.Description}}
version = {{.AppVersion}}

[package]
id = {{.AppName}}

[id]
name = {{.AppName}}
version = {{.AppVersion}}
`))

var propsConfTmpl = template.Must(template.New("props.conf").Parse(`# Generated by audit-gen --format=splunk-ta — DO NOT EDIT by hand.
# CIM Change data-model field extractions for audit events emitted
# by github.com/axonops/audit via the splunk output with
# formatter: cim_change.

[{{.Sourcetype}}]
# JSON field extraction. Every key in the cim_change envelope
# (action, change_type, user, user_id, user_name, object, object_id,
# object_category, object_path, object_attrs, status, src, dvc, ...)
# becomes a Splunk field automatically — no FIELDALIAS rules needed.
#
# KV_MODE = json runs JSON KV extraction at SEARCH time, which works
# uniformly for forwarder ingest AND HEC direct ingest (HEC does not
# evaluate INDEXED_EXTRACTIONS rules on the indexer side, so we cannot
# rely on indexed-time JSON extraction alone for HEC-sourced events).
KV_MODE = json

# Timestamp extraction. The cim_change formatter writes _time as
# epoch seconds with millisecond precision.
TIMESTAMP_FIELDS = _time
TIME_FORMAT = %s.%3N

# vendor_product is a per-TA constant — overrides any per-event
# value to prevent operator-supplied taxonomies from polluting the
# field. Change here if you've configured a non-default value via
# the splunk output's vendor_product formatter option.
EVAL-vendor_product = "{{.VendorProduct}}"

# dvc falls back to host when the audit event does not carry an
# explicit dvc value (CIM Change requires dvc be non-null).
EVAL-dvc = if(isnotnull(dvc), dvc, host)
`))

var eventtypesConfTmpl = template.Must(template.New("eventtypes.conf").Parse(`# Generated by audit-gen --format=splunk-ta — DO NOT EDIT by hand.
# One eventtype per (category, event_type) pair in the taxonomy. The
# search matches either ` + "`action`" + ` (the CIM-canonical key written by
# CIMChangeFormatter) or ` + "`event_type`" + ` (the audit-canonical key kept
# by JSONFormatter), so the same TA works with either formatter.
#
# The search has no leading ` + "`index=`" + ` constraint and so runs across
# every index the searching user has access to. Operators routing
# audit events to a dedicated index (recommended for retention and
# access-control reasons) should prepend ` + "`index=<their-index>`" + ` in
# their own ` + "`local/eventtypes.conf`" + ` override for better search-time
# performance on busy clusters.

{{range .Eventtypes -}}
[{{.Name}}]
search = sourcetype="{{$.Sourcetype}}" (action="{{.EventType}}" OR event_type="{{.EventType}}")

{{end -}}
`))

var tagsConfTmpl = template.Must(template.New("tags.conf").Parse(`# Generated by audit-gen --format=splunk-ta — DO NOT EDIT by hand.
# CIM tag bindings. Every eventtype gets the "change" tag (CIM
# Change data model is the canonical model for audit events).
# Security-related categories also get the "authentication" tag for
# CIM Authentication data model linkage.

{{range .Eventtypes -}}
[eventtype={{.Name}}]
change = enabled
{{if .IsAuthentication}}authentication = enabled
{{end}}
{{end -}}
`))

var defaultMetaTmpl = template.Must(template.New("default.meta").Parse(`# Generated by audit-gen --format=splunk-ta — DO NOT EDIT by hand.
# Export the eventtypes and tags app-wide so dashboards in other
# apps can use them.

[]
export = system

[eventtypes]
export = system

[tags]
export = system

[props]
export = system
`))

var dashboardTmpl = template.Must(template.New("audit_events.xml").Parse(`<form theme="light" version="1.1">
  <label>Audit Events</label>
  <description>Starter view for events ingested via the {{.AppName}} TA. Customise as needed.</description>
  <fieldset submitButton="false">
    <input type="time" token="time_window">
      <label>Time Range</label>
      <default>
        <earliest>-24h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <title>Events by Type (last 24h)</title>
      <chart>
        <search>
          <query>sourcetype="{{.Sourcetype}}" | stats count by action</query>
          <earliest>$time_window.earliest$</earliest>
          <latest>$time_window.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
      </chart>
    </panel>
    <panel>
      <title>Failure Rate (CIM Change status)</title>
      <chart>
        <search>
          <query>sourcetype="{{.Sourcetype}}" | stats count by status</query>
          <earliest>$time_window.earliest$</earliest>
          <latest>$time_window.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Recent Audit Events</title>
      <table>
        <search>
          <query>sourcetype="{{.Sourcetype}}" | table _time action user_name object object_category status src dvc</query>
          <earliest>$time_window.earliest$</earliest>
          <latest>$time_window.latest$</latest>
        </search>
      </table>
    </panel>
  </row>
</form>
`))
