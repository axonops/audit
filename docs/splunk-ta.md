[← Back to Splunk Output](splunk-output.md)

# Splunk TA Generator — Operator Guide

The `audit-gen` CLI emits a minimal Splunk Technology Add-on (TA)
from a taxonomy YAML. The generated TA configures the Splunk side
of the integration — sourcetype-to-CIM mapping, eventtype
definitions, CIM tags — that complements the library's `splunk`
output + `cim_change` formatter.

- [When to use the generator](#when-to-use-the-generator)
- [Quick Start](#quick-start)
- [The Six Generated Files](#the-six-generated-files)
- [CIM Tag Inference Rules](#cim-tag-inference-rules)
- [Customising the Output](#customising-the-output)
- [Installing the TA](#installing-the-ta)
- [Verifying with AppInspect](#verifying-with-appinspect)
- [Regenerating Without Drift](#regenerating-without-drift)
- [Limitations](#limitations)

---

## When to use the generator

| You have | Use |
|---|---|
| The library's stock taxonomy (no custom event types) | The pre-built [reference TA](../deploy/splunk-ta-axonops-audit/) at `deploy/splunk-ta-axonops-audit/`. |
| A custom taxonomy with your own event types | The generator (`audit-gen --format=splunk-ta`). |
| A non-trivial custom taxonomy AND custom Splunk searches/dashboards/risk-modifiers | The generator + your own `local/` overrides on top of the generated tree. |

The TA generator is intentionally minimal. It does NOT generate:

- `fields.conf` — `INDEXED_EXTRACTIONS = json` automatically extracts
  every JSON key, so a static field declaration is unnecessary for
  CIM compliance.
- `savedsearches.conf` — risk modifiers and scheduled searches are
  consumer-specific. Add them in your own app's `local/` directory.
- `transforms.conf` — required only for non-JSON field extractions.

---

## Quick Start

```bash
go run github.com/axonops/audit/cmd/audit-gen \
  --format=splunk-ta \
  --input my-taxonomy.yaml \
  --output ./my-ta
```

This produces the directory tree:

```
my-ta/
├── default/
│   ├── app.conf
│   ├── props.conf
│   ├── eventtypes.conf
│   ├── tags.conf
│   └── data/ui/views/audit_events.xml
└── metadata/
    └── default.meta
```

Optional flags:

| Flag | Default | Purpose |
|---|---|---|
| `--vendor-product` | `AxonOps:Audit` | The CIM `vendor_product` value stamped as an EVAL constant in `props.conf`. Override to identify your deployment uniquely. |
| `--splunk-ta-name` | `TA-axonops-audit` | The Splunk app id. MUST match the basename of `--output` (AppInspect rejects mismatches). |
| `--splunk-ta-version` | `0.1.0` | The version stamped into `app.conf`. Use semver. |

Example with a custom vendor:

```bash
go run github.com/axonops/audit/cmd/audit-gen \
  --format=splunk-ta \
  --input my-taxonomy.yaml \
  --output ./TA-myvendor-audit \
  --vendor-product "MyVendor:AuditApp" \
  --splunk-ta-name TA-myvendor-audit \
  --splunk-ta-version 1.0.0
```

---

## The Six Generated Files

### `default/app.conf`

App metadata for Splunk's installer — `[install]`, `[ui]`,
`[launcher]`, `[package]`, `[id]` stanzas. `ui.is_visible = false`
because TAs are configuration-only; they don't surface in the
Splunk app launcher.

### `default/props.conf`

The load-bearing file. Configures the sourcetype:

```ini
[axonops:audit]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIMESTAMP_FIELDS = _time
TIME_FORMAT = %s.%3N
EVAL-vendor_product = "AxonOps:Audit"
EVAL-dvc = if(isnotnull(dvc), dvc, host)
```

- `INDEXED_EXTRACTIONS = json` extracts every JSON key at index
  time — no FIELDALIAS rules needed because the `cim_change`
  formatter already emits CIM-named keys.
- `KV_MODE = none` prevents Splunk from running a second
  search-time extraction over the same fields.
- `TIMESTAMP_FIELDS = _time` + `TIME_FORMAT = %s.%3N` consumes
  the CIM canonical epoch-seconds-with-ms-precision timestamp.
- `EVAL-vendor_product` stamps a per-TA constant so operator-
  supplied values can't pollute the CIM `vendor_product` field.
- `EVAL-dvc` ensures the CIM Change required `dvc` field is
  non-null even for events that don't carry an explicit `dvc`.

### `default/eventtypes.conf`

One stanza per `(category, event_type)` pair in the taxonomy:

```ini
[account_user_create]
search = sourcetype="axonops:audit" event_type="user_create"
```

The stanza name is `<category>_<event_type>` (sanitised to
ASCII-safe characters).

### `default/tags.conf`

CIM tag bindings:

```ini
[eventtype=account_user_create]
change = enabled

[eventtype=security_login_failure]
change = enabled
authentication = enabled
```

Every eventtype gets `change = enabled` (CIM Change is the root
data model for audit events). Categories matching the CIM
Authentication data model also get `authentication = enabled` —
see [CIM Tag Inference Rules](#cim-tag-inference-rules).

### `default/data/ui/views/audit_events.xml`

A starter dashboard with three panels:

1. **Events by Type** (column chart) — `stats count by action`.
2. **Failure Rate** (pie chart) — `stats count by status` (CIM
   Change binary).
3. **Recent Audit Events** (table) — `table _time action user_name
   object object_category status src dvc`.

Customise via your own `local/data/ui/views/*.xml` overrides.

### `metadata/default.meta`

Marks the TA's eventtypes, tags, and props as `export = system`
so dashboards in other apps can use them. Without this, the
eventtypes / tags are app-private.

---

## CIM Tag Inference Rules

The generator infers `authentication = enabled` on a per-category
basis. A category is treated as an authentication category if its
name (case-insensitive) is one of:

- `auth`
- `authentication`
- `security`
- `access`

This is a starting heuristic, not a constraint. To customise:

1. **Recommended** — rename your taxonomy categories to match the
   generator's rules.
2. **Editable override** — add a `local/tags.conf` to your TA with
   the corrected stanzas. Splunk merges `local/` over `default/`.

---

## Customising the Output

The generator's templates are not user-configurable on the
command line beyond the three flags listed above. For deeper
customisation:

1. **`local/` overrides** — Splunk merges `local/` over `default/`
   per stanza/key. Add a `local/props.conf` with extra `EVAL-*`
   rules, or a `local/tags.conf` with additional data-model tags
   (e.g., `network = enabled` for events that should also satisfy
   CIM Network Traffic).
2. **Post-process the generator output** — run `audit-gen
   --format=splunk-ta` once, then commit + manually edit. Pair
   with `make ta-diff-check` only if you're not modifying the
   generated files (the diff check verifies the committed tree
   matches the generator output).
3. **Fork the generator** — for projects that need a different
   shape, copy `cmd/audit-gen/splunk_ta.go` into your own tool
   and modify the templates.

---

## Installing the TA

### Splunk Enterprise

```bash
sudo cp -r ./TA-myvendor-audit /opt/splunk/etc/apps/TA-myvendor-audit
sudo /opt/splunk/bin/splunk restart
```

### Splunk Cloud

1. Package the TA: `tar czf TA-myvendor-audit.tar.gz TA-myvendor-audit`
2. Upload via Splunk Web → **Apps** → **Manage Apps** → **Install
   app from file**.
3. Splunk Cloud may require a support ticket for custom TAs that
   haven't been published to Splunkbase. Consider publishing your
   TA (see Splunk's [Splunkbase publishing docs](https://dev.splunk.com/enterprise/docs/releaseapps/)).

---

## Verifying with AppInspect

[Splunk AppInspect](https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/)
is the Splunkbase publishing gate. Run it locally:

```bash
pip install splunk-appinspect
splunk-appinspect inspect --mode precert --included-tags cloud ./my-ta
```

- `--mode precert` — the Splunkbase publishing gate (stricter than
  `--mode test`).
- `--included-tags cloud` — focuses on rules that matter for Splunk
  Cloud (the most restrictive deployment target).

The library's CI runs this against the reference TA on every
commit. Any failure blocks merge.

---

## Regenerating Without Drift

If you commit a generated TA into your own repository (the library
does this for the reference TA at `deploy/splunk-ta-axonops-audit/`),
guard against drift between the source taxonomy and the committed
output:

```makefile
# Mirrors the library's `make ta-diff-check` target.
ta-diff-check:
	@TMP=$$(mktemp -d); \
	go run github.com/axonops/audit/cmd/audit-gen --format=splunk-ta \
		--input my-taxonomy.yaml --output "$$TMP/ta" >/dev/null && \
	if ! diff -qr --exclude=README.md "$$TMP/ta" ./my-ta >/dev/null; then \
		echo "./my-ta is stale; run 'make ta'"; \
		diff -ur --exclude=README.md ./my-ta "$$TMP/ta"; \
		rm -rf "$$TMP"; exit 1; \
	fi; \
	rm -rf "$$TMP"
```

Wire `ta-diff-check` into your CI's static-analysis job so a stale
TA fails the build.

---

## Limitations

- **`/raw` endpoint not supported.** The generator targets the
  `/event` endpoint's JSON envelope; the `/raw` endpoint requires
  per-source TIME_PREFIX / LINE_BREAKER configuration that's
  consumer-specific.
- **CIM Authentication is a hint, not a contract.** The
  `authentication = enabled` tag is inferred from category names;
  for full Authentication data-model compliance, you may need to
  add `app`, `dest`, `src_user` field extractions in a
  `local/props.conf` override.
- **No risk modifiers / savedsearches.** Enterprise Security risk
  scoring requires `savedsearches.conf` entries that are
  threat-model-specific. Add your own in `local/`.
- **No `transforms.conf`.** If your sourcetype isn't pure JSON,
  the generated TA won't work — extend with a `local/` override.

---

## Related

- [Splunk Output](splunk-output.md) — the library-side configuration
  that pairs with this TA.
- [Code Generation](code-generation.md) — the broader `audit-gen`
  documentation covering Go source / JSON Schema / CEF template
  generation.
- [Reference TA](../deploy/splunk-ta-axonops-audit/README.md) —
  the pre-built TA for the library's stock taxonomy.
