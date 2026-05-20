# TA-axonops-audit — Reference Splunk Technology Add-on

This is the reference Splunk Technology Add-on (TA) for the
[`github.com/axonops/audit`](https://github.com/axonops/audit)
library's Splunk HEC output with the `cim_change` formatter.

> **This TA is generated.** The source is the taxonomy YAML at
> [`internal/schemagen/reference_ta_taxonomy.yaml`](../../internal/schemagen/reference_ta_taxonomy.yaml).
> Regenerate via `make ta`. Do not edit files in this directory by
> hand — they will be overwritten on the next regen.

## What it does

- Maps audit events emitted via the `cim_change` formatter to the
  Splunk Common Information Model (CIM) **Change** data model.
- Security events (categories: `auth`, `authentication`, `security`,
  `access`) also receive the CIM **Authentication** tag.
- Stamps `vendor_product` as a per-TA constant (`AxonOps:Audit`).
- Provides a starter dashboard at `Audit Events` showing event-type
  breakdown, success/failure ratio, and a recent-events table.

## Installation

### Splunk Enterprise (self-managed)

```bash
# Copy the TA into $SPLUNK_HOME/etc/apps/
sudo cp -r deploy/splunk-ta-axonops-audit /opt/splunk/etc/apps/TA-axonops-audit
sudo /opt/splunk/bin/splunk restart
```

### Splunk Cloud

1. Package the TA: `tar czf TA-axonops-audit.tar.gz -C deploy splunk-ta-axonops-audit`
2. Upload via Splunk Web → **Apps** → **Manage Apps** → **Install
   app from file**.
3. Splunk Cloud customers may need to file a support ticket to
   install custom TAs that haven't been published to Splunkbase.

## HEC token configuration

The TA expects events with `sourcetype=axonops:audit`. Create a HEC
token in Splunk Web → **Settings** → **Data inputs** → **HTTP Event
Collector** with:

- **Source type:** `axonops:audit` (matches the default the library
  emits).
- **Index:** any index your audit retention policy targets.
- **Indexer Acknowledgment:** enable if your library config uses
  `ack_mode: best_effort` or `ack_mode: required`.

## Verification (AppInspect)

The reference TA passes
[Splunk AppInspect](https://dev.splunk.com/enterprise/docs/developapps/testvalidate/appinspect/)
with zero failures at `--mode precert`:

```bash
pip install splunk-appinspect
splunk-appinspect inspect --mode precert deploy/splunk-ta-axonops-audit/
```

CI runs this automatically on every commit via the
`splunk-ta-appinspect` job.

## Customisation

Two ways to deviate from this reference TA:

1. **Recommended** — regenerate from your own taxonomy YAML:

   ```bash
   go run github.com/axonops/audit/cmd/audit-gen \
     --format=splunk-ta \
     --input <your-taxonomy.yaml> \
     --output <your-ta-dir> \
     --vendor-product "MyVendor:MyProduct" \
     --splunk-ta-name TA-myvendor-audit \
     --splunk-ta-version 1.0.0
   ```

2. **Editable overrides** — add a `local/` subdirectory next to
   `default/` with your own `props.conf`/`tags.conf` stanzas.
   Splunk merges `local/` over `default/` on top of the generated
   tree. Never edit `default/` directly — the next `make ta`
   regeneration will overwrite your changes.

See [`docs/splunk-ta.md`](../../docs/splunk-ta.md) for the full
operator walkthrough.

## Files

| Path | Purpose |
|---|---|
| `default/app.conf` | App metadata for Splunk's installer. |
| `default/props.conf` | Index-time JSON extraction + EVAL constants. |
| `default/eventtypes.conf` | One stanza per (category, event) pair. |
| `default/tags.conf` | CIM `change` (+ `authentication`) tag bindings. |
| `default/data/ui/views/audit_events.xml` | Starter dashboard view. |
| `metadata/default.meta` | App-wide visibility for eventtypes/tags. |
