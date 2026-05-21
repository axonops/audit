[← Back to examples](../README.md)

> **Previous:** [20 — Capstone](../20-capstone/) |
> **Next:** end of series

# Example 21: Splunk HEC Output

Sends audit events to a [Splunk Enterprise](https://www.splunk.com/)
instance via the [HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
(HEC), with the CIM Change formatter for CIM-compliant indexed
fields and the reference Technology Add-on for tag-based search.

## What You'll Learn

1. How audit events are pushed to Splunk via the HEC `/event`
   endpoint with batching, gzip, and retry-on-5xx semantics.
2. How the **CIM Change formatter** renames audit fields to
   CIM-canonical names (`actor_id → user_id`, `event_type → action`,
   `target_id → object_id`, …) so events flow into the Splunk
   Common Information Model.
3. How the **reference TA** (`deploy/splunk-ta-axonops-audit/`)
   applies the `change` and `authentication` tags at index time so
   Enterprise Security correlation searches find audit events.
4. How **indexer acknowledgement** (`ack_mode: off | best_effort |
   required`) provides delivery telemetry or at-least-once
   semantics.

## Prerequisites

Splunk does not publish an arm64 container image. This example
requires an `x86_64` host (CI x86 runner, Linux/Intel laptop, or
Mac with Docker Desktop x86 emulation).

Start a local Splunk Enterprise container:

```bash
docker run -d --name splunk \
  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e SPLUNK_PASSWORD=ChangeMeForRealUse123! \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_HEC_TOKEN=example-hec-token \
  -e SPLUNK_HEC_SSL=False \
  splunk/splunk:10.4-rhel9
```

Splunk's startup takes 2–3 minutes. Wait for HEC to be reachable:

```bash
until curl -s http://localhost:8088/services/collector/health \
  | grep -q 'HEC is healthy'; do sleep 5; done
```

## Files

| File | Purpose |
|------|---------|
| [`main.go`](main.go) | Creates an auditor with a Splunk output and audits 4 events |
| [`outputs.yaml`](outputs.yaml) | YAML configuration for the Splunk output (HEC URL, token, batching, ACK, CIM formatter) |
| [`taxonomy.yaml`](taxonomy.yaml) | 4 event types across 2 categories (`account`, `security`) |
| [`audit_generated.go`](audit_generated.go) | Generated typed builders (created by `go generate`) |
| [`README.md`](README.md) | This file |

## Running the Example

```bash
go generate ./...
go run .
```

**Output:**

```
Audited: user_create by alice
Audited: user_update by alice
Audited: login_success by alice
Audited: login_failure by mallory

Waiting for Splunk delivery...
Done. Search your events:
  # All events from this app:
  curl -s -k -u admin:'ChangeMeForRealUse123!' \
    'https://localhost:8089/services/search/jobs/export' \
    --data-urlencode 'search=search index=main sourcetype="axonops:audit" app_name="audit-example-splunk"' \
    --data-urlencode 'exec_mode=oneshot' --data-urlencode 'output_mode=json' | jq '.result'
```

## What Happens Under the Hood

1. **Taxonomy loaded** — `taxonomy.yaml` defines 4 event types
   across 2 categories (`account` and `security`).
2. **Splunk output created** — `outputs.yaml` configures the HEC
   URL, token, sourcetype, batching, retries, and the CIM Change
   formatter.
3. **Events audited** — each event is validated against the
   taxonomy, formatted as CIM Change JSON, enqueued in the splunk
   output's internal buffer.
4. **Batch flushed** — the batch loop POSTs the gzip-compressed
   batch to `http://localhost:8088/services/collector/event`.
   HEC's success/error code maps to the library's
   action-dispatch table (success → flush, code 24 → capacity
   warning, code 4/7 → stop, codes 8/9 → retry).
5. **Events queryable** — events appear in `index=main` with
   sourcetype `axonops:audit` within ~1 second.

## CIM Change Formatter — Field Renames

With `formatter: { type: cim_change, vendor_product: "AxonOps:Audit" }`,
the audit-canonical field names are remapped to CIM Change keys
before serialisation:

| Audit field | CIM Change key |
|-------------|----------------|
| `event_type` | `action` |
| `actor_id` | `user_id` |
| `target_id` | `object_id` |
| `target_type` | `object_category` |
| `outcome` | `status` (collapsed to `success` or `failure`) |
| `source_ip` | `src` |

Splunk's CIM Change data model then recognises these fields and
populates correlation searches without per-event mapping rules.

## Reference TA — Tag Application

The reference Splunk Technology Add-on at
[`deploy/splunk-ta-axonops-audit/`](../../deploy/splunk-ta-axonops-audit/)
applies CIM tags at index time. Install it once via:

```bash
docker cp deploy/splunk-ta-axonops-audit \
  splunk:/opt/splunk/etc/apps/TA-axonops-audit
docker exec splunk /opt/splunk/bin/splunk restart
```

After install:

- Every audit event carries `tag=change` — Enterprise Security's
  Change Analysis searches find audit events automatically.
- Events from the `security` category also carry
  `tag=authentication` — login_success and login_failure surface
  in the Authentication data model.
- `vendor_product` is forced to `AxonOps:Audit` via the TA's
  EVAL clause so per-event override cannot pollute the field.
- Indexed-time field extraction (`KV_MODE = json`) makes every
  CIM key searchable directly without `| spath`.

See [`docs/splunk-ta.md`](../../docs/splunk-ta.md) for the full
TA install walkthrough and customisation guide.

## Indexer Acknowledgement (`ack_mode`)

```yaml
ack_mode: "off"             # default — no telemetry
ack_mode: "best_effort"     # poll /ack, record telemetry; never gate
ack_mode: "required"        # at-least-once with resend on timeout
```

`best_effort` and `required` modes require the HEC token to have
indexer acknowledgement enabled. Set this in Splunk Web at
**Settings → Data inputs → HTTP Event Collector → ⟨your-token⟩
→ Enable indexer acknowledgement**, or enable it on the test
container by passing `SPLUNK_HEC_USEACK=1` to docker run (Splunk
10.x+).

For most deployments `best_effort` is the right choice: every
batch is verified asynchronously without blocking the producer.
Use `required` only when at-least-once semantics matter more than
throughput.

## YAML Configuration Explained

Key fields in [`outputs.yaml`](outputs.yaml):

```yaml
outputs:
  splunk_audit:
    type: splunk
    splunk:
      url: "http://localhost:8088"   # HEC endpoint (no path)
      token: "example-hec-token"     # never log this; library redacts in String/GoString
      sourcetype: "axonops:audit"    # matches the reference TA's props.conf stanza
      index: "main"                  # set via `splunk add index <name>` first
      allow_insecure_http: true      # http:// only — production uses https
      allow_private_ranges: true     # localhost — blocks RFC1918 by default

      batch_size: 10                 # push after 10 events
      flush_interval: "1s"           # or 1 second, whichever first
      timeout: "10s"
      max_retries: 5                 # retry transient HEC 5xx with exponential backoff
      gzip: true

      formatter:
        type: cim_change             # rename audit fields → CIM keys
        vendor_product: "AxonOps:Audit"

      ack_mode: "off"                # see "Indexer Acknowledgement" above
```

Splunk Cloud deployments can use the convenience URL form
[`splunkcloud://<stack-name>`](../../docs/splunk-output.md#splunk-cloud-shorthand)
which expands to the public-CA-signed HEC endpoint.

## Splunk Cloud — Shorthand URL

```yaml
url: "splunkcloud://acme-prod"
# expands to: https://http-inputs-acme-prod.splunkcloud.com:443
```

Only `[a-z0-9][a-z0-9-]{0,62}` is accepted for the stack name —
the library rejects anything else at construction time to prevent
URL-injection foot-guns.

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Invalid token` (HEC code 4) | `token` in outputs.yaml differs from the container's `SPLUNK_HEC_TOKEN` | Verify both are set to the same value (the example uses `example-hec-token`). |
| `ErrHealthCheckFailed` at startup | HEC not yet listening | Wait for Splunk's bootstrap to finish; see the `until curl …` loop above. |
| Events not appearing in search | TA not installed or wrong sourcetype | Install the TA per "Reference TA — Tag Application", or override the search to omit the sourcetype clause. |
| `must be https` error | `http://` URL without flag | Add `allow_insecure_http: true` (development only). |
| SSRF blocked on 127.0.0.1 | Private-range protection | Add `allow_private_ranges: true` (development only). |
| `ack_mode != off` errors at startup | HEC token does not have ACK enabled | Enable ACK on the token in Splunk Web, or set `ack_mode: "off"`. |

## Blank Import — Splunk Ships Separately

The splunk output lives in its own Go module
(`github.com/axonops/audit/splunk`) and is published on an
independent release cadence from `github.com/axonops/audit/outputs`.
At the time of writing, the pinned `audit/outputs v0.1.13` release
does not yet include the splunk factory, so this example imports
splunk explicitly:

```go
import (
    _ "github.com/axonops/audit/outputs" // stdout, file, syslog, webhook, loki
    _ "github.com/axonops/audit/splunk"  // splunk (until outputs aggregator catches up)
)
```

Once a release of `audit/outputs` that includes the splunk factory
is published, the second import becomes optional — but harmless to
keep. Smaller deployments that only want splunk can also import
just the splunk sub-module on its own, which avoids pulling in the
other output transports.

## Cleanup

```bash
docker stop splunk && docker rm splunk
```

## Further Reading

- [Splunk Output Reference](../../docs/splunk-output.md) — full
  configuration, testing layers, ACK semantics, Splunk Cloud
  shorthand, and troubleshooting.
- [Splunk TA Generator](../../docs/splunk-ta.md) — generate a
  TA from your own taxonomy.
- [Output Types](../../docs/outputs.md#splunk-output) — Splunk
  section with security and delivery details.
- [CIM Change formatter](../../docs/json-format.md#cim-change-formatter) —
  formatter contract details.
