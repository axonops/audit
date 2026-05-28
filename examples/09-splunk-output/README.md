[← Back to examples](../README.md)

> **Previous:** [08 — Loki Output](../08-loki-output/) |
> **Next:** [10 — Multi-Output](../10-multi-output/)

# Example 09: Splunk HEC Output

Sends audit events directly to Splunk with **CIM-compliant field
mapping** and **at-least-once delivery via indexer acknowledgement**
— so Enterprise Security correlation searches find your audit data
without per-event mapping rules and compliance auditors can
demonstrate no event was silently dropped.

Implementation: events go to the [HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
(`/services/collector/event`) on [Splunk Enterprise](https://www.splunk.com/)
or Splunk Cloud, formatted by the
[`CIMChangeFormatter`](../../docs/splunk-output.md#formatter-choice-json-vs-cim_change)
so every event already carries the CIM Change keys
(`user_id`, `action`, `object_id`, `status`, …). Pair with the
[reference Technology Add-on](../../deploy/splunk-ta-axonops-audit/)
to get `tag=change` and `tag=authentication` applied at index time.

## 30-second quickstart

```bash
# 1. Start Splunk (x86 only — see Prerequisites for arm64 caveat).
docker run -d --name splunk \
  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e SPLUNK_PASSWORD=ChangeMeForRealUse123! \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_HEC_TOKEN=example-hec-token \
  -e SPLUNK_HEC_SSL=False \
  splunk/splunk:10.4-rhel9

# 2. Wait ~3 minutes for HEC.
until curl -s http://localhost:8088/services/collector/health | grep -q 'HEC is healthy'; do sleep 5; done

# 3. Generate typed builders + run.
go generate ./... && go run .
```

Expected: four `Audited: …` lines printed, then `Done. Search
your events:` with a copy-pasteable `curl` to Splunk's search REST.

Read on for the why (CIM mapping, ACK modes, reference TA), the
Splunk Cloud variant, and the production checklist.

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

> **⚠️ Apple Silicon (arm64) users:** Splunk does NOT publish an
> arm64 container image. This example requires an `x86_64` host —
> CI x86 runner, Linux/Intel laptop, or Mac with Docker Desktop's
> x86 emulation enabled. Without emulation the `docker run` below
> will fail at image pull or container start.

Start a local Splunk Enterprise container. The `SPLUNK_HEC_TOKEN`
value below MUST match the `token:` field in `outputs.yaml`
(`example-hec-token`) — change one, change the other:

```bash
docker run -d --name splunk \
  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e SPLUNK_PASSWORD=ChangeMeForRealUse123! \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_HEC_TOKEN=example-hec-token \
  -e SPLUNK_HEC_SSL=False \
  splunk/splunk:10.4-rhel9
```

Splunk's startup takes 2–3 minutes. Wait for HEC to be reachable
(bounded at 5 minutes — if the loop doesn't exit by then, run
`docker logs splunk` for licence/port issues):

```bash
deadline=$((SECONDS+300))
until curl -s http://localhost:8088/services/collector/health \
  | grep -q 'HEC is healthy'; do
  if [ $SECONDS -gt $deadline ]; then
    echo "Splunk did not become healthy within 5 minutes — check 'docker logs splunk'"
    exit 1
  fi
  sleep 5
done
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

## What the HEC POST Body Looks Like

Each batched event lands at HEC as a JSON envelope. For the first
`user_create` event in this example, the wire payload is:

```json
{
  "time": 1747830712.345,
  "host": "dev-machine",
  "source": "audit",
  "sourcetype": "axonops:audit",
  "index": "main",
  "event": {
    "_time": 1747830712.345,
    "action": "user_create",
    "app_name": "audit-example-splunk",
    "dvc": "dev-machine",
    "host": "dev-machine",
    "object_category": "topic",
    "object_id": "topic-orders",
    "outcome": "success",
    "severity_id": 3,
    "status": "success",
    "user_id": "alice",
    "vendor_product": "AxonOps:Audit"
  }
}
```

The envelope's `host`/`source`/`sourcetype`/`index` fields are
metadata Splunk consumes directly (they become the standard
`_host`/`_source` etc. on the indexed event). The `event` object
is what Splunk stores as `_raw` and what CIM correlation searches
field-extract via the reference TA's `KV_MODE = json`.

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

> **Note:** the `splunk restart` step takes another 30–60 seconds
> and bounces the HEC listener — re-run the
> `until curl … HEC is healthy` loop from Prerequisites before
> running the example. Production deployments install the TA via
> Splunkbase or an apps-deployment pipeline so the restart happens
> during a planned maintenance window, not on every run. For
> repeated local iteration, bind-mount the TA into the container
> at create-time (see
> [`tests/bdd/docker-compose.splunk.yml`](../../tests/bdd/docker-compose.splunk.yml)
> for the staged-copy pattern) to avoid the restart entirely.

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
→ Enable indexer acknowledgement**. (The docker-splunk image does
not consistently honour an `SPLUNK_HEC_USEACK` env var across
releases; the Splunk Web toggle is the reliable path. For
provisioning-as-code, bake an `inputs.conf` with `useACK = 1` into
a custom Splunk image or bind-mount it into
`/opt/splunk/etc/apps/splunk_httpinput/local/`.)

**For an audit/compliance library, `required` is the right
default.** Compliance auditors typically demand at-least-once
evidence of delivery — `best_effort` records telemetry but does
not gate the producer, so a buffer overflow during an indexer
outage silently drops events. Use `best_effort` only when you
have an upstream durable queue (Kafka, NATS JetStream, etc.) that
already provides at-least-once semantics. Use `off` only for
non-compliance signals where dropping under stress is acceptable.

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
      source: "audit"                # Splunk metadata `_source`; how operators
                                     # distinguish audit-pipeline events from
                                     # application logs in the same index
      index: "main"                  # set via `splunk add index <name>` first
      allow_insecure_http: true      # http:// only — production uses https
      allow_private_ranges: true     # localhost — blocks RFC1918 by default

      batch_size: 10                 # push after 10 events (demo value; default 500)
      flush_interval: "1s"           # or 1 second, whichever first (demo value; default 2s)
      timeout: "10s"
      max_retries: 5                 # retry transient HEC 5xx with exponential backoff
      gzip: true

      formatter:
        type: cim_change             # rename audit fields → CIM keys
        vendor_product: "AxonOps:Audit"

      ack_mode: "off"                # see "Indexer Acknowledgement" above
```

The `batch_size: 10` and `flush_interval: 1s` values above are
demo settings — they prioritise visibility (events appear in
Splunk within ~1 second of running the example) over throughput.
Production deployments should use the library defaults
(`batch_size: 500` and `flush_interval: 2s`) unless you have
measured a different target.

Splunk Cloud deployments can use the convenience URL form
[`splunkcloud://<stack-name>`](../../docs/splunk-output.md#splunk-cloud-specifics)
which expands to the public-CA-signed HEC endpoint.

## Splunk Cloud — Drop-in Configuration

Splunk Cloud customers don't need the Docker prerequisite at all
— the HEC endpoint is provided by the stack. Replace the
`outputs.yaml::splunk_audit` block above with this, then run
`go run .` exactly as documented:

```yaml
outputs:
  splunk_audit:
    type: splunk
    splunk:
      # `splunkcloud://<stack-name>` expands to
      # `https://http-inputs-<stack-name>.splunkcloud.com:443`.
      # Only `[a-z0-9][a-z0-9-]{0,62}` is accepted; the library
      # rejects anything else at construction time to prevent
      # URL-injection foot-guns.
      url: "splunkcloud://acme-prod"

      # Token from Splunk Cloud's Settings → Data inputs → HTTP
      # Event Collector → ⟨your-token⟩. Use a secret-resolver
      # reference rather than a literal in production —
      # `token: ${env:SPLUNK_HEC_TOKEN}` reads from the env at
      # outputconfig.New time and the literal never lands in the
      # repo.
      token: "${env:SPLUNK_HEC_TOKEN}"

      sourcetype: "axonops:audit"
      index: "main"

      # DELETE the two dev-only flags from the self-hosted block:
      # the Splunk Cloud URL is https and the dial target is
      # public-CA-signed; default policies are correct.
      # allow_insecure_http: <REMOVE — Cloud is https only>
      # allow_private_ranges: <REMOVE — public IPs only>

      batch_size: 500                # library default — production scale
      flush_interval: "2s"           # library default
      timeout: "10s"
      max_retries: 5
      gzip: true

      formatter:
        type: cim_change
        vendor_product: "AxonOps:Audit"

      # ACK enablement on Splunk Cloud: Settings → Data inputs →
      # HTTP Event Collector → ⟨your-token⟩ → Enable indexer
      # acknowledgement. After enabling, set:
      ack_mode: "required"
```

A typical Splunk Cloud deployment differs from this self-hosted
example only in those four lines: `url`, `token`, the two removed
dev-only flags, and the recommended `ack_mode: required`.

## Blank Import — Splunk Ships Separately

The splunk output lives in its own Go module
(`github.com/axonops/audit/splunk`) and is published on an
independent release cadence. The `audit/outputs` convenience
aggregator registers the splunk factory alongside file/syslog/
webhook/loki, so most consumers only need ONE blank import:

```go
import (
    _ "github.com/axonops/audit/outputs" // stdout, file, syslog, webhook, loki, splunk
)
```

Smaller deployments that only want splunk can import the sub-module
on its own to avoid pulling in the other output transports:

```go
import (
    _ "github.com/axonops/audit/splunk"
)
```

(This example currently keeps an explicit `_ "audit/splunk"` import
in addition to `audit/outputs` while the aggregator's release pin
catches up — once the example's `go.mod` references the
splunk-bundled aggregator version, the second import can drop.)

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Invalid token` (HEC code 4) | `token` in outputs.yaml differs from the container's `SPLUNK_HEC_TOKEN` | Verify both are set to the same value (the example uses `example-hec-token`). |
| `ErrHealthCheckFailed` at startup | HEC not yet listening | Wait for Splunk's bootstrap to finish; see the `until curl …` loop above. |
| Events not appearing in search | TA not installed or wrong sourcetype | Install the TA per "Reference TA — Tag Application", or override the search to omit the sourcetype clause. |
| `must be https` error | `http://` URL without flag | Add `allow_insecure_http: true` (development only). |
| SSRF blocked on 127.0.0.1 | Private-range protection | Add `allow_private_ranges: true` (development only). |
| `ack_mode != off` errors at startup | HEC token does not have ACK enabled | Enable ACK on the token in Splunk Web, or set `ack_mode: "off"`. |

## Production Checklist

The defaults this example sets are tuned for a one-shot demo on
localhost. Before shipping to production, flip every line in this
table:

| Setting in this example | Production value | Why |
|---|---|---|
| `url: "http://localhost:8088"` | `https://<host>:8088` or `splunkcloud://<stack>` | HEC traffic crosses an untrusted network in any non-loopback deployment. |
| `allow_insecure_http: true` | DELETE (default `false`) | `http://` is rejected unless this flag is set; production MUST use `https://`. |
| `allow_private_ranges: true` | DELETE (default `false`) | SSRF protection blocks RFC1918 ranges by default; only needed for sidecar or air-gapped deployments. |
| `token: "example-hec-token"` | `token: ${env:SPLUNK_HEC_TOKEN}` or a secrets-provider reference | Never commit the literal HEC token. |
| `ack_mode: "off"` | `ack_mode: "required"` for compliance, `best_effort` if upstream provides at-least-once | See "Indexer Acknowledgement" above. |
| `batch_size: 10` / `flush_interval: 1s` | `batch_size: 500` / `flush_interval: 2s` (defaults) | Demo values prioritise visibility; defaults prioritise throughput. |
| `buffer_size: 1000` | Raise to absorb your peak burst | Buffer-full drops are silent except via the OutputMetrics counter — measure the high-water mark in production load tests and add ~30 %. |
| Reference TA via `docker cp` | TA installed via Splunkbase or apps provisioning pipeline | The docker-cp install is for the demo container; production TAs ship via your Splunk app-deployment process. |
| `verify_on_startup: <unset>` (default `true`) | Keep default | The startup probe surfaces misconfiguration at `audit.New` time instead of as silent loss on the first flush — important for boot-time fail-fast. |

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
- [CIM Change formatter](../../docs/splunk-output.md#formatter-choice-json-vs-cim_change) —
  formatter contract details.
