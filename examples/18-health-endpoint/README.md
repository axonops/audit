[← Back to examples](../README.md)

> **Previous:** [17 — Capstone](../17-capstone/)

# Example 18: Health Endpoint (`/healthz` and `/readyz`)

Demonstrates how to expose Kubernetes-style liveness and
readiness HTTP probes for a service that uses the audit library.
The handlers query the `Auditor`'s public introspection
primitives — no global state, no monkey-patching, no special
test hooks.

## What You'll Learn

- The difference between liveness and readiness, and what each
  should mean for an audit-using service.
- How to drive `/healthz` from `Auditor.QueueLen()` /
  `Auditor.QueueCap()`.
- How to drive `/readyz` from `Auditor.IsDisabled()` and
  `Auditor.OutputNames()`.
- Why the queue-saturation threshold (90 % by default) is a
  tuning knob and not a contract — and how to choose it.

## Liveness vs readiness

| Probe | What it asks | Failure consequence (Kubernetes) |
|---|---|---|
| Liveness (`/healthz`) | "Is this process healthy enough to keep running?" | Pod is restarted. |
| Readiness (`/readyz`) | "Should I send new traffic to this pod?" | Pod stays alive but is removed from the load balancer rotation. |

For an audit-using service the practical mapping is:

- **Liveness fail (queue jammed)** → there is no recovery from
  inside the process. Restart me.
- **Readiness fail (no outputs configured, or auditor disabled)**
  → I cannot accept events right now (e.g., still starting up,
  or a critical config issue caught at startup). Don't send me
  traffic yet, but don't restart — the operator may be in the
  middle of fixing the config.

A common mistake is to wire the same conditions into both
probes. Don't: a fault that is permanent (for the lifetime of
this pod) belongs in `/healthz`; a fault that is transient or
operator-correctable belongs in `/readyz`.

## Run

```bash
go run .
```

In another terminal:

```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```

You should see (note the blank line `curl -i` prints between
headers and body):

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"healthy","queue_len":0,"queue_cap":10,"saturation":0.00}
```

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ready","output_count":1,"outputs":["stdout"]}
```

A failing `/readyz` (e.g., `outputs.yaml` deleted before
startup) returns:

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{"status":"not-ready","reason":"no outputs configured"}
```

The example uses a tiny `queue_size: 10` (in `outputs.yaml`) and
emits one event per second from a background goroutine, so the
saturation indicator stays low. To see `/healthz` go red, drop
`queue_size` in `outputs.yaml` to `1` and shorten the
`time.NewTicker(1 * time.Second)` interval in `driveAuditLoop`
(`main.go`) to e.g. `1 * time.Millisecond` — the queue will
saturate and `/healthz` will return 503 with the observed
saturation in the body.

## How it Works

### `/healthz` — liveness

```go
func healthzHandler(a *audit.Auditor) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        queueLen := a.QueueLen()
        queueCap := a.QueueCap()
        var saturation float64
        if queueCap > 0 {
            saturation = float64(queueLen) / float64(queueCap)
        }
        if saturation > 0.90 {
            w.WriteHeader(http.StatusServiceUnavailable)
            // ... error body ...
            return
        }
        w.WriteHeader(http.StatusOK)
        // ... healthy body ...
    }
}
```

The 90 % threshold is the default the docs recommend. **Tune
for your workload.** A larger queue tolerates a higher absolute
backlog before declaring a fault; a smaller queue trips earlier.

**Worked example.** With `queue_size: 10000` and a sustained
drain rate of 5000 events/s, 90 % saturation = 9000 events ≈
1.8 s of backlog. Choose the threshold so that the absolute
backlog exceeds your Kubernetes probe's `failureThreshold ×
periodSeconds` — otherwise transient spikes will flap the probe.
The [Capacity Planning tier table](../../docs/deployment.md#capacity-planning)
gives concrete `queue_size` values per event-rate tier.

### `/readyz` — readiness

```go
func readyzHandler(a *audit.Auditor) http.HandlerFunc {
    return func(w http.ResponseWriter, _ *http.Request) {
        if a.IsDisabled() {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        if len(a.OutputNames()) == 0 {
            w.WriteHeader(http.StatusServiceUnavailable)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}
```

Both checks are sub-microsecond reads on internal state. Both
are safe to call concurrently from any goroutine.

**`/readyz` runtime semantics.** The output list is fixed at
auditor construction (in `outputconfig.New`); it does not flip
back to empty if a downstream output starts failing later. So
`/readyz` mostly catches the "auditor was disabled" or
"`outputs.yaml` was missing or empty at startup" case. To detect
a runtime delivery stall on a specific output, you need
`Auditor.LastDeliveryAge(name)` — see "What's NOT here" below.

## Production checklist

The example binds everything to one public listener (`:8080`)
for simplicity. Three things to change before deploying:

1. **Probes on a separate listener.** Bind probe traffic to
   localhost (or the pod IP only) so it skips the public
   authentication path:

   ```go
   probeMux := http.NewServeMux()
   probeMux.HandleFunc("/healthz", healthzHandler(auditor))
   probeMux.HandleFunc("/readyz", readyzHandler(auditor))
   probeSrv := &http.Server{
       Addr:              "127.0.0.1:9090",
       Handler:           probeMux,
       ReadHeaderTimeout: 5 * time.Second,
   }
   go probeSrv.ListenAndServe()
   ```

2. **Kubernetes Pod spec.** Reference the probe port from the
   container manifest:

   ```yaml
   livenessProbe:
     httpGet:
       path: /healthz
       port: 9090
       host: 127.0.0.1
     periodSeconds: 10
     failureThreshold: 3
   readinessProbe:
     httpGet:
       path: /readyz
       port: 9090
       host: 127.0.0.1
     periodSeconds: 5
     failureThreshold: 2
   ```

3. **Tune the saturation threshold** for your workload using
   the worked example above.

## What's NOT here

- **Per-output staleness**. A real production probe would also
  fail liveness if an output has not delivered an event in N
  seconds — a hung downstream syslog server, for example.
  Per-output staleness needs a new public API
  (`Auditor.LastDeliveryAge(outputName)`) that is tracked under
  [#753](https://github.com/axonops/audit/issues/753). Until
  that lands, the queue-saturation check catches the case where
  the slow output blocks the drain goroutine and the queue
  starts to fill.

- **Authentication on the probe endpoint**. Production probes
  typically run on a separate listener bound to localhost (or
  the pod IP only) so probe traffic doesn't hit the public
  authentication path. See the Production checklist above.

- **Runtime-configurable threshold.** This example uses a
  package-level `const` for the saturation threshold. Real
  services should expose this as a flag or env var so operators
  can tune without redeploying.

## Files

| File | Purpose |
|---|---|
| `main.go` | The HTTP server, the two handlers, and a background loop emitting one audit event per second so the queue shows non-zero depth. |
| `taxonomy.yaml` | Minimal taxonomy with one event type (`health_probe`). |
| `audit_generated.go` | `audit-gen` output (run `go generate` to regenerate). |
| `outputs.yaml` | Single stdout output; tiny `queue_size` so the saturation knob is observable. |

## Copying this example to your own project

`go run .` works inside the workspace because `outputconfig.New`
reads `outputs.yaml` from the current working directory. If you
copy this example into your own repository:

1. Follow the [For Consumers Outside the Workspace](../README.md#for-consumers-outside-the-workspace)
   instructions to fetch `github.com/axonops/audit`,
   `github.com/axonops/audit/outputconfig`, and
   `github.com/axonops/audit/outputs`.
2. To regenerate `audit_generated.go`, install the code generator
   first:

   ```bash
   go install github.com/axonops/audit/cmd/audit-gen@latest
   go generate ./...
   ```

3. Either run the binary from the directory containing
   `outputs.yaml`, or pass an absolute path to
   `outputconfig.New`. The taxonomy is embedded via `go:embed`
   and travels with the binary; `outputs.yaml` is a runtime
   config file and does not.

For the complete `Auditor` introspection surface (signatures,
return values, concurrency guarantees) see the
[godoc](https://pkg.go.dev/github.com/axonops/audit#Auditor).
