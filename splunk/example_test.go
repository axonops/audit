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

package splunk_test

import (
	"fmt"

	"github.com/axonops/audit/splunk"
)

// ExampleNew shows the minimal construction shape against the
// default `/event` endpoint with JSON envelope wrapping and the
// `Authorization: Splunk <token>` header.
//
// In production code, pass a real [audit.OutputMetrics] via
// [splunk.WithOutputMetrics]. The auditor will wire the output via
// [audit.WithOutputs] (or via the outputconfig YAML loader) and
// call `Write` on every emitted event.
func ExampleNew() {
	// Note: this example does NOT contact a real Splunk endpoint —
	// DisableStartupVerification skips the /health probe so the
	// example can run without network access.
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		Sourcetype:                 "axonops:audit",
		Index:                      "audit_logs",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()

	// In real code: pass the output to audit.New via audit.WithOutputs.
	fmt.Println(out.Name() != "")
	// Output: true
}

// ExampleNew_raw shows the `/services/collector/raw` endpoint mode,
// where events are sent as newline-delimited bodies and metadata
// travels in the URL query string. Useful when consumer events are
// already line-oriented (e.g. CEF) and Splunk-side `props.conf`
// owns the parsing.
func ExampleNew_raw() {
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		Endpoint:                   splunk.EndpointRaw,
		Sourcetype:                 "axonops:audit",
		Source:                     "axonops-audit",
		Index:                      "audit_logs",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()
	fmt.Println("ok")
	// Output: ok
}

// ExampleConfig_redaction demonstrates that Config's String /
// GoString / Format methods redact the token across every fmt verb.
// This is a load-bearing security guarantee — the token must NEVER
// appear in log lines, error messages, or stack traces.
func ExampleConfig_redaction() {
	cfg := splunk.Config{
		URL:   "https://splunk.example.com:8088",
		Token: "super-secret-token",
	}
	fmt.Println(cfg.String())
	// Output: SplunkConfig{url="https://splunk.example.com:8088", endpoint=event, sourcetype="", index="", gzip=<default>, batch_size=0, max_batch_bytes=0, ack_mode=off, token=REDACTED}
}

// ExampleNew_cimJSON wires the Splunk output with the
// [audit.CIMChangeFormatter] (`type: cim_change` in YAML). Pair
// with the reference Splunk Technology Add-on (or your own
// generated TA) so Splunk indexes the events as CIM Change.
//
// The formatter is wired at the AUDITOR level (via
// audit.WithFormatter or per-output config) — splunk.Output itself
// is formatter-agnostic. This example shows the construction shape;
// in production, outputconfig YAML composes the auditor and the
// output via the cim_change formatter declaration.
func ExampleNew_cimJSON() {
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		Sourcetype:                 "axonops:audit",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()
	fmt.Println("constructed for CIM Change pipeline")
	// Output: constructed for CIM Change pipeline
}

// ExampleNew_ackRequired shows the compliance-grade durability
// mode. With AckMode=Required, events stay in an in-flight buffer
// until Splunk's /services/collector/ack endpoint returns positive
// for the batch's ackID. On AckResendWindow timeout, the events
// re-send. The producer (Write) remains non-blocking — when the
// in-flight buffer reaches BufferSize, new batches drop with
// metric reason=ack_buffer_full instead of stalling.
//
// The HEC token MUST have ACK enabled on its channel. The library
// feature-detects at startup and refuses to launch with
// [splunk.ErrAckDisabled] if ACK is not enabled.
func ExampleNew_ackRequired() {
	cfg := &splunk.Config{
		URL:                        "https://splunk.example.com:8088",
		Token:                      "your-hec-token",
		AckMode:                    splunk.AckModeRequired,
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()
	fmt.Println("ack mode:", cfg.AckMode)
	// Output: ack mode: required
}

// ExampleNew_splunkCloud uses the `splunkcloud://<stack>` URL
// shortcut. The library expands the stack name (validated against
// `^[a-z0-9][a-z0-9-]{0,62}$`) to the canonical Splunk Cloud HEC URL
// `https://http-inputs-<stack>.splunkcloud.com:443`.
//
// Splunk Cloud HEC does not support mTLS — configuring TLSCert,
// TLSKey, or TLSCA with a `splunkcloud://` URL is rejected at
// config validation. Use a self-managed HTTPS proxy with mTLS
// termination if mTLS is required.
func ExampleNew_splunkCloud() {
	cfg := &splunk.Config{
		URL:                        "splunkcloud://acme-prod",
		Token:                      "your-hec-token",
		DisableStartupVerification: true,
	}
	out, err := splunk.New(cfg, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = out.Close() }()
	// Name() reflects the EXPANDED URL host.
	fmt.Println(out.Name())
	// Output: splunk:http-inputs-acme-prod.splunkcloud.com:443
}
