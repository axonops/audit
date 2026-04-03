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

// Package loki provides a Grafana Loki output for the go-audit library.
//
// The output pushes audit events to a Loki instance via the HTTP Push
// API (POST /loki/api/v1/push). Events are batched and delivered as
// JSON-encoded push requests with configurable stream labels, gzip
// compression, multi-tenant support, and TLS.
//
// # Stream Labels
//
// Users control which fields become Loki stream labels via the Labels
// configuration. Static labels (e.g., job, environment) are constant
// across all events. Dynamic labels (event_type, severity,
// event_category, app_name, host, pid) are derived per-event from
// [audit.EventMetadata] via the [audit.MetadataWriter] interface.
//
// Custom user-defined fields are never labels — they stay in the log
// line and are queryable via LogQL JSON parsing:
//
//	{event_type="auth_failure"} | json | actor_id="alice"
//
// # Batching
//
// Events are buffered internally and flushed when the batch reaches
// [Config.BatchSize] events, [Config.MaxBatchBytes] total payload
// bytes, or [Config.FlushInterval] elapses — whichever comes first.
// The [Output.Close] method flushes any remaining events.
//
// # Import
//
// Import this package for its side effect of registering the "loki"
// output type with the audit output registry:
//
//	import _ "github.com/axonops/go-audit/loki"
package loki
