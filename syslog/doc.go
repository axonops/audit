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

// Package syslog provides an RFC 5424 syslog [audit.Output] implementation
// supporting TCP, UDP, and TCP+TLS (including mTLS) transport.
//
// # Construction
//
// [New] dials the syslog server immediately — the server must be
// reachable at construction time:
//
//	out, err := syslog.New(&syslog.Config{
//	    Network: "tcp+tls",
//	    Address: "syslog.example.com:6514",
//	    TLSCA:   "/etc/audit/ca.pem",
//	})
//
// Valid [Config.Network] values: "tcp" (default), "udp", "tcp+tls".
// Use "tcp+tls" with [Config.TLSCert] and [Config.TLSKey] for mTLS.
//
// # Reconnection
//
// TCP and TLS connections are re-established automatically on write
// failure, up to [Config.MaxRetries] attempts (default 10). UDP is
// connectionless and does not reconnect, but messages exceeding the
// UDP MTU are silently truncated by the network.
//
// To observe reconnect events, wire an [audit.OutputMetrics] value via
// [WithOutputMetrics] at construction. If the value also implements
// [ReconnectRecorder] its RecordReconnect method is called on each
// reconnect attempt (structural typing — no explicit registration
// needed).
//
// Recommended import alias:
//
//	import auditsyslog "github.com/axonops/audit/syslog"
package syslog
