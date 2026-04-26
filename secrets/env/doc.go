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

// Package env implements the env:// secret provider for the audit
// library. Resolves secrets from process environment variables.
//
// # Reference syntax
//
//	ref+env://VAR_NAME
//
// The path is the variable name and MUST match the POSIX form
// `[A-Z_][A-Z0-9_]*`. Fragments are not supported and are rejected
// with an error.
//
// # When to use
//
// Use env:// for development, CI, and small deployments where
// secrets are passed via the process environment. For production
// Kubernetes deployments, prefer [github.com/axonops/audit/secrets/file]
// reading from `/var/run/secrets/...` because env values are
// visible to any process running as the same UID via
// `/proc/PID/environ`.
//
// # Registration
//
// Blank-import the package to register the provider with the
// outputconfig loader:
//
//	import _ "github.com/axonops/audit/secrets/env"
//
// # Threat model
//
// Environment variables are visible to any process running as the
// same UID via `/proc/PID/environ` (Linux) or equivalent
// per-platform mechanisms. They also appear in process listings
// when set via the `env` command at exec time. For stronger
// isolation use file:// (filesystem permissions on the secret file)
// or vault/openbao (out-of-process secret store with audit log).
package env
