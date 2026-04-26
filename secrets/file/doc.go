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

// Package file implements the file:// secret provider for the
// audit library. Resolves secrets from filesystem paths — the
// canonical pattern for Kubernetes mounted secrets at
// `/var/run/secrets/...`.
//
// # Reference syntax
//
//	ref+file:///var/run/secrets/myapp/token       — whole file
//	ref+file:///etc/secrets/db.json#password      — JSON, fragment
//	ref+file:///etc/secrets/cfg.json#tls.ca       — dotted fragment
//
// Without a fragment, the entire file content is the secret value
// (a single trailing newline is trimmed). With a fragment, the
// file is parsed as JSON and the fragment is interpreted as a
// dotted path into nested objects, returning the scalar string
// leaf.
//
// # When to use
//
// Use file:// for Kubernetes mounted secrets, Docker secrets, and
// any deployment that supplies secrets via the filesystem. K8s
// atomically swaps `..data` symlinks on rotation; this provider
// follows symlinks and re-reads on every Resolve, so consumers
// that re-resolve (e.g. on SIGHUP) pick up rotated values.
//
// # Registration
//
// Blank-import the package to register the provider with the
// outputconfig loader:
//
//	import _ "github.com/axonops/audit/secrets/file"
//
// # Path validation
//
// The path MUST be absolute, MUST NOT contain `..` segments, and
// MUST NOT contain a NUL byte. Symlinks are followed (required for
// the Kubernetes `..data` atomic-swap pattern).
//
// # File size cap
//
// Each Resolve reads at most 1 MiB. A file larger than the cap
// returns [secrets.ErrSecretResolveFailed].
//
// # Threat model
//
// The path in `outputs.yaml` is the trust boundary. The provider
// will follow symlinks and read whatever is at the target;
// operators are responsible for ensuring filesystem permissions
// match their threat model. The library does NOT enforce a
// permission-mode check (K8s mounts at 0644 by default —
// enforcement would break the dominant use case). All errors
// redact the path; an attacker reading library logs cannot infer
// the secret-mount layout from error messages alone.
package file
