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

package env

import (
	"context"
	"fmt"
	"os"

	"github.com/axonops/audit/secrets"
)

// Scheme is the URI scheme this provider handles. Use it as the
// scheme component in `ref+env://VAR_NAME` references.
const Scheme = "env"

// Provider implements [secrets.SecretProvider] for environment-
// variable secret references. The zero value is ready to use; the
// provider is stateless and safe for concurrent use by multiple
// goroutines.
type Provider struct{}

// Compile-time interface satisfaction check.
var _ secrets.Provider = (*Provider)(nil)

// New returns a new env:// secret provider. The provider is
// stateless and accepts no configuration.
func New() *Provider {
	return &Provider{}
}

// Scheme returns the URI scheme this provider handles ("env").
func (*Provider) Scheme() string { return Scheme }

// Close is a no-op. The env provider holds no resources to release.
// Idempotent; safe to call multiple times.
func (*Provider) Close() error { return nil }

// Resolve fetches the value of the environment variable named by
// ref.Path. Returns [secrets.ErrSecretResolveFailed] when the
// variable is unset or set to an empty string. Empty audit
// secrets are never legitimate, so set-to-empty is treated
// identically to unset.
//
// The variable name in the input ref is NOT echoed in the error
// message — knowing which env var your config consults is itself
// information a log scraper should not gain. Callers wanting to
// distinguish unset / empty / invalid-name during local debugging
// should inspect the returned error chain via [errors.Is] against
// [secrets.ErrSecretResolveFailed] and read the diagnostic message
// in the auditor's slog output (which is typically stderr, not
// shipped to a log aggregator).
func (*Provider) Resolve(_ context.Context, ref secrets.Ref) (string, error) {
	if err := ref.Valid(); err != nil {
		return "", fmt.Errorf("audit/secrets/env: %w", err)
	}
	if ref.Scheme != Scheme {
		// Should never happen — outputconfig dispatches by scheme —
		// but redact the scheme just in case to avoid leaking what
		// providers a deployment uses.
		return "", fmt.Errorf("audit/secrets/env: unexpected scheme: %w", secrets.ErrMalformedRef)
	}
	if ref.Key != "" {
		// env:// has no key/fragment concept — silently dropping it
		// would mask consumer typos that should fail loudly.
		return "", fmt.Errorf("audit/secrets/env: fragment not supported: %w", secrets.ErrMalformedRef)
	}
	if !validEnvName(ref.Path) {
		return "", fmt.Errorf("audit/secrets/env: invalid variable name (redacted): %w", secrets.ErrMalformedRef)
	}
	val, ok := os.LookupEnv(ref.Path)
	if !ok {
		return "", fmt.Errorf("audit/secrets/env: variable not set (redacted): %w", secrets.ErrSecretResolveFailed)
	}
	if val == "" {
		return "", fmt.Errorf("audit/secrets/env: variable resolved to empty value (redacted): %w", secrets.ErrSecretResolveFailed)
	}
	return val, nil
}

// validEnvName reports whether s is a valid POSIX environment-
// variable name: leading character `[A-Z_]`, subsequent characters
// `[A-Z0-9_]`, non-empty. Hand-rolled linear scan — no regexp
// import (avoids any ReDoS surface and keeps the sub-module
// dependency footprint minimal).
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case i == 0 && (r == '_' || (r >= 'A' && r <= 'Z')):
			// valid leading character
		case i > 0 && (r == '_' || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z')):
			// valid subsequent character
		default:
			return false
		}
	}
	return true
}
