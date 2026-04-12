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

package outputconfig

import (
	"context"
	"fmt"
	"time"

	"github.com/axonops/audit/secrets"
)

// MaxSecretValueSize is the maximum size in bytes for a resolved
// secret value. Values exceeding this limit are rejected.
const MaxSecretValueSize = 64 << 10 // 64 KiB

// resolver holds registered secret providers and dual-level caches
// for deduplicating API calls within a single Load invocation.
// Providers implementing [secrets.BatchProvider] get path-level
// caching (one call per unique path). Others get ref-level caching
// (one call per unique scheme+path+key).
type resolver struct {
	providers map[string]secrets.Provider  // scheme → provider
	pathCache map[string]map[string]string // "scheme://path" → {key → value} (batch providers)
	refCache  map[string]string            // "scheme://path#key" → value (non-batch providers)
}

// newResolver builds a resolver from the providers registered via
// [WithSecretProvider]. Returns (nil, nil) when no providers are
// registered. Returns an error if duplicate schemes are detected.
func newResolver(providers []secrets.Provider) (*resolver, error) {
	if len(providers) == 0 {
		return nil, nil //nolint:nilnil // nil = no secret resolution
	}
	r := &resolver{
		providers: make(map[string]secrets.Provider, len(providers)),
		pathCache: make(map[string]map[string]string),
		refCache:  make(map[string]string),
	}
	for _, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("%w: secret provider must not be nil", ErrOutputConfigInvalid)
		}
		scheme := p.Scheme()
		if _, dup := r.providers[scheme]; dup {
			return nil, fmt.Errorf("%w: duplicate secret provider for scheme %q",
				ErrOutputConfigInvalid, scheme)
		}
		r.providers[scheme] = p
	}
	return r, nil
}

// resolve fetches a secret value, using path-level caching for
// [secrets.BatchProvider] implementations and ref-level caching for
// standard providers.
func (r *resolver) resolve(ctx context.Context, ref secrets.Ref, fieldPath string) (string, error) { //nolint:gocyclo,cyclop,gocognit // dual-cache resolution with batch/single paths
	pathKey := ref.Scheme + "://" + ref.Path

	// Check path-level cache first (batch providers).
	if cached, ok := r.pathCache[pathKey]; ok {
		val, found := cached[ref.Key]
		if !found {
			return "", fmt.Errorf("%w: key %q not found at cached path (field %s)",
				secrets.ErrSecretNotFound, ref.Key, fieldPath)
		}
		if val == "" {
			return "", fmt.Errorf("%w: secret resolved to empty value (field %s)",
				secrets.ErrSecretResolveFailed, fieldPath)
		}
		if len(val) > MaxSecretValueSize {
			return "", fmt.Errorf("%w: secret value exceeds maximum size %d bytes (field %s)",
				secrets.ErrSecretResolveFailed, MaxSecretValueSize, fieldPath)
		}
		return val, nil
	}

	// Check ref-level cache (non-batch providers).
	refKey := pathKey + "#" + ref.Key
	if val, ok := r.refCache[refKey]; ok {
		return val, nil
	}

	// Look up provider.
	provider, ok := r.providers[ref.Scheme]
	if !ok {
		return "", fmt.Errorf("%w: scheme %q (field %s)",
			secrets.ErrProviderNotRegistered, ref.Scheme, fieldPath)
	}

	// Check context before network call.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("secret resolution cancelled (field %s): %w", fieldPath, err)
	}

	// Try batch resolution first (path-level cache).
	if bp, ok := provider.(secrets.BatchProvider); ok {
		allKeys, err := bp.ResolvePath(ctx, ref.Path)
		if err != nil {
			return "", fmt.Errorf("field %s: %w", fieldPath, err)
		}
		// Cache the entire path response. Validation happens per-key
		// at extraction time — peer keys may have valid-but-empty
		// values for flags, which should not block the requested key.
		r.pathCache[pathKey] = allKeys
		val, found := allKeys[ref.Key]
		if !found {
			return "", fmt.Errorf("%w: key %q not found at path (field %s)",
				secrets.ErrSecretNotFound, ref.Key, fieldPath)
		}
		if val == "" {
			return "", fmt.Errorf("%w: secret resolved to empty value (field %s)",
				secrets.ErrSecretResolveFailed, fieldPath)
		}
		if len(val) > MaxSecretValueSize {
			return "", fmt.Errorf("%w: secret value exceeds maximum size %d bytes (field %s)",
				secrets.ErrSecretResolveFailed, MaxSecretValueSize, fieldPath)
		}
		return val, nil
	}

	// Fallback: single-key resolve with ref-level cache.
	val, err := provider.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("field %s: %w", fieldPath, err)
	}

	// Validate resolved value.
	if val == "" {
		return "", fmt.Errorf("%w: secret resolved to empty value (field %s)",
			secrets.ErrSecretResolveFailed, fieldPath)
	}
	if len(val) > MaxSecretValueSize {
		return "", fmt.Errorf("%w: secret value exceeds maximum size %d bytes (field %s)",
			secrets.ErrSecretResolveFailed, MaxSecretValueSize, fieldPath)
	}

	r.refCache[refKey] = val
	return val, nil
}

// contextWithSecretTimeout returns a context with the secret
// resolution timeout applied. The caller's existing deadline takes
// precedence when it is earlier than the configured timeout.
func contextWithSecretTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline, hasDeadline := parent.Deadline()
	secretDeadline := time.Now().Add(timeout)
	if !hasDeadline || secretDeadline.Before(deadline) {
		return context.WithDeadline(parent, secretDeadline)
	}
	return context.WithCancel(parent) // caller's deadline is already earlier
}

// expandSecretsInValue walks a parsed YAML value tree and resolves
// ref+SCHEME://PATH#KEY references in string-typed leaf values.
// Map keys are never scanned. Resolved values are NOT re-scanned
// (single-pass guarantee). Returns the value unchanged when r is nil.
func expandSecretsInValue(ctx context.Context, v any, fieldPath string, r *resolver) (any, error) { //nolint:gocognit,gocyclo,cyclop // recursive tree walk mirrors expandEnvInValue
	if r == nil {
		return v, nil
	}

	switch val := v.(type) {
	case string:
		ref, err := secrets.ParseRef(val)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", fieldPath, err)
		}
		if ref.IsZero() {
			return val, nil // not a ref — literal value
		}
		resolved, rErr := r.resolve(ctx, ref, fieldPath)
		if rErr != nil {
			return nil, rErr
		}
		return resolved, nil

	case map[string]any:
		for key, child := range val {
			childPath := fieldPath
			if childPath != "" {
				childPath += "."
			}
			childPath += key
			expanded, err := expandSecretsInValue(ctx, child, childPath, r)
			if err != nil {
				return nil, err
			}
			val[key] = expanded
		}
		return val, nil

	case []any:
		for i, child := range val {
			childPath := fmt.Sprintf("%s[%d]", fieldPath, i)
			expanded, err := expandSecretsInValue(ctx, child, childPath, r)
			if err != nil {
				return nil, err
			}
			val[i] = expanded
		}
		return val, nil

	default:
		// Numbers, booleans, nil — no resolution needed.
		return v, nil
	}
}

// validateNoUnresolvedRefs scans a parsed YAML value tree for any
// remaining ref+ URI patterns. Returns [secrets.ErrUnresolvedRef] if
// any string leaf contains a ref+ URI after all resolution passes.
func validateNoUnresolvedRefs(v any, fieldPath string) error { //nolint:gocognit,cyclop // recursive tree walk
	switch val := v.(type) {
	case string:
		if secrets.ContainsRef(val) {
			return fmt.Errorf("%w: field %s still contains a secret reference",
				secrets.ErrUnresolvedRef, fieldPath)
		}
		return nil

	case map[string]any:
		for key, child := range val {
			childPath := fieldPath
			if childPath != "" {
				childPath += "."
			}
			childPath += key
			if err := validateNoUnresolvedRefs(child, childPath); err != nil {
				return err
			}
		}
		return nil

	case []any:
		for i, child := range val {
			childPath := fmt.Sprintf("%s[%d]", fieldPath, i)
			if err := validateNoUnresolvedRefs(child, childPath); err != nil {
				return err
			}
		}
		return nil

	default:
		return nil
	}
}

// expandOutputSecrets resolves ref+ URIs in the per-output config
// fields (type config, route, formatter). HMAC is NOT included here —
// it is handled by buildHMACConfig with its disabled-bypass logic.
func expandOutputSecrets(ctx context.Context, name string, f *outputFields, r *resolver) error {
	if r == nil {
		return nil
	}
	base := "outputs." + name
	if f.typeConfigRaw != nil {
		expanded, err := expandSecretsInValue(ctx, f.typeConfigRaw, base+"."+f.typeName, r)
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.typeConfigRaw = expanded
	}
	if f.routeRaw != nil {
		expanded, err := expandSecretsInValue(ctx, f.routeRaw, base+".route", r)
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.routeRaw = expanded
	}
	if f.formatterRaw != nil {
		expanded, err := expandSecretsInValue(ctx, f.formatterRaw, base+".formatter", r)
		if err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
		f.formatterRaw = expanded
	}
	return nil
}

// validateOutputNoUnresolvedRefs runs the safety-net scan on all
// per-output raw fields that were subject to expansion.
func validateOutputNoUnresolvedRefs(name string, f *outputFields) error {
	base := "outputs." + name
	if f.typeConfigRaw != nil {
		if err := validateNoUnresolvedRefs(f.typeConfigRaw, base+"."+f.typeName); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	if f.routeRaw != nil {
		if err := validateNoUnresolvedRefs(f.routeRaw, base+".route"); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	if f.formatterRaw != nil {
		if err := validateNoUnresolvedRefs(f.formatterRaw, base+".formatter"); err != nil {
			return fmt.Errorf("output %q: %w", name, err)
		}
	}
	return nil
}
