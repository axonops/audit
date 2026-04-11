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

package steps

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/go-audit/outputconfig"
	"github.com/axonops/go-audit/secrets"
)

// ---------------------------------------------------------------------------
// Mock secret provider
// ---------------------------------------------------------------------------

// mockSecretProvider is a thin in-memory implementation of
// [secrets.Provider] used by BDD scenarios. It is constructed via
// Given steps and consulted by a registered LoadOption during
// outputconfig.Load. Call counts are tracked atomically so scenarios
// can assert on the number of provider invocations.
type mockSecretProvider struct { //nolint:govet // readability over alignment
	scheme string
	data   map[string]map[string]string // path → {key → value}
	delay  time.Duration                // optional delay to simulate slow responses
	calls  atomic.Int64
}

// Compile-time interface check — mock implements BatchProvider.
var _ secrets.BatchProvider = (*mockSecretProvider)(nil)

func (m *mockSecretProvider) Scheme() string { return m.scheme }

func (m *mockSecretProvider) Resolve(ctx context.Context, ref secrets.Ref) (string, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("mock provider: %w", ctx.Err())
		case <-time.After(m.delay):
		}
	}
	keys, ok := m.data[ref.Path]
	if !ok {
		return "", fmt.Errorf("%w: path %q", secrets.ErrSecretNotFound, ref.Path)
	}
	val, ok := keys[ref.Key]
	if !ok {
		return "", fmt.Errorf("%w: key %q at path %q", secrets.ErrSecretNotFound, ref.Key, ref.Path)
	}
	return val, nil
}

func (m *mockSecretProvider) ResolvePath(ctx context.Context, path string) (map[string]string, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("mock provider: %w", ctx.Err())
		case <-time.After(m.delay):
		}
	}
	keys, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("%w: path %q", secrets.ErrSecretNotFound, path)
	}
	return keys, nil
}

func (m *mockSecretProvider) Close() error { return nil }

func (m *mockSecretProvider) String() string {
	return fmt.Sprintf("mock{scheme: %s, [REDACTED]}", m.scheme)
}

// ---------------------------------------------------------------------------
// Secret-related TestContext extensions
// ---------------------------------------------------------------------------

// currentMockProvider returns the most recently registered mock provider.
// Panics if none has been registered; scenarios must register one first.
func (tc *TestContext) currentMockProvider() *mockSecretProvider {
	if tc.MockProvider == nil {
		panic("no mock secret provider has been registered for this scenario")
	}
	return tc.MockProvider
}

// ---------------------------------------------------------------------------
// Step registration
// ---------------------------------------------------------------------------

func registerSecretSteps(ctx *godog.ScenarioContext, tc *TestContext) {
	ctx.Step(
		`^a mock secret provider with scheme "([^"]*)"$`,
		func(scheme string) error {
			return tc.stepRegisterMockProvider(scheme, 0)
		},
	)

	ctx.Step(
		`^a mock secret provider with scheme "([^"]*)" that delays (\d+)ms$`,
		func(scheme string, delayMs int) error {
			return tc.stepRegisterMockProvider(scheme, time.Duration(delayMs)*time.Millisecond)
		},
	)

	ctx.Step(
		`^a nil secret provider is registered$`,
		func() error {
			tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(nil))
			return nil
		},
	)

	ctx.Step(
		`^the mock provider has secret at path "([^"]*)" key "([^"]*)" value "([^"]*)"$`,
		tc.stepAddSecret,
	)

	ctx.Step(
		`^the mock provider call count should be (\d+)$`,
		tc.stepAssertCallCount,
	)

	ctx.Step(
		`^the environment variable "([^"]*)" is set to "([^"]*)"$`,
		tc.stepSetEnvVar,
	)

	ctx.Step(
		`^the secret resolution timeout is (\d+)ms$`,
		func(ms int) error {
			tc.SecretTimeout = time.Duration(ms) * time.Millisecond
			return nil
		},
	)

	ctx.Step(
		`^the following output configuration YAML with secret providers:$`,
		tc.stepLoadYAMLWithProviders,
	)

	ctx.Step(
		`^the config load should fail$`,
		tc.stepAssertConfigLoadFailed,
	)

	ctx.Step(
		`^the error message should not contain "([^"]*)"$`,
		tc.stepAssertErrorNotContains,
	)
}

// ---------------------------------------------------------------------------
// Step implementations
// ---------------------------------------------------------------------------

// stepRegisterMockProvider creates a new mock and appends it to LoadOptions.
// MockProvider always points to the LAST registered mock. When called twice
// with the same scheme (duplicate-scheme test), both providers land in
// LoadOptions but MockProvider tracks only the second — this is intentional
// since duplicate-scheme scenarios never call stepAddSecret or stepAssertCallCount.
func (tc *TestContext) stepRegisterMockProvider(scheme string, delay time.Duration) error {
	tc.MockProvider = &mockSecretProvider{
		scheme: scheme,
		data:   make(map[string]map[string]string),
		delay:  delay,
	}
	tc.LoadOptions = append(tc.LoadOptions, outputconfig.WithSecretProvider(tc.MockProvider))
	return nil
}

func (tc *TestContext) stepAddSecret(path, key, value string) error {
	p := tc.currentMockProvider()
	if p.data[path] == nil {
		p.data[path] = make(map[string]string)
	}
	p.data[path][key] = value
	return nil
}

func (tc *TestContext) stepAssertCallCount(want int) error {
	p := tc.currentMockProvider()
	got := int(p.calls.Load())
	if got != want {
		return fmt.Errorf("mock provider call count: got %d, want %d", got, want)
	}
	return nil
}

func (tc *TestContext) stepSetEnvVar(name, value string) error {
	if err := os.Setenv(name, value); err != nil {
		return fmt.Errorf("set env var %q: %w", name, err)
	}
	tc.envVarsSet = append(tc.envVarsSet, name)
	return nil
}

func (tc *TestContext) stepLoadYAMLWithProviders(doc *godog.DocString) error {
	dir, err := os.MkdirTemp("", "bdd-secrets-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	tc.FileDir = dir
	if err := os.Setenv("AUDIT_BDD_DIR", dir); err != nil {
		return fmt.Errorf("set AUDIT_BDD_DIR: %w", err)
	}

	opts := make([]outputconfig.LoadOption, len(tc.LoadOptions))
	copy(opts, tc.LoadOptions)
	if tc.SecretTimeout > 0 {
		opts = append(opts, outputconfig.WithSecretTimeout(tc.SecretTimeout))
	}

	result, loadErr := outputconfig.Load(
		context.Background(),
		[]byte(doc.Content),
		tc.Taxonomy,
		opts...,
	)
	if loadErr != nil {
		tc.LastErr = loadErr
		return nil //nolint:nilerr // scenario asserts on tc.LastErr
	}
	tc.Options = result.Options
	tc.LoadResult = result
	return nil
}

func (tc *TestContext) stepAssertConfigLoadFailed() error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected config load to fail, but it succeeded")
	}
	return nil
}

func (tc *TestContext) stepAssertErrorNotContains(substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected an error but got none; cannot check for absent substring %q", substr)
	}
	if strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("error message must not contain %q, but it does: %s",
			substr, tc.LastErr.Error())
	}
	return nil
}
