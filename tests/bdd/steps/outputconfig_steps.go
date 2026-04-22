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
	"strings"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
)

// registerOutputConfigSteps registers step definitions for output config
// YAML loading scenarios (queue_size, buffer_size, output metrics factory, etc.).
func registerOutputConfigSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,cyclop,gocyclo // BDD step registration
	var (
		yamlData    []byte
		loadResult  *outputconfig.Loaded
		auditorOwns bool // true once an auditor takes ownership of loadResult's outputs
	)

	// Reset closure state at each scenario start so state does not leak
	// between scenarios within the same suite run.
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		yamlData = nil
		loadResult = nil
		auditorOwns = false
		return c, nil
	})

	ctx.Step(`^the following outputs YAML:$`, func(doc *godog.DocString) error {
		yamlData = []byte(doc.Content)
		return nil
	})

	ctx.Step(`^a mock output metrics factory is configured$`, func() error {
		tc.OutputMetricsFactoryMock = NewMockOutputMetricsFactory()
		return nil
	})

	ctx.Step(`^I load the outputs config$`, func() error {
		if tc.Taxonomy == nil {
			return fmt.Errorf("no taxonomy configured — add 'Given a standard test taxonomy' before loading")
		}
		result, err := outputconfig.Load(context.Background(), yamlData, tc.Taxonomy)
		loadResult = result
		tc.LastErr = err
		// Close outputs to prevent goroutine leaks in tests.
		if result != nil {
			tc.AddCleanup(func() {
				// Close only when no auditor took ownership — otherwise
				// Auditor.Close has already closed these outputs and a
				// second Close violates the Loaded.Close contract.
				if !auditorOwns {
					_ = result.Close()
				}
			})
		}
		return nil
	})

	ctx.Step(`^I load the outputs config with the output metrics factory$`, func() error {
		if tc.Taxonomy == nil {
			return fmt.Errorf("no taxonomy configured — add 'Given a standard test taxonomy' before loading")
		}
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory configured — add 'And a mock output metrics factory is configured' first")
		}
		result, err := outputconfig.Load(context.Background(), yamlData, tc.Taxonomy,
			outputconfig.WithOutputMetrics(tc.OutputMetricsFactoryMock.Factory()),
		)
		loadResult = result
		tc.LastErr = err
		if result != nil {
			tc.AddCleanup(func() {
				// Close only when no auditor took ownership — otherwise
				// Auditor.Close has already closed these outputs and a
				// second Close violates the Loaded.Close contract.
				if !auditorOwns {
					_ = result.Close()
				}
			})
		}
		return nil
	})

	ctx.Step(`^I load the outputs config without an output metrics factory$`, func() error {
		if tc.Taxonomy == nil {
			return fmt.Errorf("no taxonomy configured — add 'Given a standard test taxonomy' before loading")
		}
		result, err := outputconfig.Load(context.Background(), yamlData, tc.Taxonomy)
		loadResult = result
		tc.LastErr = err
		if result != nil {
			tc.AddCleanup(func() {
				// Close only when no auditor took ownership — otherwise
				// Auditor.Close has already closed these outputs and a
				// second Close violates the Loaded.Close contract.
				if !auditorOwns {
					_ = result.Close()
				}
			})
		}
		return nil
	})

	ctx.Step(`^I create an auditor from the loaded config$`, func() error {
		if loadResult == nil {
			return fmt.Errorf("no load result available — load the outputs config first")
		}
		opts := append([]audit.Option{audit.WithTaxonomy(tc.Taxonomy)}, loadResult.Options()...)
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("failed to create auditor from loaded config: %w", err)
		}
		auditorOwns = true
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the config should load successfully$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected successful config load, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the auditor queue_size should be (\d+)$`, func(expected int) error {
		if loadResult == nil {
			return fmt.Errorf("no load result available — load the outputs config first")
		}
		opts := append([]audit.Option{audit.WithTaxonomy(tc.Taxonomy)}, loadResult.Options()...)
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor from loaded config: %w", err)
		}
		auditorOwns = true
		tc.AddCleanup(func() { _ = auditor.Close() })
		if qc := auditor.QueueCap(); qc != expected {
			return fmt.Errorf("expected queue_size %d, got QueueCap %d", expected, qc)
		}
		return nil
	})

	ctx.Step(`^the config load should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the output metrics factory should have been called (\d+) times?$`, func(expected int) error {
		if tc.OutputMetricsFactoryMock == nil {
			if expected == 0 {
				return nil
			}
			return fmt.Errorf("no output metrics factory mock configured, expected %d calls", expected)
		}
		actual := tc.OutputMetricsFactoryMock.CallCount()
		if actual != expected {
			return fmt.Errorf("expected factory called %d times, got %d", expected, actual)
		}
		return nil
	})

	ctx.Step(`^the output metrics factory should have been called with type "([^"]*)" and name "([^"]*)"$`, func(outputType, outputName string) error {
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory mock configured")
		}
		if !tc.OutputMetricsFactoryMock.WasCalledWith(outputType, outputName) {
			return fmt.Errorf("factory was not called with type=%q name=%q; calls: %v",
				outputType, outputName, tc.OutputMetricsFactoryMock.GetCalls())
		}
		return nil
	})

	ctx.Step(`^the metrics instance for "([^"]*)" should not be the same as "([^"]*)"$`, func(keyA, keyB string) error {
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory mock configured")
		}
		partsA := strings.SplitN(keyA, ":", 2)
		partsB := strings.SplitN(keyB, ":", 2)
		if len(partsA) != 2 || len(partsB) != 2 {
			return fmt.Errorf("keys must be in 'type:name' format, got %q and %q", keyA, keyB)
		}
		mA := tc.OutputMetricsFactoryMock.MetricsFor(partsA[0], partsA[1])
		mB := tc.OutputMetricsFactoryMock.MetricsFor(partsB[0], partsB[1])
		if mA == nil {
			return fmt.Errorf("no metrics instance for %q", keyA)
		}
		if mB == nil {
			return fmt.Errorf("no metrics instance for %q", keyB)
		}
		if mA == mB {
			return fmt.Errorf("metrics instances for %q and %q are the same pointer", keyA, keyB)
		}
		return nil
	})

	ctx.Step(`^the output metrics for "([^"]*)" should have recorded at least (\d+) flush`, func(key string, minFlushes int) error {
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory mock configured")
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("key must be in 'type:name' format, got %q", key)
		}
		m := tc.OutputMetricsFactoryMock.MetricsFor(parts[0], parts[1])
		if m == nil {
			return fmt.Errorf("no metrics instance for %q", key)
		}
		actual := m.FlushCount()
		if actual < minFlushes {
			return fmt.Errorf("expected at least %d flushes for %q, got %d", minFlushes, key, actual)
		}
		return nil
	})

	ctx.Step(`^the output metrics for "([^"]*)" should have recorded (\d+) errors?$`, func(key string, expected int) error {
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory mock configured")
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("key must be in 'type:name' format, got %q", key)
		}
		m := tc.OutputMetricsFactoryMock.MetricsFor(parts[0], parts[1])
		if m == nil {
			return fmt.Errorf("no metrics instance for %q", key)
		}
		actual := m.ErrorCount()
		if actual != expected {
			return fmt.Errorf("expected %d errors for %q, got %d", expected, key, actual)
		}
		return nil
	})

	ctx.Step(`^the output metrics for "([^"]*)" should have recorded (\d+) drops?$`, func(key string, expected int) error {
		if tc.OutputMetricsFactoryMock == nil {
			return fmt.Errorf("no output metrics factory mock configured")
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("key must be in 'type:name' format, got %q", key)
		}
		m := tc.OutputMetricsFactoryMock.MetricsFor(parts[0], parts[1])
		if m == nil {
			return fmt.Errorf("no metrics instance for %q", key)
		}
		actual := m.DropCount()
		if actual != expected {
			return fmt.Errorf("expected %d drops for %q, got %d", expected, key, actual)
		}
		return nil
	})

	ctx.Step(`^I load the outputs config with a nil-returning output metrics factory$`, func() error {
		if tc.Taxonomy == nil {
			return fmt.Errorf("no taxonomy configured — add 'Given a standard test taxonomy' before loading")
		}
		nilFactory := func(_, _ string) audit.OutputMetrics {
			return nil
		}
		result, err := outputconfig.Load(context.Background(), yamlData, tc.Taxonomy,
			outputconfig.WithOutputMetrics(nilFactory),
		)
		loadResult = result
		tc.LastErr = err
		if result != nil {
			tc.AddCleanup(func() {
				// Close only when no auditor took ownership — otherwise
				// Auditor.Close has already closed these outputs and a
				// second Close violates the Loaded.Close contract.
				if !auditorOwns {
					_ = result.Close()
				}
			})
		}
		return nil
	})
}
