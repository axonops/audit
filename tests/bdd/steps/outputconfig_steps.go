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

	"github.com/axonops/audit/outputconfig"
)

// registerOutputConfigSteps registers step definitions for output config
// YAML loading scenarios (queue_size, buffer_size, etc.).
func registerOutputConfigSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit // BDD step registration
	var (
		yamlData   []byte
		loadResult *outputconfig.LoadResult
	)

	ctx.Step(`^the following outputs YAML:$`, func(doc *godog.DocString) error {
		yamlData = []byte(doc.Content)
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
			for _, o := range result.Outputs {
				tc.AddCleanup(func() { _ = o.Output.Close() })
			}
		}
		return nil
	})

	ctx.Step(`^the config should load successfully$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected successful config load, got: %w", tc.LastErr)
		}
		return nil
	})

	ctx.Step(`^the loaded config queue_size should be (\d+)$`, func(expected int) error {
		if loadResult == nil {
			return fmt.Errorf("no load result available")
		}
		if loadResult.Config.QueueSize != expected {
			return fmt.Errorf("expected queue_size %d, got %d", expected, loadResult.Config.QueueSize)
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
}
