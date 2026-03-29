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
	"fmt"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

func registerMetricsSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^mock metrics are configured$`, func() error {
		tc.MockMetrics = NewMockMetrics()
		return nil
	})

	ctx.Step(`^a logger with stdout output and metrics$`, func() error {
		tc.Options = append(tc.Options, audit.WithMetrics(tc.MockMetrics))
		return createStdoutLogger(tc, audit.Config{Version: 1, Enabled: true})
	})

	ctx.Step(`^a filtering taxonomy with only "write" enabled$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(filteringTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse filtering taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^the metrics should have recorded event "([^"]*)" for output "([^"]*)"$`, func(status, output string) error {
		// Close to flush async events through the pipeline.
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		tc.MockMetrics.mu.Lock()
		defer tc.MockMetrics.mu.Unlock()
		key := output + ":" + status
		count := tc.MockMetrics.Events[key]
		if count == 0 {
			return fmt.Errorf("expected RecordEvent(%q, %q) to be called, got 0 (all events: %v)", output, status, tc.MockMetrics.Events)
		}
		return nil
	})

	ctx.Step(`^the metrics should have recorded a validation error$`, func() error {
		tc.MockMetrics.mu.Lock()
		defer tc.MockMetrics.mu.Unlock()
		total := 0
		for _, v := range tc.MockMetrics.ValidationErrors {
			total += v
		}
		if total == 0 {
			return fmt.Errorf("expected at least one RecordValidationError call, got 0")
		}
		return nil
	})

	ctx.Step(`^the metrics should have recorded a filtered event "([^"]*)"$`, func(eventType string) error {
		// Close to flush to ensure metrics are recorded.
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		tc.MockMetrics.mu.Lock()
		defer tc.MockMetrics.mu.Unlock()
		count := tc.MockMetrics.Filtered[eventType]
		if count == 0 {
			return fmt.Errorf("expected RecordFiltered(%q) to be called, got 0 (all filtered: %v)", eventType, tc.MockMetrics.Filtered)
		}
		return nil
	})
}
