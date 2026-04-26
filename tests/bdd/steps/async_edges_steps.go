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
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

// registerAsyncEdgesSteps registers BDD step definitions for async
// delivery edge-case scenarios (#564): sync-mode close, sync-mode
// panic isolation, buffer_size:0 coercion, and the delivery
// accounting invariant.
//
//nolint:gocognit,gocyclo,cyclop // BDD step registration: 4 closures inline; splitting hurts readability
func registerAsyncEdgesSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^an auditor with synchronous delivery, file output, and a panicking output$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(&file.Config{Path: path})
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}
		tc.AddCleanup(func() { _ = fileOut.Close() })

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithNamedOutput(fileOut),
			audit.WithNamedOutput(&panicOutput{}),
			audit.WithSynchronousDelivery(),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the effective output buffer capacity should be (\d+)$`, func(want int) error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		if tc.OutputMetricsMock == nil {
			return errors.New("no MockOutputMetrics configured — precede with 'a file output with buffer_size N and mock output metrics'")
		}
		tc.OutputMetricsMock.mu.Lock()
		defer tc.OutputMetricsMock.mu.Unlock()
		if len(tc.OutputMetricsMock.queueDs) == 0 {
			return errors.New("no RecordQueueDepth call recorded; the output never observed its queue")
		}
		got := tc.OutputMetricsMock.queueDs[len(tc.OutputMetricsMock.queueDs)-1].Capacity
		if got != want {
			return fmt.Errorf("expected effective buffer capacity %d, got %d", want, got)
		}
		return nil
	})

	ctx.Step(`^an auditor with a recording output, pipeline metrics, and synchronous delivery$`, func() error {
		if tc.MockMetrics == nil {
			tc.MockMetrics = NewMockMetrics()
		}

		// Use a non-DeliveryReporter output so RecordDelivery flows
		// through tc.MockMetrics. file/syslog/webhook/loki implement
		// DeliveryReporter and bypass core RecordDelivery — that path
		// has separate coverage; this scenario isolates the core
		// metrics invariant.
		rec := &recordingMockOutput{name: "recording"}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithAppName("test-app"),
			audit.WithHost("test-host"),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithOutputs(rec),
			audit.WithSynchronousDelivery(),
		}
		auditor, err := audit.New(opts...)
		if err != nil {
			return fmt.Errorf("create auditor: %w", err)
		}
		tc.Auditor = auditor
		tc.AddCleanup(func() { _ = auditor.Close() })
		return nil
	})

	ctx.Step(`^the delivery accounting invariant should hold$`, func() error {
		if tc.Auditor != nil {
			_ = tc.Auditor.Close()
		}
		if tc.MockMetrics == nil {
			return errors.New("no MockMetrics configured")
		}
		m := tc.MockMetrics
		m.mu.Lock()
		defer m.mu.Unlock()

		successes := 0
		for k, v := range m.Events {
			if strings.HasSuffix(k, ":success") {
				successes += v
			}
		}
		outputErrs := 0
		for _, v := range m.OutputErrors {
			outputErrs += v
		}
		filtered := 0
		for _, v := range m.Filtered {
			filtered += v
		}
		validation := 0
		for _, v := range m.ValidationErrors {
			validation += v
		}
		serial := 0
		for _, v := range m.SerializationErrs {
			serial += v
		}
		total := successes + outputErrs + filtered + validation + serial + m.BufferDrops
		if total != m.Submitted {
			return fmt.Errorf(
				"invariant broken: submitted=%d != successes=%d + output_errors=%d + filtered=%d + validation_errors=%d + serialization_errors=%d + buffer_drops=%d (sum=%d)",
				m.Submitted, successes, outputErrs, filtered, validation, serial, m.BufferDrops, total)
		}
		return nil
	})
}
