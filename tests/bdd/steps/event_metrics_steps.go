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
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file"
)

// registerEventMetricsSteps registers step definitions for event count
// metrics and per-output buffer drop scenarios.
func registerEventMetricsSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerEventMetricsGivenSteps(ctx, tc)
	registerEventMetricsThenSteps(ctx, tc)
}

func registerEventMetricsGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit // BDD step registration
	ctx.Step(`^a logger with file output and pipeline metrics$`, func() error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "metrics.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithNamedOutput(fileOut),
		}

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

	ctx.Step(`^a file output with buffer_size (\d+) and mock output metrics$`, func(bufSize int) error {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "drops.log")
		tc.FilePaths["default"] = path

		fileOut, err := file.New(file.Config{Path: path, BufferSize: bufSize}, nil)
		if err != nil {
			return fmt.Errorf("create file: %w", err)
		}

		om := &MockOutputMetrics{}
		fileOut.SetOutputMetrics(om)
		tc.OutputMetricsMock = om

		tc.Options = append(tc.Options, audit.WithNamedOutput(fileOut))
		return nil
	})

	ctx.Step(`^a logger with that file output and queue_size (\d+)$`, func(queueSize int) error {
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithQueueSize(queueSize),
		}
		opts = append(opts, tc.Options...)

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

	ctx.Step(`^a logger with that file output and pipeline metrics and queue_size (\d+)$`, func(queueSize int) error {
		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithMetrics(tc.MockMetrics),
			audit.WithQueueSize(queueSize),
		}
		opts = append(opts, tc.Options...)

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

	ctx.Step(`^a logger with that file output and a stdout output$`, func() error {
		stdoutBuf := &bytes.Buffer{}
		tc.StdoutBuf = stdoutBuf

		stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: stdoutBuf})
		if err != nil {
			return fmt.Errorf("create stdout: %w", err)
		}

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(stdoutOut),
		}
		opts = append(opts, tc.Options...)

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})
}

func registerEventMetricsThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) { //nolint:gocognit,gocyclo,cyclop // BDD step registration
	ctx.Step(`^RecordSubmitted should have been called (\d+) times?$`, func(n int) error {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		got := tc.MockMetrics.SubmittedCount()
		if got != n {
			return fmt.Errorf("expected RecordSubmitted called %d times, got %d", n, got)
		}
		return nil
	})

	ctx.Step(`^RecordQueueDepth should have been called at least (\d+) times?$`, func(n int) error {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		got := tc.MockMetrics.QueueDepthCallCount()
		if got < n {
			return fmt.Errorf("expected RecordQueueDepth called >= %d times, got %d", n, got)
		}
		return nil
	})

	ctx.Step(`^the pipeline metrics should not have recorded a success event for file output$`, func() error {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		if tc.MockMetrics.HasSuccessEventFor("file:") {
			return fmt.Errorf("expected no core success metrics for file, but found success events")
		}
		return nil
	})

	ctx.Step(`^the output metrics should have recorded at least (\d+) drops?$`, func(n int) error {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		if tc.OutputMetricsMock == nil {
			return fmt.Errorf("no output metrics configured")
		}
		if tc.OutputMetricsMock.DropCount() < n {
			return fmt.Errorf("expected >= %d output drops, got %d", n, tc.OutputMetricsMock.DropCount())
		}
		return nil
	})

	ctx.Step(`^the pipeline metrics should not have recorded an output error for file$`, func() error {
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		if tc.MockMetrics.HasOutputErrorFor("file:") {
			return fmt.Errorf("expected no output errors for file, but found output errors")
		}
		return nil
	})
}
