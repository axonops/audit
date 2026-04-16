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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

func registerConfigSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerConfigWhenSteps(ctx, tc)
	registerConfigThenSteps(ctx, tc)
}

func registerConfigWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a logger$`, func() error {
		return tryCreateLogger(tc)
	})

	ctx.Step(`^I create a logger$`, func() error {
		return tryCreateLogger(tc)
	})

	ctx.Step(`^I create a logger with buffer size (\d+)$`, func(bufSize int) error {
		return tryCreateLogger(tc, audit.WithQueueSize(bufSize))
	})

	ctx.Step(`^I try to create a logger with buffer size (\d+)$`, func(bufSize int) error {
		return tryCreateLogger(tc, audit.WithQueueSize(bufSize))
	})

	ctx.Step(`^I create a logger with drain timeout (\d+)$`, func(timeout int) error {
		return tryCreateLogger(tc, audit.WithDrainTimeout(time.Duration(timeout)))
	})

	ctx.Step(`^I try to create a logger with drain timeout (\d+)s$`, func(secs int) error {
		return tryCreateLogger(tc, audit.WithDrainTimeout(time.Duration(secs)*time.Second))
	})

	ctx.Step(`^I create a disabled logger$`, func() error {
		return tryCreateLogger(tc, audit.WithDisabled())
	})

}

func registerConfigThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the logger construction should fail with an error matching:$`, func(doc *godog.DocString) error {
		return assertConstructionExactError(tc, strings.TrimSpace(doc.Content))
	})
	ctx.Step(`^the logger construction should fail wrapping "([^"]*)"$`, func(s string) error {
		return assertConstructionSentinel(tc, s)
	})
	ctx.Step(`^the logger construction should fail with an error$`, func() error {
		return assertConstructionFailed(tc)
	})
	ctx.Step(`^the logger construction should fail with an error containing "([^"]*)"$`, func(s string) error {
		return assertConstructionErrorContaining(tc, s)
	})

	ctx.Step(`^the logger should be created successfully$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected successful creation, got: %w", tc.LastErr)
		}
		if tc.Logger == nil {
			return fmt.Errorf("logger is nil after successful creation")
		}
		return nil
	})

	ctx.Step(`^the logger should handle audit calls without error$`, func() error {
		// Disabled logger returns nil from Audit without delivering.
		if tc.Logger == nil {
			// No-op logger (Enabled=false) returns nil from NewLogger.
			return nil
		}
		err := tc.Logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"outcome":  "success",
			"actor_id": "test",
		}))
		if err != nil {
			return fmt.Errorf("expected no error from disabled logger, got: %w", err)
		}
		return nil
	})
}

// tryCreateLogger creates a logger with the given options and stores it
// in the test context. If creation fails, the error is stored in tc.LastErr
// without failing the step (the scenario may assert on the error).
func tryCreateLogger(tc *AuditTestContext, extraOpts ...audit.Option) error {
	buf := &bytes.Buffer{}
	tc.StdoutBuf = buf

	stdoutOut, err := audit.NewStdoutOutput(audit.StdoutConfig{Writer: buf})
	if err != nil {
		return fmt.Errorf("create stdout output: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(stdoutOut),
	}
	opts = append(opts, extraOpts...)

	logger, err := audit.NewLogger(opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func assertConstructionExactError(tc *AuditTestContext, expected string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
	}
	if tc.LastErr.Error() != expected {
		return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
	}
	return nil
}

func assertConstructionSentinel(tc *AuditTestContext, sentinel string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected error wrapping %q, got nil", sentinel)
	}
	switch sentinel {
	case "ErrDuplicateDestination":
		if !errors.Is(tc.LastErr, audit.ErrDuplicateDestination) {
			return fmt.Errorf("expected ErrDuplicateDestination, got:\n  %q", tc.LastErr.Error())
		}
	case "ErrConfigInvalid":
		if !errors.Is(tc.LastErr, audit.ErrConfigInvalid) {
			return fmt.Errorf("expected ErrConfigInvalid, got:\n  %q", tc.LastErr.Error())
		}
	default:
		return fmt.Errorf("unknown sentinel: %s", sentinel)
	}
	return nil
}

func assertConstructionFailed(tc *AuditTestContext) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected construction error, got nil")
	}
	return nil
}

func assertConstructionErrorContaining(tc *AuditTestContext, substr string) error {
	if tc.LastErr == nil {
		return fmt.Errorf("expected construction error containing %q, got nil", substr)
	}
	if !strings.Contains(tc.LastErr.Error(), substr) {
		return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
	}
	return nil
}
