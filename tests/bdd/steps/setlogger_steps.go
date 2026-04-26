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
	"log/slog"

	"github.com/cucumber/godog"
)

// setLoggerCtx holds SetLogger-test-specific state alongside the
// shared AuditTestContext.
type setLoggerCtx struct {
	captured *bytes.Buffer
	logger   *slog.Logger
}

// registerSetLoggerSteps wires the #601 BDD scenarios that assert
// the runtime diagnostic-logger swap contract.
func registerSetLoggerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	c := &setLoggerCtx{}

	ctx.Step(`^a captured replacement diagnostic logger$`, func() error {
		c.captured = &bytes.Buffer{}
		c.logger = slog.New(slog.NewTextHandler(c.captured, &slog.HandlerOptions{Level: slog.LevelDebug}))
		return nil
	})

	ctx.Step(`^I call SetLogger to swap the auditor's diagnostic logger$`, func() error {
		if tc.Auditor == nil {
			return fmt.Errorf("no auditor configured")
		}
		if c.logger == nil {
			return fmt.Errorf("replacement logger not captured — Given step missing")
		}
		tc.Auditor.SetLogger(c.logger)
		return nil
	})

	ctx.Step(`^I trigger a diagnostic message via EnableCategory "([^"]*)"$`, func(category string) error {
		if tc.Auditor == nil {
			return fmt.Errorf("no auditor configured")
		}
		_ = tc.Auditor.EnableCategory(category)
		// EnableCategory may return ErrUnknownCategory if the category
		// isn't in the taxonomy — either path emits a diagnostic line,
		// which is what this scenario is verifying.
		return nil
	})

	ctx.Step(`^the captured logger should record the diagnostic message$`, func() error {
		if c.captured == nil {
			return fmt.Errorf("no replacement logger captured")
		}
		if c.captured.Len() == 0 {
			return fmt.Errorf("replacement logger received no messages — SetLogger swap did not take effect")
		}
		return nil
	})
}
