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
	stdctx "context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// ctxAPICtx holds Sanitizer-test-specific state alongside the
// shared AuditTestContext.
type ctxAPICtx struct {
	diagBuf *bytes.Buffer
	lastErr error
}

// registerContextAPISteps wires the #600 BDD scenarios that assert
// the [audit.Auditor.AuditEventContext] / [audit.EventHandle.AuditContext]
// cancellation contract.
//
//nolint:gocognit,gocyclo,cyclop // step-registration block: flat list of ctx.Step closures, not branching logic
func registerContextAPISteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	c := &ctxAPICtx{}

	ctx.Step(`^an auditor with a captured diagnostic logger$`, func() error {
		c.diagBuf = &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(c.diagBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		return createStdoutAuditor(tc, audit.WithDiagnosticLogger(logger))
	})

	ctx.Step(`^a registered EventHandle for "([^"]*)"$`, func(eventType string) error {
		h, err := tc.Auditor.Handle(eventType)
		if err != nil {
			return fmt.Errorf("obtain handle: %w", err)
		}
		tc.EventHandle = h
		return nil
	})

	ctx.Step(`^I call AuditEventContext with a background context for "([^"]*)"$`, func(eventType string) error {
		evt := audit.NewEvent(eventType, audit.Fields{
			"outcome":  "success",
			"actor_id": "alice@example.com",
		})
		c.lastErr = tc.Auditor.AuditEventContext(stdctx.Background(), evt)
		// Async stdout — close to flush.
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		tc.Auditor = nil
		return nil
	})

	ctx.Step(`^I call AuditEventContext with a pre-cancelled context for "([^"]*)"$`, func(eventType string) error {
		ctxCancel, cancel := stdctx.WithCancel(stdctx.Background())
		cancel()
		evt := audit.NewEvent(eventType, audit.Fields{
			"outcome":  "success",
			"actor_id": "alice@example.com",
		})
		c.lastErr = tc.Auditor.AuditEventContext(ctxCancel, evt)
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		tc.Auditor = nil
		return nil
	})

	ctx.Step(`^I call AuditEventContext with a context whose deadline has expired for "([^"]*)"$`, func(eventType string) error {
		ctxDeadline, cancel := stdctx.WithDeadline(stdctx.Background(), time.Now().Add(-time.Hour))
		defer cancel()
		evt := audit.NewEvent(eventType, audit.Fields{
			"outcome":  "success",
			"actor_id": "alice@example.com",
		})
		c.lastErr = tc.Auditor.AuditEventContext(ctxDeadline, evt)
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		tc.Auditor = nil
		return nil
	})

	ctx.Step(`^I call EventHandle.AuditContext with a pre-cancelled context$`, func() error {
		ctxCancel, cancel := stdctx.WithCancel(stdctx.Background())
		cancel()
		c.lastErr = tc.EventHandle.AuditContext(ctxCancel, audit.Fields{
			"outcome":  "success",
			"actor_id": "alice@example.com",
		})
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		tc.Auditor = nil
		return nil
	})

	ctx.Step(`^the call should return context.Canceled$`, func() error {
		if !errors.Is(c.lastErr, stdctx.Canceled) {
			return fmt.Errorf("expected context.Canceled, got %w", c.lastErr)
		}
		return nil
	})

	ctx.Step(`^the call should return context.DeadlineExceeded$`, func() error {
		if !errors.Is(c.lastErr, stdctx.DeadlineExceeded) {
			return fmt.Errorf("expected context.DeadlineExceeded, got %w", c.lastErr)
		}
		return nil
	})

	ctx.Step(`^no event should be captured$`, func() error {
		if tc.StdoutBuf == nil {
			return nil
		}
		evs, err := parseJSONLines(tc.StdoutBuf.Bytes())
		if err != nil {
			return fmt.Errorf("parse stdout: %w", err)
		}
		if len(evs) != 0 {
			return fmt.Errorf("expected 0 events, got %d: %v", len(evs), evs)
		}
		return nil
	})

	ctx.Step(`^the diagnostic log should record "([^"]*)"$`, func(snippet string) error {
		if c.diagBuf == nil {
			return fmt.Errorf("no diagnostic log captured")
		}
		logs := c.diagBuf.String()
		if !strings.Contains(logs, snippet) {
			return fmt.Errorf("diagnostic log missing %q; got:\n%s", snippet, logs)
		}
		return nil
	})

	ctx.Step(`^the diagnostic log should record the event_type "([^"]*)"$`, func(eventType string) error {
		if c.diagBuf == nil {
			return fmt.Errorf("no diagnostic log captured")
		}
		logs := c.diagBuf.String()
		// slog text-handler emits unquoted attrs for simple identifiers:
		// `event_type=user_create`.
		if !strings.Contains(logs, "event_type="+eventType) {
			return fmt.Errorf("diagnostic log missing event_type=%s; got:\n%s", eventType, logs)
		}
		return nil
	})
}
