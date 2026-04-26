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
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// sanitizerCtx holds Sanitizer-test-specific state alongside the
// shared AuditTestContext. The capture buffer for the diagnostic
// logger is here rather than on AuditTestContext to keep that
// struct focused on cross-feature shared state.
type sanitizerCtx struct {
	diagBuf    *bytes.Buffer
	callCount  *atomic.Int64
	emitErrors *atomic.Int64
}

// redactingSanitizer is a Sanitizer that redacts a configured field
// key by returning "[redacted]"; everything else passes through.
type redactingSanitizer struct {
	audit.NoopSanitizer
	key string
}

func (r redactingSanitizer) SanitizeField(key string, value any) any {
	if key == r.key {
		return "[redacted]"
	}
	return value
}

// panicOnKeySanitizer panics when SanitizeField is called for a
// configured key. The panic value embeds the configured secret to
// prove the diagnostic-log isolation contract.
type panicOnKeySanitizer struct {
	audit.NoopSanitizer
	key    string
	secret string
}

func (p panicOnKeySanitizer) SanitizeField(key string, value any) any {
	if key == p.key {
		panic("sanitiser exploded on " + p.secret)
	}
	return value
}

// countingSanitizer is a Sanitizer used for concurrency tests; counts
// SanitizeField invocations atomically.
type countingSanitizer struct {
	audit.NoopSanitizer
	calls *atomic.Int64
}

func (c countingSanitizer) SanitizeField(_ string, value any) any {
	c.calls.Add(1)
	return value
}

// registerSanitizerSteps wires the #598 BDD scenarios that assert
// the [audit.Sanitizer] field-redaction contract on the Audit /
// AuditEvent path. (Middleware-panic scenarios live in
// middleware_sanitizer_test.go — they need an http.Server harness
// not modelled here.)
//
//nolint:gocognit,gocyclo,cyclop // step-registration block: flat list of ctx.Step closures, not branching logic
func registerSanitizerSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	sc := &sanitizerCtx{}

	ctx.Step(`^an auditor with a Sanitizer that redacts the "([^"]*)" field$`, func(key string) error {
		s := redactingSanitizer{key: key}
		return createStdoutAuditor(tc, audit.WithSanitizer(s))
	})

	ctx.Step(`^an auditor with a Sanitizer that panics on "([^"]*)"$`, func(key string) error {
		s := panicOnKeySanitizer{key: key, secret: "default-secret"}
		return createStdoutAuditor(tc, audit.WithSanitizer(s))
	})

	ctx.Step(`^an auditor with a Sanitizer that panics with the sentinel string captured$`, func() error {
		sc.diagBuf = &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(sc.diagBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
		// The sanitiser's panic message embeds the actual value, so
		// the assertion proves the helper logs `%T` only.
		s := panicOnKeySanitizer{key: "actor_id", secret: "SECRET-PII-12345"}
		return createStdoutAuditor(tc, audit.WithSanitizer(s), audit.WithDiagnosticLogger(logger))
	})

	ctx.Step(`^an auditor with a counting Sanitizer$`, func() error {
		var calls atomic.Int64
		sc.callCount = &calls
		s := countingSanitizer{calls: &calls}
		return createStdoutAuditor(tc, audit.WithSanitizer(s))
	})

	ctx.Step(`^I audit a "([^"]*)" event with actor_id "([^"]*)"$`, func(eventType, actorID string) error {
		err := tc.Auditor.AuditEvent(audit.NewEvent(eventType, audit.Fields{
			"outcome":  "success",
			"actor_id": actorID,
		}))
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		// Stdout output is async by default; close to drain.
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		return nil
	})

	ctx.Step(`^the captured event field "([^"]*)" should equal "([^"]*)"$`, func(key, want string) error {
		ev, err := lastStdoutEvent(tc)
		if err != nil {
			return err
		}
		got, ok := ev[key]
		if !ok {
			return fmt.Errorf("captured event has no field %q (event=%v)", key, ev)
		}
		if got != want {
			return fmt.Errorf("field %q: want %q, got %v", key, want, got)
		}
		return nil
	})

	ctx.Step(`^the captured event should not have field "([^"]*)"$`, func(key string) error {
		ev, err := lastStdoutEvent(tc)
		if err != nil {
			return err
		}
		if _, ok := ev[key]; ok {
			return fmt.Errorf("captured event unexpectedly has field %q", key)
		}
		return nil
	})

	ctx.Step(`^the captured event "([^"]*)" framework field should list "([^"]*)"$`, func(field, expected string) error {
		ev, err := lastStdoutEvent(tc)
		if err != nil {
			return err
		}
		raw, ok := ev[field]
		if !ok {
			return fmt.Errorf("captured event has no field %q", field)
		}
		// Stdout output JSON-decodes []string as []any.
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("framework field %q is %T, want []any", field, raw)
		}
		for _, v := range list {
			if v == expected {
				return nil
			}
		}
		return fmt.Errorf("framework field %q does not contain %q (got %v)", field, expected, list)
	})

	ctx.Step(`^the diagnostic log should record the SanitizeField panic$`, func() error {
		if sc.diagBuf == nil {
			return fmt.Errorf("no diagnostic log captured")
		}
		logs := sc.diagBuf.String()
		if !strings.Contains(logs, "Sanitizer.SanitizeField panicked") {
			return fmt.Errorf("diagnostic log missing panic record; got:\n%s", logs)
		}
		return nil
	})

	ctx.Step(`^the diagnostic log should not contain "([^"]*)"$`, func(forbidden string) error {
		if sc.diagBuf == nil {
			return fmt.Errorf("no diagnostic log captured")
		}
		logs := sc.diagBuf.String()
		if strings.Contains(logs, forbidden) {
			return fmt.Errorf("diagnostic log unexpectedly contains %q; got:\n%s", forbidden, logs)
		}
		return nil
	})

	ctx.Step(`^(\d+) goroutines each emit (\d+) "([^"]*)" events concurrently$`, func(goroutines, perGoroutine int, eventType string) error {
		var emitErrors atomic.Int64
		sc.emitErrors = &emitErrors
		var wg sync.WaitGroup
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < perGoroutine; j++ {
					if err := tc.Auditor.AuditEvent(audit.NewEvent(eventType, audit.Fields{
						"outcome":  "success",
						"actor_id": "alice",
					})); err != nil {
						emitErrors.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		// Close to flush stdout.
		if err := tc.Auditor.Close(); err != nil {
			return fmt.Errorf("close to flush: %w", err)
		}
		return nil
	})

	ctx.Step(`^(\d+) events should be captured$`, func(want int) error {
		evs, err := allStdoutEvents(tc)
		if err != nil {
			return err
		}
		if len(evs) != want {
			return fmt.Errorf("captured %d events, want %d", len(evs), want)
		}
		return nil
	})

	ctx.Step(`^the Sanitizer should have been invoked at least (\d+) times$`, func(threshold int) error {
		if sc.callCount == nil {
			return fmt.Errorf("no counting sanitizer registered")
		}
		got := sc.callCount.Load()
		if got < int64(threshold) {
			return fmt.Errorf("sanitizer invoked %d times, want at least %d", got, threshold)
		}
		return nil
	})
}

// lastStdoutEvent returns the most recent JSON event captured by the
// stdout output buffer.
func lastStdoutEvent(tc *AuditTestContext) (map[string]any, error) {
	evs, err := allStdoutEvents(tc)
	if err != nil {
		return nil, err
	}
	if len(evs) == 0 {
		return nil, fmt.Errorf("no events captured in stdout buffer")
	}
	return evs[len(evs)-1], nil
}

// allStdoutEvents parses every JSON event captured in the stdout buffer.
func allStdoutEvents(tc *AuditTestContext) ([]map[string]any, error) {
	if tc.StdoutBuf == nil {
		return nil, fmt.Errorf("no stdout buffer (auditor not configured with stdout output?)")
	}
	events, err := parseJSONLines(tc.StdoutBuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse stdout: %w", err)
	}
	return events, nil
}
