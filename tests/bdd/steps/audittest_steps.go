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
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

// audittestState holds per-scenario state for audittest-helper BDD
// tests. Kept local to this file so it does not pollute
// AuditTestContext with helper-specific fields.
type audittestState struct {
	tb       testing.TB
	auditor  *audit.Auditor
	recorder *audittest.Recorder
}

// bddTB is a minimal testing.TB used to feed audittest.New inside a
// BDD scenario. audittest itself only calls tb.Helper, tb.Cleanup,
// and tb.Fatalf on this object; fatal failures propagate through
// t.Failed() and a captured error message.
//
// Concurrency: every exported method acquires mu, so bddTB is safe
// to share across goroutines that audittest may spawn (e.g.,
// auditor.Cleanup running on the test goroutine while a BDD step
// reads Failed()).
type bddTB struct { //nolint:govet // fieldalignment: embedded testing.TB determines layout; reordering offers no savings
	testing.TB
	mu       sync.Mutex
	cleanups []func()
	fatalMsg string
	failed   bool
}

func (b *bddTB) Helper()           {}
func (b *bddTB) Cleanup(fn func()) { b.mu.Lock(); b.cleanups = append(b.cleanups, fn); b.mu.Unlock() }
func (b *bddTB) Errorf(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed = true
	b.fatalMsg = fmt.Sprintf(format, args...)
}
func (b *bddTB) Fatalf(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failed = true
	b.fatalMsg = fmt.Sprintf(format, args...)
}
func (b *bddTB) Logf(format string, args ...any) {}
func (b *bddTB) Fail()                           { b.mu.Lock(); defer b.mu.Unlock(); b.failed = true }
func (b *bddTB) FailNow()                        { b.mu.Lock(); defer b.mu.Unlock(); b.failed = true }
func (b *bddTB) Failed() bool                    { b.mu.Lock(); defer b.mu.Unlock(); return b.failed }
func (b *bddTB) Name() string                    { return "bdd-audittest" }
func (b *bddTB) runCleanups() {
	b.mu.Lock()
	fns := make([]func(), len(b.cleanups))
	copy(fns, b.cleanups)
	b.cleanups = nil
	b.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

func registerAudittestSteps(ctx *godog.ScenarioContext, _ *AuditTestContext) {
	state := &audittestState{}
	registerAudittestLifecycle(ctx, state)
	registerAudittestGivenSteps(ctx, state)
	registerAudittestWhenSteps(ctx, state)
	registerAudittestThenSteps(ctx, state)
}

func registerAudittestLifecycle(ctx *godog.ScenarioContext, state *audittestState) {
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*state = audittestState{}
		return c, nil
	})
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if state.auditor != nil {
			_ = state.auditor.Close()
		}
		if tb, ok := state.tb.(*bddTB); ok {
			tb.runCleanups()
		}
		return c, nil
	})
}

func registerAudittestGivenSteps(ctx *godog.ScenarioContext, state *audittestState) {
	ctx.Step(`^an audittest auditor in async mode with taxonomy:$`, func(doc *godog.DocString) error {
		return createAudittestAuditor(state, doc.Content, nil, true)
	})
	ctx.Step(`^an audittest auditor with WithExcludeLabels "([^"]*)" and taxonomy:$`, func(labels string, doc *godog.DocString) error {
		return createAudittestAuditor(state, doc.Content, splitAndTrim(labels, ","), false)
	})
}

func registerAudittestWhenSteps(ctx *godog.ScenarioContext, state *audittestState) {
	ctx.Step(`^(\d+) "([^"]*)" events are emitted from a background goroutine$`, func(n int, eventType string) error {
		if state.auditor == nil {
			return fmt.Errorf("auditor not initialised")
		}
		go func() {
			for i := 0; i < n; i++ {
				_ = state.auditor.AuditEvent(audit.NewEvent(eventType, audit.Fields{
					"outcome":  "success",
					"actor_id": fmt.Sprintf("actor-%d", i),
				}))
			}
		}()
		return nil
	})
	ctx.Step(`^no events are emitted$`, func() error { return nil })
	ctx.Step(`^an event "([^"]*)" is emitted with fields:$`, func(eventType string, table *godog.Table) error {
		if state.auditor == nil {
			return fmt.Errorf("auditor not initialised")
		}
		fields := audit.Fields{}
		for _, row := range table.Rows[1:] {
			fields[row.Cells[0].Value] = row.Cells[1].Value
		}
		if err := state.auditor.AuditEvent(audit.NewEvent(eventType, fields)); err != nil {
			return fmt.Errorf("audit event: %w", err)
		}
		return nil
	})
}

func registerAudittestThenSteps(ctx *godog.ScenarioContext, state *audittestState) {
	ctx.Step(`^Recorder\.WaitForN (\d+) within "([^"]*)" should return true$`, func(n int, timeoutStr string) error {
		return assertWaitForN(state, n, timeoutStr, true)
	})
	ctx.Step(`^Recorder\.WaitForN (\d+) within "([^"]*)" should return false$`, func(n int, timeoutStr string) error {
		return assertWaitForN(state, n, timeoutStr, false)
	})
	ctx.Step(`^the recorder should contain at least (\d+) events$`, func(n int) error {
		return assertRecorderCountAtLeast(state, n)
	})
	ctx.Step(`^the recorder should contain (\d+) events$`, func(n int) error {
		return assertRecorderCountExactly(state, n)
	})
	ctx.Step(`^the recorded event should have field "([^"]*)" equal to "([^"]*)"$`, func(field, want string) error {
		return assertRecordedFieldEquals(state, field, want)
	})
	ctx.Step(`^the recorded event should not have field "([^"]*)"$`, func(field string) error {
		return assertRecordedFieldAbsent(state, field)
	})
}

func assertRecorderCountAtLeast(state *audittestState, n int) error {
	if state.recorder == nil {
		return fmt.Errorf("recorder not initialised")
	}
	if got := state.recorder.Count(); got < n {
		return fmt.Errorf("expected at least %d events, got %d", n, got)
	}
	return nil
}

func assertRecorderCountExactly(state *audittestState, n int) error {
	if state.recorder == nil {
		return fmt.Errorf("recorder not initialised")
	}
	if got := state.recorder.Count(); got != n {
		return fmt.Errorf("expected %d events, got %d", n, got)
	}
	return nil
}

func assertRecordedFieldEquals(state *audittestState, field, want string) error {
	if state.recorder == nil {
		return fmt.Errorf("recorder not initialised")
	}
	evt, ok := state.recorder.First()
	if !ok {
		return fmt.Errorf("no events recorded")
	}
	if got := evt.StringField(field); got != want {
		return fmt.Errorf("field %q: expected %q, got %q", field, want, got)
	}
	return nil
}

func assertRecordedFieldAbsent(state *audittestState, field string) error {
	if state.recorder == nil {
		return fmt.Errorf("recorder not initialised")
	}
	evt, ok := state.recorder.First()
	if !ok {
		return fmt.Errorf("no events recorded")
	}
	if v := evt.Field(field); v != nil {
		return fmt.Errorf("field %q should be stripped but has value %v", field, v)
	}
	return nil
}

func createAudittestAuditor(state *audittestState, yamlContent string, excludeLabels []string, async bool) error {
	tb := &bddTB{}
	state.tb = tb

	opts := []audittest.Option{}
	if async {
		opts = append(opts, audittest.WithAsync())
	}
	for _, label := range excludeLabels {
		if label != "" {
			opts = append(opts, audittest.WithExcludeLabels("recorder", label))
		}
	}

	auditor, rec, _ := audittest.New(tb, []byte(yamlContent), opts...)
	if tb.Failed() {
		return fmt.Errorf("audittest.New failed: %s", tb.fatalMsg)
	}
	state.auditor = auditor
	state.recorder = rec
	return nil
}

func assertWaitForN(state *audittestState, n int, timeoutStr string, expected bool) error {
	if state.recorder == nil {
		return fmt.Errorf("recorder not initialised")
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("parse timeout %q: %w", timeoutStr, err)
	}
	got := state.recorder.WaitForN(state.tb, n, timeout)
	if got != expected {
		return fmt.Errorf("WaitForN(%d, %s): expected %t, got %t (recorder count=%d)",
			n, timeoutStr, expected, got, state.recorder.Count())
	}
	return nil
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
