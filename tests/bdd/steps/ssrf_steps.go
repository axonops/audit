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
	"net"
	"strconv"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// ssrfState holds the last CheckSSRFIP result for post-When
// assertions in ssrf_protection.feature. Kept out of the global
// TestContext because this feature is purely a pure-function
// classification test — no taxonomy or auditor involved.
type ssrfState struct {
	lastErr error
}

//nolint:gocognit // multiple ctx.Step registrations of similar shape; splitting reduces clarity
func registerSSRFSteps(ctx *godog.ScenarioContext, _ *AuditTestContext) {
	state := &ssrfState{}

	ctx.Step(`^I want to classify SSRF rejections by reason$`, func() error {
		state.lastErr = nil
		return nil
	})

	ctx.Step(
		`^I check SSRF classification for IP "([^"]+)" with AllowPrivateRanges "(true|false)"$`,
		func(ipStr, allowStr string) error {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("BDD test fixture: unparseable IP %q", ipStr)
			}
			allowPrivate, err := strconv.ParseBool(allowStr)
			if err != nil {
				return fmt.Errorf("BDD test fixture: unparseable bool %q: %w", allowStr, err)
			}
			state.lastErr = audit.CheckSSRFIP(ip, allowPrivate)
			return nil
		},
	)

	ctx.Step(`^the SSRF classification should wrap ErrSSRFBlocked$`, func() error {
		if state.lastErr == nil {
			return fmt.Errorf("expected classification to return an error, got nil")
		}
		if !errors.Is(state.lastErr, audit.ErrSSRFBlocked) {
			return fmt.Errorf("expected error to wrap audit.ErrSSRFBlocked, got: %w", state.lastErr)
		}
		return nil
	})

	ctx.Step(`^the SSRF classification reason should be "([^"]+)"$`, func(want string) error {
		if state.lastErr == nil {
			return fmt.Errorf("expected classification error, got nil")
		}
		var ssrfErr *audit.SSRFBlockedError
		if !errors.As(state.lastErr, &ssrfErr) {
			return fmt.Errorf("expected *audit.SSRFBlockedError, got %T: %w", state.lastErr, state.lastErr)
		}
		if string(ssrfErr.Reason) != want {
			return fmt.Errorf("reason mismatch: want %q, got %q", want, ssrfErr.Reason)
		}
		return nil
	})

	ctx.Step(`^the SSRF classification should succeed$`, func() error {
		if state.lastErr != nil {
			return fmt.Errorf("expected classification to succeed, got: %w", state.lastErr)
		}
		return nil
	})
}
