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

//go:build integration

// Package bdd_test runs Godog BDD feature files against the go-audit
// library. Feature files in features/ define the executable specification;
// step definitions in steps/ translate Gherkin to API calls.
//
// Run with: make test-bdd (requires Docker for syslog/webhook scenarios)
// Run core-only: go test -tags=integration ./tests/bdd/... --godog.tags=@core
package bdd_test

import (
	"os"
	"testing"

	"github.com/cucumber/godog"
	"github.com/cucumber/godog/colors"
	"go.uber.org/goleak"

	"github.com/axonops/go-audit/tests/bdd/steps"
)

func TestFeatures(t *testing.T) {
	defer goleak.VerifyNone(t,
		// HTTP transport persistent connection goroutines linger
		// briefly after httptest.Server.Close() and webhook HTTP
		// clients. These are harmless and cleaned up by the
		// runtime's connection pool.
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*conn).serve"),
		goleak.IgnoreAnyFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreAnyFunction("crypto/tls.(*Conn).Read"),
	)
	opts := godog.Options{
		Output:      colors.Colored(os.Stdout),
		Format:      "pretty",
		Paths:       []string{"features"},
		Randomize:   0,
		Concurrency: 1, // sequential: shared Docker infrastructure
		TestingT:    t,
	}

	suite := godog.TestSuite{
		Name:                "go-audit",
		ScenarioInitializer: steps.InitializeScenario,
		Options:             &opts,
	}

	if suite.Run() != 0 {
		t.Fatal("BDD tests failed")
	}
}
