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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

// middlewareTaxonomyYAML extends the standard taxonomy with an HTTP
// event type for middleware scenarios.
const middlewareTaxonomyYAML = `
version: 1
categories:
  http:
    - api_request
events:
  api_request:
    category: http
    required: [outcome]
    optional: [method, path, status_code, actor_id, source_ip, user_agent, request_id, custom_field]
default_enabled:
  - http
`

func registerMiddlewareSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMiddlewareGivenSteps(ctx, tc)
	registerMiddlewareWhenSteps(ctx, tc)
	registerMiddlewareThenSteps(ctx, tc)
	registerMiddlewareRequestIDSteps(ctx, tc)
	registerMiddlewareExactLenSteps(ctx, tc)
	registerMiddlewareTruncationSteps(ctx, tc)
	registerMiddlewarePathSteps(ctx, tc)
}

func registerMiddlewareGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a middleware test taxonomy$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(middlewareTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse middleware taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})

	ctx.Step(`^an HTTP test server with audit middleware$`, func() error {
		return createTestServer(tc, http.StatusOK, false, false)
	})

	ctx.Step(`^an HTTP test server with audit middleware returning status (\d+)$`, func(status int) error {
		return createTestServer(tc, status, false, false)
	})

	ctx.Step(`^an HTTP test server with audit middleware that sets actor_id$`, func() error {
		return createTestServer(tc, http.StatusOK, true, false)
	})

	ctx.Step(`^an HTTP test server with audit middleware that sets Extra hints$`, func() error {
		return createTestServerWithExtra(tc)
	})

	ctx.Step(`^an HTTP test server with audit middleware that skips GET requests$`, func() error {
		return createTestServer(tc, http.StatusOK, false, true)
	})

	ctx.Step(`^an HTTP test server with panicking handler and audit middleware$`, func() error {
		return createPanicHandlerServer(tc)
	})

	ctx.Step(`^I send a GET request to "([^"]*)" expecting panic$`, func(path string) error {
		// The middleware recovers the panic, so the HTTP response will be
		// written (500 status). httptest.Server handles panics by closing
		// the connection. We catch the error.
		_ = sendTestRequest(tc, "GET", path, nil)
		return nil
	})

	ctx.Step(`^an HTTP test server with audit middleware returning no explicit status$`, func() error {
		return createTestServer(tc, 0, false, false) // 0 = don't call WriteHeader
	})

	ctx.Step(`^an HTTP test server with nil logger middleware$`, func() error {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mw := audit.Middleware(nil, defaultEventBuilder)
		tc.TestServer = httptest.NewServer(mw(handler))
		tc.AddCleanup(func() { tc.TestServer.Close() })
		return nil
	})
}

func registerMiddlewareWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I send a (GET|POST|PUT|DELETE) request to "([^"]*)" with header "([^"]*)" = "([^"]*)"$`, func(method, path, hdr, val string) error {
		return sendTestRequest(tc, method, path, map[string]string{hdr: val})
	})
	ctx.Step(`^I send (\d+) concurrent (GET|POST) requests to "([^"]*)"$`, func(count int, method, path string) error {
		var wg sync.WaitGroup
		for range count {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Don't use sendTestRequest — it writes tc.LastHTTPResp
				// which races across goroutines. Make the request directly.
				req, reqErr := http.NewRequestWithContext(context.Background(), method, tc.TestServer.URL+path, http.NoBody)
				if reqErr != nil {
					return
				}
				resp, doErr := testHTTPClient.Do(req)
				if doErr != nil {
					return
				}
				_ = resp.Body.Close()
			}()
		}
		wg.Wait()
		return nil
	})

	ctx.Step(`^I send a (GET|POST|PUT|DELETE) request to "([^"]*)"$`, func(method, path string) error {
		return sendTestRequest(tc, method, path, nil)
	})
}

func registerMiddlewareThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file event should have field "([^"]*)" with value "([^"]*)"$`, func(f, v string) error { return assertFileEventFieldValue(tc, f, v) })
	ctx.Step(`^the file event should have field "([^"]*)" present$`, func(f string) error { return assertFileEventFieldExists(tc, f) })
	ctx.Step(`^the response status should be (\d+)$`, func(s int) error { return assertHTTPStatus(tc, s) })
}

func assertFileEventFieldValue(tc *AuditTestContext, field, value string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	for _, e := range events {
		if formatFieldValue(e[field]) == value {
			return nil
		}
	}
	return fmt.Errorf("no file event with %s=%q (%d events)", field, value, len(events))
}

func assertFileEventFieldExists(tc *AuditTestContext, field string) error {
	events, err := readFileEvents(tc, "default")
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no events in file")
	}
	if _, ok := events[0][field]; !ok {
		return fmt.Errorf("field %q not present in event", field)
	}
	return nil
}

func assertHTTPStatus(tc *AuditTestContext, status int) error {
	if tc.LastHTTPResp == nil {
		return fmt.Errorf("no HTTP response recorded")
	}
	if tc.LastHTTPResp.StatusCode != status {
		return fmt.Errorf("expected status %d, got %d", status, tc.LastHTTPResp.StatusCode)
	}
	return nil
}

func registerMiddlewareRequestIDSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I send a GET request to "([^"]*)" with a (\d+)-char X-Request-Id$`, func(path string, length int) error {
		longID := strings.Repeat("x", length)
		return sendTestRequest(tc, "GET", path, map[string]string{"X-Request-Id": longID})
	})
	ctx.Step(`^the file event request_id should be shorter than (\d+) characters$`, func(maxLen int) error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return fmt.Errorf("no events in file")
		}
		rid, ok := events[0]["request_id"].(string)
		if !ok {
			return fmt.Errorf("request_id is not a string: %v", events[0]["request_id"])
		}
		if len(rid) >= maxLen {
			return fmt.Errorf("request_id length %d not shorter than %d (value: %q)", len(rid), maxLen, rid)
		}
		return nil
	})
}

func registerMiddlewareExactLenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file event user_agent field should be exactly (\d+) characters$`, func(exactLen int) error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return fmt.Errorf("no events in file")
		}
		ua, ok := events[0]["user_agent"].(string)
		if !ok {
			return fmt.Errorf("user_agent is not a string: %v", events[0]["user_agent"])
		}
		if len(ua) != exactLen {
			return fmt.Errorf("user_agent length %d, expected exactly %d", len(ua), exactLen)
		}
		return nil
	})
}

func registerMiddlewareTruncationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I send a GET request to "([^"]*)" with a (\d+)-char User-Agent$`, func(path string, length int) error {
		ua := strings.Repeat("A", length)
		return sendTestRequest(tc, "GET", path, map[string]string{"User-Agent": ua})
	})
	ctx.Step(`^the file event user_agent field should be at most (\d+) characters$`, func(maxLen int) error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return fmt.Errorf("no events in file")
		}
		ua, ok := events[0]["user_agent"].(string)
		if !ok {
			return fmt.Errorf("user_agent field is not a string: %v", events[0]["user_agent"])
		}
		if len(ua) > maxLen {
			return fmt.Errorf("user_agent length %d exceeds max %d", len(ua), maxLen)
		}
		return nil
	})
}

func registerMiddlewarePathSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I send a GET request to a path with (\d+) characters$`, func(length int) error {
		path := "/" + strings.Repeat("a", length-1)
		return sendTestRequest(tc, "GET", path, nil)
	})
	ctx.Step(`^the file event path field should be at most (\d+) characters$`, func(maxLen int) error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return fmt.Errorf("no events in file")
		}
		path, ok := events[0]["path"].(string)
		if !ok {
			return fmt.Errorf("path field is not a string: %v", events[0]["path"])
		}
		if len(path) > maxLen {
			return fmt.Errorf("path length %d exceeds max %d", len(path), maxLen)
		}
		return nil
	})
}

func sendTestRequest(tc *AuditTestContext, method, path string, headers map[string]string) error {
	if tc.TestServer == nil {
		return fmt.Errorf("test server not created")
	}
	req, err := http.NewRequestWithContext(context.Background(), method, tc.TestServer.URL+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	_ = resp.Body.Close()
	tc.LastHTTPResp = resp
	return nil
}

func createPanicHandlerServer(tc *AuditTestContext) error {
	builder := func(_ *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		return "api_request", audit.Fields{
			"outcome":     "failure",
			"method":      transport.Method,
			"path":        transport.Path,
			"status_code": transport.StatusCode,
		}, false
	}

	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("intentional handler panic")
	})

	mw := audit.Middleware(tc.Logger, builder)
	tc.TestServer = httptest.NewServer(mw(handler))
	tc.AddCleanup(func() { tc.TestServer.Close() })
	return nil
}

func createTestServerWithExtra(tc *AuditTestContext) error {
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		fields := audit.Fields{
			"outcome":     "success",
			"method":      transport.Method,
			"path":        transport.Path,
			"status_code": transport.StatusCode,
			"source_ip":   transport.ClientIP,
			"user_agent":  transport.UserAgent,
			"request_id":  transport.RequestID,
		}
		if hints != nil && hints.Extra != nil {
			for k, v := range hints.Extra {
				fields[k] = v
			}
		}
		return "api_request", fields, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hints := audit.HintsFromContext(r.Context()); hints != nil {
			hints.Extra = map[string]any{"custom_field": "custom_value"}
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := audit.Middleware(tc.Logger, builder)
	tc.TestServer = httptest.NewServer(mw(handler))
	tc.AddCleanup(func() { tc.TestServer.Close() })
	return nil
}

// --- Middleware helpers ---

var defaultEventBuilder = func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
	fields := audit.Fields{
		"outcome":     "success",
		"method":      transport.Method,
		"path":        transport.Path,
		"status_code": transport.StatusCode,
		"source_ip":   transport.ClientIP,
		"user_agent":  transport.UserAgent,
		"request_id":  transport.RequestID,
	}
	if hints != nil && hints.ActorID != "" {
		fields["actor_id"] = hints.ActorID
	}
	return "api_request", fields, false
}

func createTestServer(tc *AuditTestContext, status int, setActorID, skipGET bool) error {
	builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
		if skipGET && transport.Method == "GET" {
			return "", nil, true
		}
		fields := audit.Fields{
			"outcome":     "success",
			"method":      transport.Method,
			"path":        transport.Path,
			"status_code": transport.StatusCode,
			"source_ip":   transport.ClientIP,
			"user_agent":  transport.UserAgent,
			"request_id":  transport.RequestID,
		}
		if setActorID {
			fields["actor_id"] = "handler-actor"
		}
		return "api_request", fields, false
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if setActorID {
			if hints := audit.HintsFromContext(r.Context()); hints != nil {
				hints.ActorID = "handler-actor"
			}
		}
		if status > 0 {
			w.WriteHeader(status)
		}
		// status=0 means don't call WriteHeader (default 200)
	})

	mw := audit.Middleware(tc.Logger, builder)
	tc.TestServer = httptest.NewServer(mw(handler))
	tc.AddCleanup(func() { tc.TestServer.Close() })
	return nil
}
