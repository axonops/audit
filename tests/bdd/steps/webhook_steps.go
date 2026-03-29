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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/webhook"
)

func registerWebhookSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerWebhookGivenSteps(ctx, tc)
	registerWebhookWhenSteps(ctx, tc)
	registerWebhookThenSteps(ctx, tc)
}

func registerWebhookGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with webhook output configured for batch size (\d+)$`, func(batchSize int) error {
		return createWebhookLogger(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: 100 * time.Millisecond,
		})
	})

	ctx.Step(`^a logger with webhook output configured for batch size (\d+) and flush interval (\d+)ms$`, func(batchSize, flushMS int) error {
		return createWebhookLogger(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: time.Duration(flushMS) * time.Millisecond,
		})
	})

	ctx.Step(`^a logger with webhook output configured for batch size (\d+) and flush interval (\d+)s$`, func(batchSize, flushS int) error {
		return createWebhookLogger(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: time.Duration(flushS) * time.Second,
		})
	})

	ctx.Step(`^a logger with webhook output configured for batch size (\d+) and max retries (\d+)$`, func(batchSize, maxRetries int) error {
		return createWebhookLogger(tc, &webhook.Config{
			BatchSize:     batchSize,
			FlushInterval: 100 * time.Millisecond,
			MaxRetries:    maxRetries,
		})
	})

	ctx.Step(`^a logger with webhook output with custom header "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return createWebhookLogger(tc, &webhook.Config{
			BatchSize:     1,
			FlushInterval: 100 * time.Millisecond,
			Headers:       map[string]string{name: value},
		})
	})

	ctx.Step(`^a logger with webhook output to "([^"]*)" with AllowInsecureHTTP$`, func(url string) error {
		return createWebhookLoggerWithURL(tc, url, &webhook.Config{
			BatchSize:     1,
			FlushInterval: 100 * time.Millisecond,
		})
	})

	ctx.Step(`^the webhook receiver is configured to return status (\d+)$`, func(status int) error {
		return configureWebhook(tc.WebhookURL, status, 0)
	})

	ctx.Step(`^the webhook receiver is reconfigured to return status (\d+)$`, func(status int) error {
		return configureWebhook(tc.WebhookURL, status, 0)
	})
}

func registerWebhookWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit a uniquely marked webhook "([^"]*)" event$`, func(eventType string) error {
		return auditMarkedWebhookEvent(tc, eventType, "default")
	})

	ctx.Step(`^I audit a uniquely marked webhook "([^"]*)" event "([^"]*)"$`, func(eventType, name string) error {
		return auditMarkedWebhookEvent(tc, eventType, name)
	})

	ctx.Step(`^I audit (\d+) uniquely marked webhook events$`, func(count int) error {
		for i := range count {
			name := fmt.Sprintf("webhook_%d", i)
			if err := auditMarkedWebhookEvent(tc, "user_create", name); err != nil {
				return fmt.Errorf("webhook event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I try to create a webhook output to "([^"]*)" without AllowInsecureHTTP$`, func(url string) error {
		_, err := webhook.New(&webhook.Config{
			URL:                url,
			AllowInsecureHTTP:  false,
			AllowPrivateRanges: true,
			BatchSize:          1,
		}, nil, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output to "([^"]*)"$`, func(url string) error {
		_, err := webhook.New(&webhook.Config{
			URL:                url,
			AllowInsecureHTTP:  true,
			AllowPrivateRanges: true,
			BatchSize:          1,
		}, nil, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with header containing CRLF$`, func() error {
		_, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          1,
			Headers:            map[string]string{"X-Bad": "value\r\nInjected: true"},
		}, nil, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a webhook output with batch size (\d+)$`, func(batchSize int) error {
		_, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          batchSize,
		}, nil, nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I rapidly audit (\d+) webhook events measuring time$`, func(count int) error {
		start := time.Now()
		for i := range count {
			_ = tc.Logger.Audit("user_create", audit.Fields{
				"outcome":  "success",
				"actor_id": fmt.Sprintf("rapid_%d", i),
			})
		}
		tc.AuditDuration = time.Since(start)
		return nil
	})

	ctx.Step(`^all (\d+) audit calls should complete within (\d+) seconds$`, func(count, secs int) error {
		if tc.AuditDuration == 0 {
			return fmt.Errorf("no audit duration recorded")
		}
		maxDuration := time.Duration(secs) * time.Second
		if tc.AuditDuration > maxDuration {
			return fmt.Errorf("%d audit calls took %v (max %v) — suggests blocking", count, tc.AuditDuration, maxDuration)
		}
		return nil
	})

	ctx.Step(`^I try to create a webhook output with max retries (\d+)$`, func(maxRetries int) error {
		_, err := webhook.New(&webhook.Config{
			URL:                "https://example.com/events",
			AllowPrivateRanges: true,
			BatchSize:          1,
			MaxRetries:         maxRetries,
		}, nil, nil)
		tc.LastErr = err
		return nil
	})
}

func registerWebhookThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the webhook receiver should have at least (\d+) event within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have at least (\d+) events? within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have received all (\d+) events within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have at least (\d+) requests? within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookEventCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the webhook receiver should have exactly (\d+) events within (\d+) seconds$`, func(n, timeout int) error {
		return assertWebhookExactCount(tc, n, time.Duration(timeout)*time.Second)
	})

	ctx.Step(`^the received webhook event should have header "([^"]*)" with value "([^"]*)"$`, func(name, value string) error {
		return assertWebhookHeader(tc, name, value)
	})

	ctx.Step(`^the webhook event body should contain field "([^"]*)" with value "([^"]*)"$`, func(field, value string) error {
		return assertWebhookBodyField(tc, field, value)
	})

	ctx.Step(`^the webhook event body should contain field "([^"]*)"$`, func(field string) error {
		return assertWebhookBodyFieldPresent(tc, field)
	})

	ctx.Step(`^the webhook construction should fail with exact error:$`, func(doc *godog.DocString) error {
		expected := strings.TrimSpace(doc.Content)
		if tc.LastErr == nil {
			return fmt.Errorf("expected error:\n  %q\ngot: nil", expected)
		}
		if tc.LastErr.Error() != expected {
			return fmt.Errorf("expected error:\n  %q\ngot:\n  %q", expected, tc.LastErr.Error())
		}
		return nil
	})

	ctx.Step(`^the webhook construction should fail with an error$`, func() error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected webhook construction error, got nil")
		}
		return nil
	})

	ctx.Step(`^the webhook construction should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %w", substr, tc.LastErr)
		}
		return nil
	})
}

// --- Internal helpers ---

func createWebhookLogger(tc *AuditTestContext, cfg *webhook.Config) error {
	cfg.URL = tc.WebhookURL + "/events"
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true
	cfg.Timeout = 5 * time.Second
	return createWebhookLoggerFromConfig(tc, cfg)
}

func createWebhookLoggerWithURL(tc *AuditTestContext, url string, cfg *webhook.Config) error {
	cfg.URL = url
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true
	cfg.Timeout = 5 * time.Second
	return createWebhookLoggerFromConfig(tc, cfg)
}

func createWebhookLoggerFromConfig(tc *AuditTestContext, cfg *webhook.Config) error {
	out, err := webhook.New(cfg, nil, nil)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(out),
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func auditMarkedWebhookEvent(tc *AuditTestContext, eventType, name string) error {
	if tc.Logger == nil {
		return fmt.Errorf("logger is nil (construction may have failed: %w)", tc.LastErr)
	}
	m := marker("WH")
	tc.Markers[name] = m
	fields := defaultRequiredFields(tc.Taxonomy, eventType)
	fields["marker"] = m
	tc.LastErr = tc.Logger.Audit(eventType, fields)
	return nil
}

func configureWebhook(baseURL string, statusCode, delayMS int) error {
	body := fmt.Sprintf(`{"status_code":%d,"delay_ms":%d}`, statusCode, delayMS)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+"/configure", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("configure request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("configure webhook: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("configure webhook close body: %w", err)
	}
	return nil
}

func getWebhookEvents(baseURL string) ([]webhookEvent, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		baseURL+"/events", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("get events request: %w", err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get events: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read events: %w", err)
	}
	var events []webhookEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("parse events: %w", err)
	}
	return events, nil
}

// webhookEvent represents an event stored by the webhook receiver.
type webhookEvent struct { //nolint:govet // fieldalignment: JSON field order matches receiver API
	Body    json.RawMessage   `json:"body"`
	Headers map[string]string `json:"headers"`
	Time    time.Time         `json:"time"`
}

func assertWebhookEventCount(tc *AuditTestContext, minCount int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events, err := getWebhookEvents(tc.WebhookURL)
		if err == nil && len(events) >= minCount {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	events, _ := getWebhookEvents(tc.WebhookURL)
	return fmt.Errorf("wanted >= %d webhook events, got %d after %v", minCount, len(events), timeout)
}

func assertWebhookExactCount(tc *AuditTestContext, exactCount int, timeout time.Duration) error {
	// Wait for events to arrive, then verify exact count.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		events, err := getWebhookEvents(tc.WebhookURL)
		if err == nil && len(events) >= exactCount {
			if len(events) == exactCount {
				return nil
			}
			return fmt.Errorf("wanted exactly %d webhook events, got %d", exactCount, len(events))
		}
		time.Sleep(200 * time.Millisecond)
	}
	events, _ := getWebhookEvents(tc.WebhookURL)
	return fmt.Errorf("wanted exactly %d webhook events, got %d after %v", exactCount, len(events), timeout)
}

func assertWebhookHeader(tc *AuditTestContext, name, value string) error {
	events, err := getWebhookEvents(tc.WebhookURL)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("no webhook events to check headers")
	}
	got, ok := events[0].Headers[name]
	if !ok {
		return fmt.Errorf("header %q not found in webhook event (headers: %v)", name, events[0].Headers)
	}
	if got != value {
		return fmt.Errorf("header %q: want %q, got %q", name, value, got)
	}
	return nil
}

func assertWebhookBodyField(tc *AuditTestContext, field, value string) error {
	body, err := getFirstWebhookBody(tc)
	if err != nil {
		return err
	}
	got, ok := body[field]
	if !ok {
		return fmt.Errorf("field %q not found in webhook body", field)
	}
	if fmt.Sprintf("%v", got) != value {
		return fmt.Errorf("field %q: want %q, got %q", field, value, got)
	}
	return nil
}

func assertWebhookBodyFieldPresent(tc *AuditTestContext, field string) error {
	body, err := getFirstWebhookBody(tc)
	if err != nil {
		return err
	}
	if _, ok := body[field]; !ok {
		return fmt.Errorf("field %q not found in webhook body (keys: %v)", field, mapKeys(body))
	}
	return nil
}

func getFirstWebhookBody(tc *AuditTestContext) (map[string]any, error) {
	events, err := getWebhookEvents(tc.WebhookURL)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("no webhook events")
	}
	var body map[string]any
	if err := json.Unmarshal(events[0].Body, &body); err != nil {
		return nil, fmt.Errorf("parse webhook body: %w", err)
	}
	return body, nil
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
