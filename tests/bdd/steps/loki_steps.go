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
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
)

// lokiQueryClient is a dedicated HTTP client for querying Loki in BDD tests.
var lokiQueryClient = &http.Client{Timeout: 15 * time.Second} //nolint:gochecknoglobals // test infrastructure

const defaultLokiTenant = "bdd-test"

// registerLokiSteps registers all Loki-specific Given/When/Then steps.
func registerLokiSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiGivenSteps(ctx, tc)
	registerLokiWhenSteps(ctx, tc)
	registerLokiThenSteps(ctx, tc)
}

// ---------------------------------------------------------------------------
// Given steps — construction
// ---------------------------------------------------------------------------

func registerLokiGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiGivenConstructionSteps(ctx, tc)
	registerLokiGivenValidationSteps(ctx, tc)
	registerLokiGivenConfigSteps(ctx, tc)
}

func registerLokiGivenConstructionSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {

	ctx.Step(`^a logger with loki output$`, func() error {
		return createLokiLogger(tc, &loki.Config{Compress: true})
	})

	ctx.Step(`^a logger with loki output to tenant "([^"]*)"$`, func(tenant string) error {
		return createLokiLogger(tc, &loki.Config{TenantID: tenant, Compress: true})
	})

	ctx.Step(`^a logger with loki output with static label "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return createLokiLogger(tc, &loki.Config{
			Compress: true,
			Labels:   loki.LabelConfig{Static: map[string]string{name: value}},
		})
	})

	ctx.Step(`^a logger with loki output with batch size (\d+)$`, func(size int) error {
		return createLokiLogger(tc, &loki.Config{BatchSize: size, Compress: true})
	})

	ctx.Step(`^a logger with loki output with batch size (\d+) and flush interval (\d+)ms$`, func(size, ms int) error {
		return createLokiLogger(tc, &loki.Config{
			BatchSize:     size,
			FlushInterval: time.Duration(ms) * time.Millisecond,
			Compress:      true,
		})
	})

	ctx.Step(`^a logger with loki output with batch size (\d+) and flush interval (\d+)s$`, func(size, s int) error {
		return createLokiLogger(tc, &loki.Config{
			BatchSize:     size,
			FlushInterval: time.Duration(s) * time.Second,
			Compress:      true,
		})
	})

	ctx.Step(`^a logger with loki output excluding dynamic label "([^"]*)"$`, func(label string) error {
		cfg := &loki.Config{Compress: true}
		switch label {
		case "severity":
			cfg.Labels.Dynamic.ExcludeSeverity = true
		case "event_type":
			cfg.Labels.Dynamic.ExcludeEventType = true
		case "event_category":
			cfg.Labels.Dynamic.ExcludeEventCategory = true
		case "app_name":
			cfg.Labels.Dynamic.ExcludeAppName = true
		case "host":
			cfg.Labels.Dynamic.ExcludeHost = true
		case "pid":
			cfg.Labels.Dynamic.ExcludePID = true
		default:
			return fmt.Errorf("unknown dynamic label: %s", label)
		}
		return createLokiLogger(tc, cfg)
	})

	ctx.Step(`^a logger with loki output with gzip enabled$`, func() error {
		return createLokiLogger(tc, &loki.Config{Compress: true})
	})

	ctx.Step(`^a logger with loki output with gzip disabled$`, func() error {
		cfg := &loki.Config{}
		cfg.Compress = false
		return createLokiLogger(tc, cfg)
	})
}

func registerLokiGivenValidationSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I try to create a loki output with empty URL$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{URL: ""})
	})

	ctx.Step(`^I try to create a loki output to "([^"]*)"$`, func(rawURL string) error {
		return tryCreateLokiOutput(tc, &loki.Config{URL: rawURL})
	})

	ctx.Step(`^I try to create a loki output with basic auth and bearer token$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:         "https://loki.example.com/push",
			BasicAuth:   &loki.BasicAuth{Username: "user", Password: "pass"},
			BearerToken: "token",
		})
	})

	ctx.Step(`^I try to create a loki output with basic auth username "([^"]*)" and password "([^"]*)"$`, func(user, pass string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:       "https://loki.example.com/push",
			BasicAuth: &loki.BasicAuth{Username: user, Password: pass},
		})
	})

	ctx.Step(`^I try to create a loki output with static label "([^"]*)" = "([^"]*)"$`, func(name, value string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:    "https://loki.example.com/push",
			Labels: loki.LabelConfig{Static: map[string]string{name: value}},
		})
	})

	ctx.Step(`^I try to create a loki output with static label "([^"]*)" containing control chars$`, func(name string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:    "https://loki.example.com/push",
			Labels: loki.LabelConfig{Static: map[string]string{name: "prod\ninjected"}},
		})
	})

	ctx.Step(`^I try to create a loki output with unknown dynamic label "([^"]*)"$`, func(name string) error {
		// Use the YAML factory path to test dynamic label validation.
		yamlCfg := fmt.Sprintf("url: https://loki.example.com/push\nlabels:\n  dynamic:\n    %s: true\n", name)
		factory := audit.LookupOutputFactory("loki")
		if factory == nil {
			return fmt.Errorf("loki factory not registered")
		}
		_, err := factory("test", []byte(yamlCfg), nil)
		tc.LastErr = err
		return nil
	})

	ctx.Step(`^I try to create a loki output with header containing CRLF$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			Headers: map[string]string{"X-Bad\r\nHeader": "value"},
		})
	})

	ctx.Step(`^I try to create a loki output with restricted header "([^"]*)"$`, func(header string) error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			Headers: map[string]string{header: "value"},
		})
	})

	ctx.Step(`^I try to create a loki output with (\w+) set to (-?\d+)$`, func(field string, value int) error {
		cfg := &loki.Config{URL: "https://loki.example.com/push"}
		switch field {
		case "batch_size":
			cfg.BatchSize = value
		case "buffer_size":
			cfg.BufferSize = value
		case "max_retries":
			cfg.MaxRetries = value
		default:
			return fmt.Errorf("unknown field: %s", field)
		}
		return tryCreateLokiOutput(tc, cfg)
	})

	ctx.Step(`^I try to create a loki output with tls_cert but no tls_key$`, func() error {
		return tryCreateLokiOutput(tc, &loki.Config{
			URL:     "https://loki.example.com/push",
			TLSCert: "/tmp/cert.pem",
		})
	})

}

func registerLokiGivenConfigSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Config.String() credential redaction steps.
	ctx.Step(`^a loki config with basic auth username "([^"]*)" and password "([^"]*)"$`, func(user, pass string) error {
		cfg := loki.Config{
			URL:       "https://loki.example.com/push",
			BasicAuth: &loki.BasicAuth{Username: user, Password: pass},
			BatchSize: 100,
		}
		tc.Markers["config_string"] = cfg.String()
		return nil
	})

	ctx.Step(`^a loki config with bearer token "([^"]*)"$`, func(token string) error {
		cfg := loki.Config{
			URL:         "https://loki.example.com/push",
			BearerToken: token,
			BatchSize:   100,
		}
		tc.Markers["config_string"] = cfg.String()
		return nil
	})

	ctx.Step(`^the config string should not contain "([^"]*)"$`, func(s string) error {
		cfgStr := tc.Markers["config_string"]
		if strings.Contains(cfgStr, s) {
			return fmt.Errorf("config string should not contain %q but got: %s", s, cfgStr)
		}
		return nil
	})

	ctx.Step(`^the config string should contain "([^"]*)"$`, func(s string) error {
		cfgStr := tc.Markers["config_string"]
		if !strings.Contains(cfgStr, s) {
			return fmt.Errorf("config string should contain %q but got: %s", s, cfgStr)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// When steps — Loki-specific event emission
// ---------------------------------------------------------------------------

func registerLokiWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit a uniquely marked "([^"]*)" event with field "([^"]*)" = "([^"]*)"$`,
		func(eventType, field, value string) error {
			m := marker("BDD")
			tc.Markers["default"] = m
			fields := defaultRequiredFields(tc.Taxonomy, eventType)
			fields["marker"] = m
			fields[field] = value
			return tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		})

	ctx.Step(`^I audit (\d+) loki events with a shared marker$`, func(count int) error {
		m := marker("BDD")
		tc.Markers["default"] = m
		for i := range count {
			fields := defaultRequiredFields(tc.Taxonomy, "user_create")
			fields["marker"] = m
			if err := tc.Logger.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
				return fmt.Errorf("audit event %d: %w", i, err)
			}
		}
		return nil
	})

	ctx.Step(`^I audit (\d+) uniquely marked events with the same timestamp$`,
		func(count int) error {
			for i := range count {
				m := marker("BDD")
				tc.Markers[fmt.Sprintf("multi_%d", i)] = m
				if i == 0 {
					tc.Markers["default"] = m
				}
				fields := defaultRequiredFields(tc.Taxonomy, "user_create")
				fields["marker"] = m
				if err := tc.Logger.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
					return fmt.Errorf("audit event %d: %w", i, err)
				}
			}
			return nil
		})

	ctx.Step(`^I try to audit a "([^"]*)" event$`, func(eventType string) error {
		fields := defaultRequiredFields(tc.Taxonomy, eventType)
		tc.LastErr = tc.Logger.AuditEvent(audit.NewEvent(eventType, fields))
		return nil
	})

	ctx.Step(`^no error should occur$`, func() error {
		if tc.LastErr != nil {
			return fmt.Errorf("expected no error but got: %w", tc.LastErr)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Then steps — assertions
// ---------------------------------------------------------------------------

func registerLokiThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the loki server should contain the marker within (\d+) seconds$`, func(secs int) error {
		return assertLokiContainsMarker(tc, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server should have at least (\d+) events? within (\d+) seconds$`, func(n, secs int) error {
		return assertLokiEventCount(tc, n, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki stream should have label "([^"]*)" with value "([^"]*)"$`, func(label, value string) error {
		return assertLokiStreamLabel(tc, label, value)
	})

	ctx.Step(`^the loki stream should not have label "([^"]*)"$`, func(label string) error {
		return assertLokiStreamLabelAbsent(tc, label)
	})

	ctx.Step(`^the loki event should contain field "([^"]*)" with value "([^"]*)"$`, func(field, value string) error {
		return assertLokiEventField(tc, field, value)
	})

	ctx.Step(`^the loki server should have events in stream "([^"]*)" within (\d+) seconds$`, func(eventType string, secs int) error {
		return assertLokiStreamExists(tc, eventType, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server for tenant "([^"]*)" should contain the marker within (\d+) seconds$`, func(tenant string, secs int) error {
		return assertLokiContainsMarkerForTenant(tc, tenant, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki server for tenant "([^"]*)" should not contain the marker within (\d+) seconds$`, func(tenant string, secs int) error {
		return assertLokiMarkerAbsentForTenant(tc, tenant, time.Duration(secs)*time.Second)
	})

	ctx.Step(`^the loki construction should fail with an error containing "([^"]*)"$`, func(substr string) error {
		if tc.LastErr == nil {
			return fmt.Errorf("expected construction error containing %q but got nil", substr)
		}
		if !strings.Contains(tc.LastErr.Error(), substr) {
			return fmt.Errorf("expected error containing %q, got: %s", substr, tc.LastErr.Error())
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Helpers — construction
// ---------------------------------------------------------------------------

// applyLokiTestDefaults fills zero-value config fields with BDD test defaults.
func applyLokiTestDefaults(tc *AuditTestContext, cfg *loki.Config) {
	if cfg.URL == "" {
		cfg.URL = tc.LokiURL + "/loki/api/v1/push"
	}
	cfg.AllowInsecureHTTP = true
	cfg.AllowPrivateRanges = true

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 200 * time.Millisecond
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1000
	}
	if cfg.TenantID == "" {
		cfg.TenantID = defaultLokiTenant
	}
	// Do NOT set cfg.Compress here — let each step control it.
	// The default zero value (false) is overridden by individual steps.

	if cfg.Labels.Static == nil {
		cfg.Labels.Static = make(map[string]string)
	}
	cfg.Labels.Static["test_suite"] = "bdd"
}

func createLokiLogger(tc *AuditTestContext, cfg *loki.Config) error {
	applyLokiTestDefaults(tc, cfg)

	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create loki output: %w", err)
	}

	logger, err := audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		_ = out.Close()
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func tryCreateLokiOutput(tc *AuditTestContext, cfg *loki.Config) error {
	_, err := loki.New(cfg, nil, nil)
	tc.LastErr = err
	return nil
}

// ---------------------------------------------------------------------------
// Helpers — Loki query
// ---------------------------------------------------------------------------

type lokiBDDQueryResult struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func queryLokiBDD(tc *AuditTestContext, logql, tenant string) (lokiBDDQueryResult, error) {
	now := time.Now()
	params := url.Values{
		"query": {logql},
		"start": {fmt.Sprintf("%d", now.Add(-5*time.Minute).UnixNano())},
		"end":   {fmt.Sprintf("%d", now.Add(1*time.Minute).UnixNano())},
		"limit": {"1000"},
	}

	lokiBase := tc.LokiURL
	if lokiBase == "" {
		lokiBase = "http://localhost:3100"
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		lokiBase+"/loki/api/v1/query_range?"+params.Encode(), http.NoBody)
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("build query request: %w", err)
	}
	if tenant == "" {
		tenant = defaultLokiTenant
	}
	req.Header.Set("X-Scope-OrgID", tenant)

	resp, err := lokiQueryClient.Do(req)
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("loki query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("read loki response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return lokiBDDQueryResult{}, fmt.Errorf("loki query returned %d: %s", resp.StatusCode, string(body))
	}

	var result lokiBDDQueryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return lokiBDDQueryResult{}, fmt.Errorf("parse loki response: %w", err)
	}
	return result, nil
}

func countLokiLines(result lokiBDDQueryResult) int {
	n := 0
	for _, s := range result.Data.Result {
		n += len(s.Values)
	}
	return n
}

// ---------------------------------------------------------------------------
// Helpers — assertions
// ---------------------------------------------------------------------------

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiContainsMarker(tc *AuditTestContext, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, defaultLokiTenant, 1, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiContainsMarkerForTenant(tc *AuditTestContext, tenant string, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, tenant, 1, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiMarkerAbsentForTenant(tc *AuditTestContext, tenant string, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)

	// Poll for the timeout — if events appear, that's a failure.
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		result, err := queryLokiBDD(tc, logql, tenant)
		if err == nil && countLokiLines(result) > 0 {
			return fmt.Errorf("tenant %q should NOT contain marker %s but found %d events", tenant, m, countLokiLines(result))
		}
		select {
		case <-deadline:
			return nil // timeout without finding events = success
		case <-tick.C:
		}
	}
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiEventCount(tc *AuditTestContext, n int, timeout time.Duration) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set — use a step that sets tc.Markers[\"default\"]")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	return pollLoki(tc, logql, defaultLokiTenant, n, timeout)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamLabel(tc *AuditTestContext, label, value string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	// Find the stream that contains our marker and check its labels.
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) >= 2 && strings.Contains(v[1], m) {
				got, ok := s.Stream[label]
				if ok && got == value {
					return nil
				}
				return fmt.Errorf("stream with marker has label %s=%q, want %q (stream labels: %v)",
					label, got, value, s.Stream)
			}
		}
	}
	return fmt.Errorf("no stream found containing marker %s with label %s=%q", m, label, value)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamLabelAbsent(tc *AuditTestContext, label string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, s := range result.Data.Result {
		if _, ok := s.Stream[label]; ok {
			return fmt.Errorf("stream should NOT have label %q but it does", label)
		}
	}
	return nil
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiEventField(tc *AuditTestContext, field, value string) error {
	m := tc.Markers["default"]
	if m == "" {
		return fmt.Errorf("no default marker set")
	}
	logql := fmt.Sprintf(`{test_suite="bdd"} |= "%s"`, m)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, s := range result.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(v[1]), &parsed); err != nil {
				continue
			}
			if got, ok := parsed[field]; ok && fmt.Sprintf("%v", got) == value {
				return nil
			}
		}
	}
	return fmt.Errorf("no event found with field %s=%q", field, value)
}

//nolint:gocritic // sprintfQuotedString: LogQL requires literal quotes
func assertLokiStreamExists(tc *AuditTestContext, eventType string, timeout time.Duration) error {
	// Query by event_type + test_suite label. Don't filter by marker
	// since multi-event-type scenarios may have different markers per event.
	logql := fmt.Sprintf(`{test_suite="bdd",event_type="%s"}`, eventType)
	return pollLoki(tc, logql, defaultLokiTenant, 1, timeout)
}

func pollLoki(tc *AuditTestContext, logql, tenant string, minCount int, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var lastCount int
	for {
		result, err := queryLokiBDD(tc, logql, tenant)
		if err == nil {
			lastCount = countLokiLines(result)
			if lastCount >= minCount {
				return nil
			}
		}
		select {
		case <-deadline:
			return fmt.Errorf("timed out: wanted %d events, got %d (query: %s)", minCount, lastCount, logql)
		case <-tick.C:
		}
	}
}
