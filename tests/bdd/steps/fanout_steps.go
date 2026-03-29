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
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/file"
	"github.com/axonops/go-audit/syslog"
	"github.com/axonops/go-audit/webhook"
)

// routingTaxonomyYAML provides write, read, and security categories.
const routingTaxonomyYAML = `
version: 1
categories:
  write:
    - user_create
    - config_update
  read:
    - user_get
    - config_read
  security:
    - auth_failure
    - permission_denied
events:
  user_create:    { category: write, required: [outcome, actor_id], optional: [marker] }
  config_update:  { category: write, required: [outcome, actor_id], optional: [marker] }
  user_get:       { category: read, required: [outcome], optional: [marker] }
  config_read:    { category: read, required: [outcome], optional: [marker] }
  auth_failure:   { category: security, required: [outcome, actor_id], optional: [marker] }
  permission_denied: { category: security, required: [outcome, actor_id], optional: [marker] }
default_enabled:
  - write
  - read
  - security
`

func registerFanoutSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerFanoutGivenSteps(ctx, tc)
	registerFanoutWhenSteps(ctx, tc)
	registerFanoutThenSteps(ctx, tc)
}

func registerFanoutGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with file and webhook outputs$`, func() error {
		return createFanoutLogger(tc, true, false, true, nil, nil)
	})
	ctx.Step(`^a logger with file and webhook outputs configured for batch size (\d+)$`, func(bs int) error {
		return createFanoutLogger(tc, true, false, true, nil, &bs)
	})
	ctx.Step(`^a logger with file and syslog outputs$`, func() error {
		return createFanoutLogger(tc, true, true, false, nil, nil)
	})
	ctx.Step(`^a logger with file, syslog, and webhook outputs$`, func() error {
		return createFanoutLogger(tc, true, true, true, nil, nil)
	})
	ctx.Step(`^a logger with file output using JSON and webhook output using CEF$`, func() error {
		cefFmt := &audit.CEFFormatter{Vendor: "Test", Product: "BDD", Version: "1.0"}
		return createFanoutLogger(tc, true, false, true, cefFmt, nil)
	})
	ctx.Step(`^a routing taxonomy with write, read, and security categories$`, func() error {
		tax, err := audit.ParseTaxonomyYAML([]byte(routingTaxonomyYAML))
		if err != nil {
			return fmt.Errorf("parse routing taxonomy: %w", err)
		}
		tc.Taxonomy = tax
		return nil
	})
	ctx.Step(`^a logger with file receiving all events and webhook receiving only "([^"]*)"$`, func(cat string) error {
		return createRoutedLogger(tc, &audit.EventRoute{IncludeCategories: []string{cat}})
	})
	ctx.Step(`^a logger with file receiving all events and webhook including event types "([^"]*)"$`, func(types string) error {
		return createRoutedLogger(tc, &audit.EventRoute{IncludeEventTypes: strings.Split(types, ",")})
	})
	ctx.Step(`^a logger with file receiving all events and webhook excluding categories "([^"]*)"$`, func(cat string) error {
		return createRoutedLogger(tc, &audit.EventRoute{ExcludeCategories: []string{cat}})
	})
	ctx.Step(`^a logger with file receiving all events and webhook including categories "([^"]*)" and event types "([^"]*)"$`, func(cats, types string) error {
		return createRoutedLogger(tc, &audit.EventRoute{
			IncludeCategories: strings.Split(cats, ","),
			IncludeEventTypes: strings.Split(types, ","),
		})
	})
	ctx.Step(`^a logger with file receiving all events and webhook excluding event types "([^"]*)"$`, func(types string) error {
		return createRoutedLogger(tc, &audit.EventRoute{ExcludeEventTypes: strings.Split(types, ",")})
	})
	ctx.Step(`^a logger with file and webhook both receiving all events$`, func() error {
		return createRoutedLogger(tc, nil) // nil route = all events
	})
	ctx.Step(`^I set the webhook output route to include only "([^"]*)"$`, func(cat string) error {
		// Webhook output name is "webhook:<host:port>" (from url.Parse).
		// tc.WebhookURL is "http://localhost:8080", so name is "webhook:localhost:8080".
		u := strings.TrimPrefix(tc.WebhookURL, "http://")
		u = strings.TrimPrefix(u, "https://")
		return tc.Logger.SetOutputRoute(
			"webhook:"+u,
			&audit.EventRoute{IncludeCategories: []string{cat}},
		)
	})
	ctx.Step(`^a logger with two file outputs where security goes to file-a and write goes to file-b$`, func() error {
		return createDualFileRoutedLogger(tc)
	})
	ctx.Step(`^a logger with file getting all, syslog getting security, and webhook getting write$`, func() error {
		return createTripleRoutedLogger(tc)
	})
	ctx.Step(`^I disable category "([^"]*)"$`, func(cat string) error {
		return tc.Logger.DisableCategory(cat)
	})
	ctx.Step(`^file "([^"]*)" should contain "([^"]*)"$`, func(name, text string) error {
		return assertFileContainsText(tc, name, text)
	})
	ctx.Step(`^file "([^"]*)" should not contain "([^"]*)"$`, func(name, text string) error {
		raw, err := readRawFile(tc, name)
		if err != nil {
			return err
		}
		if strings.Contains(raw, text) {
			return fmt.Errorf("file %q unexpectedly contains %q", name, text)
		}
		return nil
	})
	ctx.Step(`^the file should not contain "([^"]*)"$`, func(text string) error {
		raw, err := readRawFile(tc, "default")
		if err != nil {
			return err
		}
		if strings.Contains(raw, text) {
			return fmt.Errorf("file unexpectedly contains %q", text)
		}
		return nil
	})
}

func registerFanoutWhenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^I audit (?:a|an) "([^"]*)" event in category "[^"]*" with marker "([^"]*)"$`, func(eventType, m string) error {
		return auditEventWithMarker(tc, eventType, m)
	})
	ctx.Step(`^I try to create a logger with duplicate output names$`, func() error {
		return tryDuplicateOutputNames(tc)
	})
	ctx.Step(`^I try to create a logger with two file outputs to the same path$`, func() error {
		return tryDuplicateFilePath(tc)
	})
	ctx.Step(`^I try to create a logger with mixed include and exclude route$`, func() error {
		return tryMixedRoute(tc)
	})
	ctx.Step(`^I try to create a logger with route referencing unknown category$`, func() error {
		return tryUnknownCategoryRoute(tc)
	})
	ctx.Step(`^I try to create a logger with route referencing unknown event type$`, func() error {
		return tryUnknownEventTypeRoute(tc)
	})
}

func registerFanoutThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the file should contain the marker$`, func() error {
		m, ok := tc.Markers["default"]
		if !ok {
			return fmt.Errorf("no default marker set")
		}
		return assertFileContainsText(tc, "default", m)
	})
	ctx.Step(`^the file should contain "([^"]*)"$`, func(text string) error {
		return assertFileContainsText(tc, "default", text)
	})
	ctx.Step(`^the file should contain JSON format with "([^"]*)"$`, func(text string) error {
		return assertFileContainsText(tc, "default", text)
	})
	ctx.Step(`^the file should have no events$`, func() error {
		events, err := readFileEvents(tc, "default")
		if err != nil {
			return err
		}
		if len(events) > 0 {
			return fmt.Errorf("expected no events in file, got %d", len(events))
		}
		return nil
	})
}

// --- Extracted when-step helpers ---

func auditEventWithMarker(tc *AuditTestContext, eventType, m string) error {
	if tc.Logger == nil {
		return fmt.Errorf("logger is nil")
	}
	tc.Markers[m] = m
	fields := defaultRequiredFields(tc.Taxonomy, eventType)
	fields["marker"] = m
	tc.LastErr = tc.Logger.Audit(eventType, fields)
	return nil
}

func tryDuplicateOutputNames(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f1, err := file.New(file.Config{Path: filepath.Join(dir, "a.log")}, nil)
	if err != nil {
		return fmt.Errorf("create file a: %w", err)
	}
	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(f1, f1), // same output = duplicate name
	)
	tc.LastErr = err
	return nil
}

func tryDuplicateFilePath(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	samePath := filepath.Join(dir, "same.log")
	f1, err := file.New(file.Config{Path: samePath}, nil)
	if err != nil {
		return fmt.Errorf("create file 1: %w", err)
	}
	f2, err := file.New(file.Config{Path: samePath}, nil)
	if err != nil {
		return fmt.Errorf("create file 2: %w", err)
	}
	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithOutputs(f1, f2),
	)
	tc.LastErr = err
	return nil
}

func tryMixedRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(file.Config{Path: filepath.Join(dir, "mixed.log")}, nil)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(f, &audit.EventRoute{
			IncludeCategories: []string{"write"},
			ExcludeCategories: []string{"read"},
		}, nil),
	)
	tc.LastErr = err
	return nil
}

func tryUnknownCategoryRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(file.Config{Path: filepath.Join(dir, "unknown.log")}, nil)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(f, &audit.EventRoute{
			IncludeCategories: []string{"nonexistent"},
		}, nil),
	)
	tc.LastErr = err
	return nil
}

func tryUnknownEventTypeRoute(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	f, err := file.New(file.Config{Path: filepath.Join(dir, "unknown_evt.log")}, nil)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	_, err = audit.NewLogger(
		audit.Config{Version: 1, Enabled: true},
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(f, &audit.EventRoute{
			IncludeEventTypes: []string{"nonexistent_event"},
		}, nil),
	)
	tc.LastErr = err
	return nil
}

// --- Internal helpers ---

func assertFileContainsText(tc *AuditTestContext, name, text string) error {
	raw, err := readRawFile(tc, name)
	if err != nil {
		return err
	}
	if !strings.Contains(raw, text) {
		return fmt.Errorf("file %q does not contain %q (length: %d bytes)", name, text, len(raw))
	}
	return nil
}

func createFanoutLogger(tc *AuditTestContext, useFile, useSyslog, useWebhook bool, webhookFmt audit.Formatter, batchSize *int) error {
	var opts []audit.Option
	opts = append(opts, audit.WithTaxonomy(tc.Taxonomy))

	if useFile {
		dir, err := tc.EnsureFileDir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, "audit.log")
		tc.FilePaths["default"] = path
		f, err := file.New(file.Config{Path: path}, nil)
		if err != nil {
			return fmt.Errorf("create file output: %w", err)
		}
		opts = append(opts, audit.WithNamedOutput(f, nil, nil))
	}

	if useSyslog {
		s, err := syslog.New(&syslog.Config{
			Network: "tcp", Address: "localhost:5514",
			Facility: "local0", AppName: "bdd-fanout",
		}, nil)
		if err != nil {
			return fmt.Errorf("create syslog output: %w", err)
		}
		opts = append(opts, audit.WithNamedOutput(s, nil, nil))
	}

	if useWebhook {
		bs := 1
		if batchSize != nil {
			bs = *batchSize
		}
		w, err := webhook.New(&webhook.Config{
			URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
			AllowPrivateRanges: true, BatchSize: bs,
			FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
		}, nil, nil)
		if err != nil {
			return fmt.Errorf("create webhook output: %w", err)
		}
		opts = append(opts, audit.WithNamedOutput(w, nil, webhookFmt))
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func createDualFileRoutedLogger(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	secPath := filepath.Join(dir, "security.log")
	writePath := filepath.Join(dir, "write.log")
	tc.FilePaths["security"] = secPath
	tc.FilePaths["write"] = writePath

	secOut, err := file.New(file.Config{Path: secPath}, nil)
	if err != nil {
		return fmt.Errorf("create security file: %w", err)
	}
	writeOut, err := file.New(file.Config{Path: writePath}, nil)
	if err != nil {
		return fmt.Errorf("create write file: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(secOut, &audit.EventRoute{IncludeCategories: []string{"security"}}, nil),
		audit.WithNamedOutput(writeOut, &audit.EventRoute{IncludeCategories: []string{"write"}}, nil),
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func createTripleRoutedLogger(tc *AuditTestContext) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	fileOut, err := file.New(file.Config{Path: path}, nil)
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	syslogOut, err := syslog.New(&syslog.Config{
		Network: "tcp", Address: "localhost:5514",
		Facility: "local0", AppName: "bdd-triple",
	}, nil)
	if err != nil {
		return fmt.Errorf("create syslog output: %w", err)
	}
	webhookOut, err := webhook.New(&webhook.Config{
		URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
		AllowPrivateRanges: true, BatchSize: 1,
		FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("create webhook output: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(fileOut, nil, nil), // all events
		audit.WithNamedOutput(syslogOut, &audit.EventRoute{IncludeCategories: []string{"security"}}, nil), // security only
		audit.WithNamedOutput(webhookOut, &audit.EventRoute{IncludeCategories: []string{"write"}}, nil),   // write only
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}

func createRoutedLogger(tc *AuditTestContext, webhookRoute *audit.EventRoute) error {
	dir, err := tc.EnsureFileDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "audit.log")
	tc.FilePaths["default"] = path

	f, err := file.New(file.Config{Path: path}, nil)
	if err != nil {
		return fmt.Errorf("create file output: %w", err)
	}
	w, err := webhook.New(&webhook.Config{
		URL: tc.WebhookURL + "/events", AllowInsecureHTTP: true,
		AllowPrivateRanges: true, BatchSize: 1,
		FlushInterval: 100 * time.Millisecond, Timeout: 5 * time.Second,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("create webhook output: %w", err)
	}

	opts := []audit.Option{
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithNamedOutput(f, nil, nil),
		audit.WithNamedOutput(w, webhookRoute, nil),
	}

	logger, err := audit.NewLogger(audit.Config{Version: 1, Enabled: true}, opts...)
	if err != nil {
		tc.LastErr = err
		return nil //nolint:nilerr // scenario may assert on tc.LastErr
	}
	tc.Logger = logger
	tc.AddCleanup(func() { _ = logger.Close() })
	return nil
}
