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

// Package steps provides Godog step definitions for go-audit BDD tests.
// Each step translates Gherkin into go-audit public API calls. Step
// definitions are deliberately thin — no business logic, just API calls
// and assertions.
package steps

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

// AuditTestContext holds all mutable state for a single BDD scenario.
// A fresh context is created for every scenario in BeforeScenario.
type AuditTestContext struct { //nolint:govet // fieldalignment: readability preferred over packing
	// Logger state.
	Logger      *audit.Logger
	EventHandle *audit.EventType
	LastErr     error
	Taxonomy    audit.Taxonomy
	Config      audit.Config
	Options     []audit.Option

	// Output capture.
	StdoutBuf *bytes.Buffer     // in-memory output for non-Docker scenarios
	FilePaths map[string]string // logical name -> temp file path
	FileDir   string            // temp directory (cleaned up after scenario)
	Markers   map[string]string // logical name -> unique marker string

	// Docker infrastructure.
	WebhookURL    string // "http://localhost:8080"
	LokiURL       string // "http://localhost:3100"
	TLSReceiver   any    // *tlsWebhookReceiver for HTTPS webhook tests
	LocalReceiver any    // *localWebhookReceiver or *localLokiReceiver for SSRF/redirect/retry tests

	// Middleware state.
	TestServer   *httptest.Server
	LastHTTPResp *http.Response

	// Route query result.
	QueriedRoute *audit.EventRoute

	// Loki output name (dynamic: "loki:<host>").
	LokiOutputName string

	// HMAC capture.
	CaptureOutput  *captureOutput            // raw event bytes for HMAC verification
	CaptureOutputs map[string]*captureOutput // named outputs for multi-output HMAC tests

	// MetadataWriter capture.
	MetadataMock *MetadataWriterMock

	// Metrics capture.
	MockMetrics    *MockMetrics
	WebhookMetrics *MockWebhookMetrics
	FileMetrics    *MockFileMetrics
	SyslogMetrics  *MockSyslogMetrics
	LokiMetrics    *MockLokiMetrics
	AuditDuration  time.Duration // measured duration for timing assertions

	// Cleanup functions run in AfterScenario (LIFO order).
	cleanups []func()
	mu       sync.Mutex
}

// AddCleanup registers a cleanup function to run after the scenario.
func (tc *AuditTestContext) AddCleanup(fn func()) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cleanups = append(tc.cleanups, fn)
}

// Cleanup runs all registered cleanup functions in reverse order.
func (tc *AuditTestContext) Cleanup() {
	tc.mu.Lock()
	fns := make([]func(), len(tc.cleanups))
	copy(fns, tc.cleanups)
	tc.mu.Unlock()

	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

// Reset prepares the context for a new scenario.
func (tc *AuditTestContext) Reset() {
	tc.Logger = nil
	tc.EventHandle = nil
	tc.LastErr = nil
	tc.Taxonomy = audit.Taxonomy{}
	tc.Config = audit.Config{}
	tc.Options = nil
	tc.StdoutBuf = nil
	tc.FilePaths = make(map[string]string)
	tc.FileDir = ""
	tc.Markers = make(map[string]string)
	tc.TestServer = nil
	tc.LastHTTPResp = nil
	tc.QueriedRoute = nil
	tc.CaptureOutput = nil
	tc.CaptureOutputs = nil
	tc.MockMetrics = nil
	tc.WebhookMetrics = nil
	tc.FileMetrics = nil
	tc.SyslogMetrics = nil
	tc.LokiMetrics = nil
	tc.AuditDuration = 0
	tc.TLSReceiver = nil
	tc.LocalReceiver = nil
	tc.cleanups = nil
}

// EnsureFileDir creates a temp directory for file outputs if not already set.
func (tc *AuditTestContext) EnsureFileDir() (string, error) {
	if tc.FileDir != "" {
		return tc.FileDir, nil
	}
	dir, err := os.MkdirTemp("", "bdd-audit-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	tc.FileDir = dir
	tc.AddCleanup(func() { _ = os.RemoveAll(dir) })
	return dir, nil
}

// InitializeScenario wires all step definitions and lifecycle hooks.
func InitializeScenario(ctx *godog.ScenarioContext) {
	tc := &AuditTestContext{
		WebhookURL: "http://localhost:8080",
		LokiURL:    "http://localhost:3100",
	}

	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc.Reset()
		// Reset webhook receiver if Docker is available (ignore errors
		// for non-Docker scenarios).
		_ = resetWebhookReceiver(tc.WebhookURL)
		return ctx, nil
	})

	ctx.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		// Close logger if not already closed.
		if tc.Logger != nil {
			_ = tc.Logger.Close()
		}
		tc.Cleanup()
		return ctx, nil
	})

	// Register all step definitions.
	registerAuditSteps(ctx, tc)
	registerTaxonomySteps(ctx, tc)
	registerFilterSteps(ctx, tc)
	registerConfigSteps(ctx, tc)
	registerFileSteps(ctx, tc)
	registerFormatterSteps(ctx, tc)
	registerShutdownSteps(ctx, tc)
	registerMetricsSteps(ctx, tc)
	registerSyslogSteps(ctx, tc)
	registerWebhookSteps(ctx, tc)
	registerFanoutSteps(ctx, tc)
	registerMiddlewareSteps(ctx, tc)
	RegisterMultiCatSteps(ctx, tc)
	registerSeverityRoutingSteps(ctx, tc)
	registerSensitivitySteps(ctx, tc)
	registerBuilderSteps(ctx, tc)
	registerHMACSteps(ctx, tc)
	registerMetadataWriterSteps(ctx, tc)
	registerLokiSteps(ctx, tc)
	registerLokiReceiverSteps(ctx, tc)
	registerLokiHMACSteps(ctx, tc)
	registerLokiFanoutSteps(ctx, tc)
	registerLokiUncategorisedSteps(ctx, tc)
}
