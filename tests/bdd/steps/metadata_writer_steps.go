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
	"sync"

	"github.com/cucumber/godog"

	audit "github.com/axonops/go-audit"
)

// MetadataWriterMock implements both audit.Output and audit.MetadataWriter
// for BDD testing.
type MetadataWriterMock struct { //nolint:govet // fieldalignment: test mock
	mu       sync.Mutex
	name     string
	lastMeta audit.EventMetadata
	lastData []byte
	called   bool
	closed   bool
}

// Write implements audit.Output.
func (m *MetadataWriterMock) Write(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.lastData = cp
	return nil
}

// WriteWithMetadata implements audit.MetadataWriter.
func (m *MetadataWriterMock) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.lastData = cp
	m.lastMeta = meta
	m.called = true
	return nil
}

// Close implements audit.Output.
func (m *MetadataWriterMock) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Name implements audit.Output.
func (m *MetadataWriterMock) Name() string { return m.name }

func (m *MetadataWriterMock) getMeta() (audit.EventMetadata, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastMeta, m.called
}

func registerMetadataWriterSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerMetadataWriterGivenSteps(ctx, tc)
	registerMetadataWriterThenSteps(ctx, tc)
}

func registerMetadataWriterGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^a logger with a MetadataWriter output$`, func() error {
		mock := &MetadataWriterMock{name: "bdd-metadata-writer"}
		tc.MetadataMock = mock

		opts := []audit.Option{
			audit.WithTaxonomy(tc.Taxonomy),
			audit.WithNamedOutput(mock),
		}
		opts = append(opts, tc.Options...)

		logger, err := audit.NewLogger(opts...)
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		tc.Logger = logger
		tc.AddCleanup(func() { _ = logger.Close() })
		return nil
	})

}

// flushAndGetMeta closes the logger and returns the captured metadata.
func flushAndGetMeta(tc *AuditTestContext) (audit.EventMetadata, error) {
	if tc.Logger != nil {
		_ = tc.Logger.Close()
	}
	meta, called := tc.MetadataMock.getMeta()
	if !called {
		return meta, fmt.Errorf("WriteWithMetadata was not called")
	}
	return meta, nil
}

func registerMetadataWriterThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	ctx.Step(`^the MetadataWriter should have received event_type "([^"]*)"$`, func(expected string) error {
		meta, err := flushAndGetMeta(tc)
		if err != nil {
			return err
		}
		if meta.EventType != expected {
			return fmt.Errorf("expected event_type %q, got %q", expected, meta.EventType)
		}
		return nil
	})

	ctx.Step(`^the MetadataWriter should have received severity (\d+)$`, func(expected int) error {
		meta, err := flushAndGetMeta(tc)
		if err != nil {
			return err
		}
		if meta.Severity != expected {
			return fmt.Errorf("expected severity %d, got %d", expected, meta.Severity)
		}
		return nil
	})

	ctx.Step(`^the MetadataWriter should have received category "([^"]*)"$`, func(expected string) error {
		meta, err := flushAndGetMeta(tc)
		if err != nil {
			return err
		}
		if meta.Category != expected {
			return fmt.Errorf("expected category %q, got %q", expected, meta.Category)
		}
		return nil
	})
}
