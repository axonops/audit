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

// Step definitions for tests/bdd/features/stdout_output.feature (#578).
//
// The scenarios cover the non-panicking constructors NewStdout /
// NewStderr / NewWriter added in #578. They replace the removed
// Stdout() helper that panicked on error.

package steps

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	"github.com/axonops/audit"
)

// stdoutCaptureState holds the pipe-redirection state for a single
// scenario that captures os.Stdout or os.Stderr.
type stdoutCaptureState struct { //nolint:govet // fieldalignment: readability preferred over packing
	mu         sync.Mutex
	capturedSt bytes.Buffer
	capturedEr bytes.Buffer
	origStdout *os.File
	origStderr *os.File
	readerStd  *os.File
	readerErr  *os.File
	writerStd  *os.File
	writerErr  *os.File
	copyDoneSt chan struct{}
	copyDoneEr chan struct{}
	writerBuf  *bytes.Buffer // for NewWriter scenarios
}

func startStdoutCapture(s *stdoutCaptureState) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	s.origStdout = os.Stdout
	s.readerStd = r
	s.writerStd = w
	os.Stdout = w
	s.copyDoneSt = make(chan struct{})
	go func() {
		_, _ = io.Copy(&threadSafeBuf{buf: &s.capturedSt, mu: &s.mu}, r)
		close(s.copyDoneSt)
	}()
	return nil
}

func startStderrCapture(s *stdoutCaptureState) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	s.origStderr = os.Stderr
	s.readerErr = r
	s.writerErr = w
	os.Stderr = w
	s.copyDoneEr = make(chan struct{})
	go func() {
		_, _ = io.Copy(&threadSafeBuf{buf: &s.capturedEr, mu: &s.mu}, r)
		close(s.copyDoneEr)
	}()
	return nil
}

func stopStdoutCapture(s *stdoutCaptureState) {
	if s.writerStd != nil {
		_ = s.writerStd.Close()
		<-s.copyDoneSt
		os.Stdout = s.origStdout
		s.writerStd = nil
	}
	if s.writerErr != nil {
		_ = s.writerErr.Close()
		<-s.copyDoneEr
		os.Stderr = s.origStderr
		s.writerErr = nil
	}
}

type threadSafeBuf struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (t *threadSafeBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, err := t.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("threadSafeBuf write: %w", err)
	}
	return n, nil
}

func (s *stdoutCaptureState) stdoutString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capturedSt.String()
}

func (s *stdoutCaptureState) stderrString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capturedEr.String()
}

// newAuditorWithOutput builds a standard BDD auditor with the given
// output. Extracted to keep registerStdoutSteps below the cognitive-
// complexity threshold.
func newAuditorWithOutput(tc *AuditTestContext, out audit.Output) (*audit.Auditor, error) {
	a, err := audit.New(
		audit.WithTaxonomy(tc.Taxonomy),
		audit.WithAppName("bdd-audit"),
		audit.WithHost("bdd-host"),
		audit.WithOutputs(out),
	)
	if err != nil {
		return nil, fmt.Errorf("new auditor: %w", err)
	}
	return a, nil
}

func registerStdoutSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	var capture *stdoutCaptureState

	registerStdoutGivenSteps(ctx, tc, &capture)
	registerStdoutThenSteps(ctx, tc, &capture)
}

func registerStdoutGivenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext, capturePtr **stdoutCaptureState) {
	ctx.Step(`^an auditor with output from NewStdout$`, stdoutStepNewStdout(tc, capturePtr))
	ctx.Step(`^an auditor with output from NewStderr$`, stdoutStepNewStderr(tc, capturePtr))
	ctx.Step(`^an auditor with output from NewWriter pointed at a buffer$`, stdoutStepNewWriterBuffer(tc, capturePtr))
	ctx.Step(`^an auditor with output from NewWriter with a nil writer$`, stdoutStepNewWriterNil(tc, capturePtr))
}

func stdoutStepNewStdout(tc *AuditTestContext, capturePtr **stdoutCaptureState) func() error {
	return func() error {
		*capturePtr = &stdoutCaptureState{}
		if err := startStdoutCapture(*capturePtr); err != nil {
			return err
		}
		out, err := audit.NewStdout()
		if err != nil {
			return fmt.Errorf("new stdout: %w", err)
		}
		a, err := newAuditorWithOutput(tc, out)
		if err != nil {
			return err
		}
		tc.Auditor = a
		return nil
	}
}

func stdoutStepNewStderr(tc *AuditTestContext, capturePtr **stdoutCaptureState) func() error {
	return func() error {
		*capturePtr = &stdoutCaptureState{}
		if err := startStderrCapture(*capturePtr); err != nil {
			return err
		}
		out, err := audit.NewStderr()
		if err != nil {
			return fmt.Errorf("new stderr: %w", err)
		}
		a, err := newAuditorWithOutput(tc, out)
		if err != nil {
			return err
		}
		tc.Auditor = a
		return nil
	}
}

func stdoutStepNewWriterBuffer(tc *AuditTestContext, capturePtr **stdoutCaptureState) func() error {
	return func() error {
		*capturePtr = &stdoutCaptureState{writerBuf: &bytes.Buffer{}}
		out, err := audit.NewWriter((*capturePtr).writerBuf)
		if err != nil {
			return fmt.Errorf("new writer: %w", err)
		}
		a, err := newAuditorWithOutput(tc, out)
		if err != nil {
			return err
		}
		tc.Auditor = a
		return nil
	}
}

func stdoutStepNewWriterNil(tc *AuditTestContext, capturePtr **stdoutCaptureState) func() error {
	return func() error {
		*capturePtr = &stdoutCaptureState{}
		if err := startStdoutCapture(*capturePtr); err != nil {
			return err
		}
		out, err := audit.NewWriter(nil)
		if err != nil {
			return fmt.Errorf("new writer nil: %w", err)
		}
		a, err := newAuditorWithOutput(tc, out)
		if err != nil {
			return err
		}
		tc.Auditor = a
		return nil
	}
}

func registerStdoutThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext, capturePtr **stdoutCaptureState) {
	ctx.Step(`^the captured stdout should contain the marker$`, func() error {
		stopStdoutCapture(*capturePtr)
		m := tc.Markers["default"]
		if m == "" {
			return fmt.Errorf("no default marker set")
		}
		got := (*capturePtr).stdoutString()
		if !strings.Contains(got, m) {
			return fmt.Errorf("stdout %q does not contain marker %q", got, m)
		}
		return nil
	})

	ctx.Step(`^the captured stderr should contain the marker$`, func() error {
		stopStdoutCapture(*capturePtr)
		m := tc.Markers["default"]
		if m == "" {
			return fmt.Errorf("no default marker set")
		}
		got := (*capturePtr).stderrString()
		if !strings.Contains(got, m) {
			return fmt.Errorf("stderr %q does not contain marker %q", got, m)
		}
		return nil
	})

	ctx.Step(`^the supplied buffer should contain the marker$`, func() error {
		m := tc.Markers["default"]
		if m == "" {
			return fmt.Errorf("no default marker set")
		}
		got := (*capturePtr).writerBuf.String()
		if !strings.Contains(got, m) {
			return fmt.Errorf("supplied buffer %q does not contain marker %q", got, m)
		}
		return nil
	})
}
