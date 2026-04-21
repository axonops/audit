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

package audit

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

func init() {
	RegisterOutputFactory("stdout", func(name string, rawConfig []byte, _ Metrics, _ *slog.Logger, _ FrameworkContext) (Output, error) {
		if len(rawConfig) > 0 {
			return nil, fmt.Errorf("audit: stdout output %q: stdout does not accept configuration", name)
		}
		out, err := NewStdoutOutput(StdoutConfig{})
		if err != nil {
			return nil, err
		}
		return WrapOutput(out, name), nil
	})
}

// StdoutConfig holds configuration for [StdoutOutput].
type StdoutConfig struct {
	// Writer is the destination for audit events. When nil, [os.Stdout]
	// is used. This field exists primarily for testing. The writer does
	// not need to be safe for concurrent use; StdoutOutput serialises
	// writes internally.
	Writer io.Writer
}

// StdoutOutput writes serialised audit events to an [io.Writer],
// defaulting to [os.Stdout]. It is intended for development and
// debugging; production deployments SHOULD use [FileOutput] or another
// persistent output.
//
// StdoutOutput does NOT close the underlying writer on [Close] because
// the writer is typically [os.Stdout], which must not be closed.
//
// StdoutOutput is safe for concurrent use.
type StdoutOutput struct {
	writer io.Writer
	mu     sync.Mutex
	closed bool
}

// Stdout returns a [StdoutOutput] that writes to [os.Stdout]. This is
// a convenience shorthand for NewStdoutOutput(StdoutConfig{}).
func Stdout() *StdoutOutput {
	out, err := NewStdoutOutput(StdoutConfig{})
	if err != nil {
		// StdoutConfig{} cannot fail today; panic guards against future
		// regressions in NewStdoutOutput validation.
		panic("audit: Stdout(): " + err.Error())
	}
	return out
}

// NewStdoutOutput creates a new [StdoutOutput] from the given config.
// If [StdoutConfig.Writer] is nil, [os.Stdout] is used.
func NewStdoutOutput(cfg StdoutConfig) (*StdoutOutput, error) {
	w := cfg.Writer
	if w == nil {
		w = os.Stdout
	}
	return &StdoutOutput{writer: w}, nil
}

// Write sends a serialised audit event to the underlying writer.
// Write returns [ErrOutputClosed] if the output has been closed.
// Write is safe for concurrent use.
func (s *StdoutOutput) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrOutputClosed
	}
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("audit: stdout output write: %w", err)
	}
	return nil
}

// Close marks the output as closed. Subsequent calls to [Write] return
// [ErrOutputClosed]. Close does NOT close the underlying writer. Close
// is idempotent and safe for concurrent use with [StdoutOutput.Write].
func (s *StdoutOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// Name returns the human-readable identifier for this output.
func (s *StdoutOutput) Name() string {
	return "stdout"
}
