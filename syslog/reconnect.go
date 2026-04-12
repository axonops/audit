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

package syslog

import (
	"crypto/rand"
	"fmt"
	"math"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/srslog"
)

func (s *Output) handleWriteFailure(data []byte, priority srslog.Priority, writeErr error) (*bool, error) {
	s.failures++

	if s.failures > s.maxRetry {
		s.logger.Error("audit: syslog max retries exceeded",
			"address", s.address,
			"failures", s.failures,
			"last_error", writeErr)
		return nil, fmt.Errorf("audit: syslog write after %d failures: %w",
			s.failures, writeErr)
	}

	// Close the old writer before reconnecting.
	if s.writer != nil {
		_ = s.writer.Close()
		s.writer = nil
	}

	backoff := backoffDuration(s.failures)
	s.logger.Warn("audit: syslog reconnecting",
		"address", s.address,
		"attempt", s.failures,
		"backoff", backoff)

	// Release the mutex during backoff so Close() can proceed.
	s.mu.Unlock()
	select {
	case <-time.After(backoff):
	case <-s.closeCh:
		s.mu.Lock()
		return nil, fmt.Errorf("audit: syslog closed during reconnect: %w", writeErr)
	}
	s.mu.Lock()

	// Check if we were closed while sleeping.
	if s.closed {
		return nil, audit.ErrOutputClosed
	}

	if err := s.connect(); err != nil {
		s.logger.Error("audit: syslog reconnect failed",
			"address", s.address,
			"attempt", s.failures,
			"error", err)
		reconnected := false
		return &reconnected, fmt.Errorf("audit: syslog reconnect: %w", err)
	}

	s.logger.Info("audit: syslog reconnected", "address", s.address)
	reconnected := true

	// Retry the write on the new connection with the original priority.
	if _, err := s.writer.WriteWithPriority(priority, data); err != nil {
		return &reconnected, fmt.Errorf("audit: syslog write after reconnect: %w", err)
	}

	s.failures = 0
	return &reconnected, nil
}

// backoffDuration returns the backoff duration for the given attempt
// number using bounded exponential backoff with jitter
// (100ms * 2^(attempt-1) * [0.5, 1.0], capped at 30s). Jitter prevents
// thundering herd when multiple clients reconnect simultaneously.
//
// SYNC: similar implementations in webhook/http.go (webhookBackoff)
// and loki/http.go (lokiBackoff). Syslog uses a 30s cap (persistent
// TCP reconnection) vs 5s for HTTP outputs. The exponent uses
// attempt-1 because s.failures is pre-incremented before this call,
// so attempt=1 yields the initial 100ms base delay.
func backoffDuration(attempt int) time.Duration {
	exp := math.Min(float64(attempt-1), 20) // clamp exponent to avoid overflow
	d := syslogBaseBackoff * time.Duration(math.Pow(2, exp))
	if d > syslogMaxBackoff {
		d = syslogMaxBackoff
	}
	// Add jitter: multiply by [0.5, 1.0) using crypto/rand.
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0 // [0.5, 1.0)
		d = time.Duration(float64(d) * jitter)
	}
	return d
}

// validateSyslogConfig checks the config for correctness, applying
