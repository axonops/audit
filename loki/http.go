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

package loki

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Backoff constants for retry logic. Hardcoded to match the webhook
// output pattern — MaxRetries is the user's control surface.
const (
	backoffBase = 100 * time.Millisecond
	backoffMax  = 5 * time.Second
)

// maxRetryAfter caps the server-provided Retry-After header to prevent
// a malicious server from forcing unbounded delay.
const maxRetryAfter = 30 * time.Second

// maxResponseBody limits the response body drained after each request,
// preventing a malicious server from forcing unbounded memory allocation.
const maxResponseBody = 64 << 10 // 64 KiB

// doPostWithRetry attempts HTTP POST with exponential backoff retry.
// On success, delivery metrics are recorded. On retries exhausted or
// non-retryable errors, drop metrics are recorded. This method is
// called from flush(), which runs in the single batchLoop goroutine.
// The body []byte comes from maybeCompress() and points into Output
// buffers that are safe to use because flush() is synchronous.
func (o *Output) doPostWithRetry(ctx context.Context, body []byte, batchSize int, compressed bool) {
	start := time.Now()
	o.retryHint = 0 // clear stale hint from previous batch

	for attempt := range o.cfg.MaxRetries {
		if attempt > 0 {
			backoff := lokiBackoff(attempt)

			// Respect Retry-After from a 429 if it exceeds computed backoff.
			// retryHint is set by the previous doPost call.
			if o.retryHint > backoff {
				backoff = o.retryHint
			}
			o.retryHint = 0

			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				o.recordDrop(batchSize)
				return
			}
		}

		retryable, _, err := o.doPost(ctx, body, compressed)
		if err == nil {
			o.recordSuccess(batchSize, time.Since(start))
			return
		}

		if !retryable {
			o.logger.Load().Error("audit: loki non-retryable error",
				"error", err,
				"batch_size", batchSize)
			o.recordError()
			o.recordDrop(batchSize)
			return
		}

		o.recordRetry(attempt + 1)
		o.logger.Load().Warn("audit: loki retryable error",
			"attempt", attempt+1,
			"max_retries", o.cfg.MaxRetries,
			"error", err)
	}

	// All retries exhausted.
	o.logger.Load().Error("audit: loki retries exhausted, dropping batch",
		"batch_size", batchSize,
		"max_retries", o.cfg.MaxRetries)
	o.recordDrop(batchSize)
}

// doPost sends a single HTTP POST to the Loki push API. Returns
// (retryable, error). A nil error means success (2xx). Redirect
// rejections and 4xx (except 429) are non-retryable. 5xx, 429, and
// network errors are retryable.
func (o *Output) doPost(ctx context.Context, body []byte, compressed bool) (retryable bool, statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("audit: loki request: %w", err)
	}

	o.applyRequestHeaders(req, compressed)

	resp, err := o.client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectBlocked) {
			return false, 0, fmt.Errorf("audit: loki redirect blocked: %w", err)
		}
		if ctx.Err() != nil {
			return false, 0, fmt.Errorf("audit: loki cancelled: %w", ctx.Err())
		}
		return true, 0, fmt.Errorf("audit: loki request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, resp.StatusCode, nil // success
	}

	if resp.StatusCode == 429 {
		o.retryHint = parseRetryAfter(resp.Header.Get("Retry-After"))
		return true, 429, fmt.Errorf("audit: loki rate limited (429)")
	}

	if resp.StatusCode >= 500 {
		return true, resp.StatusCode, fmt.Errorf("audit: loki server error %d", resp.StatusCode)
	}

	// 4xx (not 429) — client error, not retryable.
	return false, resp.StatusCode, fmt.Errorf("audit: loki client error %d", resp.StatusCode)
}

// applyRequestHeaders sets all HTTP headers on the request. Consumer
// headers are applied first; library-managed headers override them
// (defence in depth — config validation already blocks restricted
// header names).
func (o *Output) applyRequestHeaders(req *http.Request, compressed bool) {
	// Consumer headers first.
	for k, v := range o.cfg.Headers {
		req.Header.Set(k, v)
	}

	// Library-managed headers override — these are non-negotiable.
	req.Header.Set("Content-Type", "application/json")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Auth — must never be overridable by consumer headers.
	if o.cfg.BasicAuth != nil {
		req.SetBasicAuth(o.cfg.BasicAuth.Username, o.cfg.BasicAuth.Password)
	} else if o.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+o.cfg.BearerToken)
	}

	if o.cfg.TenantID != "" {
		req.Header.Set("X-Scope-OrgID", o.cfg.TenantID)
	}
}

// recordSuccess records successful delivery metrics for a batch.
func (o *Output) recordSuccess(batchSize int, dur time.Duration) {
	if omp := o.outputMetrics.Load(); omp != nil {
		(*omp).RecordFlush(batchSize, dur)
	}
	if o.metrics != nil {
		name := o.Name()
		for range batchSize {
			o.metrics.RecordEvent(name, "success")
		}
	}
}

// recordDrop records dropped events in metrics.
func (o *Output) recordDrop(count int) {
	name := o.Name()
	for range count {
		if omp := o.outputMetrics.Load(); omp != nil {
			(*omp).RecordDrop()
		}
		if o.metrics != nil {
			o.metrics.RecordEvent(name, "error")
		}
	}
}

// recordRetry records a retry attempt in output metrics.
func (o *Output) recordRetry(attempt int) {
	if omp := o.outputMetrics.Load(); omp != nil {
		(*omp).RecordRetry(attempt)
	}
}

// recordError records a non-retryable error in output metrics.
func (o *Output) recordError() {
	if omp := o.outputMetrics.Load(); omp != nil {
		(*omp).RecordError()
	}
}

// parseRetryAfter parses a Retry-After header value (delta-seconds
// only). Returns 0 if absent, unparseable, or non-positive. The
// result is capped at maxRetryAfter to prevent server-controlled DoS.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs <= 0 {
		return 0
	}
	d := time.Duration(secs) * time.Second
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// lokiBackoff returns a jittered exponential backoff duration:
// 100ms * 2^attempt with [0.5, 1.0) jitter, capped at 5s.
//
// SYNC: identical to webhook/http.go (webhookBackoff, 5s cap).
// Similar to syslog/syslog.go (backoffDuration, 30s cap).
func lokiBackoff(attempt int) time.Duration {
	exp := float64(attempt)
	if exp > 20 {
		exp = 20
	}
	d := backoffBase * time.Duration(math.Pow(2, exp))
	if d > backoffMax {
		d = backoffMax
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0 // [0.5, 1.0)
		d = time.Duration(float64(d) * jitter)
	}
	return d
}
