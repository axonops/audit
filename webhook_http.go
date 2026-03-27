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
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"
)

// doPostWithRetry attempts HTTP POST with exponential backoff retry.
func (w *WebhookOutput) doPostWithRetry(ctx context.Context, batch [][]byte) {
	start := time.Now()
	body := buildNDJSON(batch)

	for attempt := range w.maxRetries {
		if attempt > 0 {
			backoff := webhookBackoff(attempt)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				w.recordDrop(len(batch))
				return
			}
		}

		retryable, err := w.doPost(ctx, body)
		if err == nil {
			w.recordSuccess(len(batch), time.Since(start))
			return
		}

		if !retryable {
			slog.Error("audit: webhook non-retryable error",
				"error", err,
				"batch_size", len(batch))
			w.recordDrop(len(batch))
			return
		}

		slog.Warn("audit: webhook retryable error",
			"attempt", attempt+1,
			"max_retries", w.maxRetries,
			"error", err)
	}

	// All retries exhausted.
	slog.Error("audit: webhook retries exhausted, dropping batch",
		"batch_size", len(batch),
		"max_retries", w.maxRetries)
	w.recordDrop(len(batch))
}

// doPost sends a single HTTP POST. Returns (retryable, error).
// nil error means success (2xx). Redirect rejections and 4xx are
// non-retryable. 5xx, 429, and network errors are retryable.
func (w *WebhookOutput) doPost(ctx context.Context, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("audit: webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		// Redirect rejection is non-retryable.
		if errors.Is(err, errRedirectBlocked) {
			return false, fmt.Errorf("audit: webhook redirect blocked: %w", err)
		}
		// Context cancellation is non-retryable.
		if ctx.Err() != nil {
			return false, fmt.Errorf("audit: webhook cancelled: %w", err)
		}
		// Network errors are retryable.
		return true, fmt.Errorf("audit: webhook request failed: %w", err)
	}
	defer func() {
		// Always consume response body to prevent connection leaks.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil // success
	}

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return true, fmt.Errorf("audit: webhook server error %d", resp.StatusCode)
	}

	// 4xx (not 429) — client error, not retryable.
	return false, fmt.Errorf("audit: webhook client error %d", resp.StatusCode)
}

// recordSuccess records successful delivery metrics for a batch.
func (w *WebhookOutput) recordSuccess(batchSize int, dur time.Duration) {
	if w.webhookMetrics == nil && w.metrics == nil {
		return
	}
	if w.webhookMetrics != nil {
		w.webhookMetrics.RecordWebhookFlush(batchSize, dur)
	}
	if w.metrics != nil {
		name := w.Name()
		for range batchSize {
			w.metrics.RecordEvent(name, "success")
		}
	}
}

// recordDrop records dropped events in metrics. [WebhookMetrics.RecordWebhookDrop]
// and RecordEvent(name, "error") are called per dropped event.
func (w *WebhookOutput) recordDrop(count int) {
	if w.webhookMetrics == nil && w.metrics == nil {
		return
	}
	name := w.Name()
	for range count {
		if w.webhookMetrics != nil {
			w.webhookMetrics.RecordWebhookDrop()
		}
		if w.metrics != nil {
			w.metrics.RecordEvent(name, "error")
		}
	}
}

// buildNDJSON concatenates event bytes as newline-delimited JSON.
// Events from the formatter already have a trailing newline.
func buildNDJSON(events [][]byte) []byte {
	var n int
	for _, e := range events {
		n += len(e)
		if len(e) == 0 || e[len(e)-1] != '\n' {
			n++ // need to add newline
		}
	}
	buf := make([]byte, 0, n)
	for _, e := range events {
		buf = append(buf, e...)
		if len(e) == 0 || e[len(e)-1] != '\n' {
			buf = append(buf, '\n')
		}
	}
	return buf
}

// webhookBackoff returns a jittered exponential backoff duration
// for webhook retry: 100ms × 2^attempt with [0.5, 1.0) jitter,
// capped at 5s.
func webhookBackoff(attempt int) time.Duration {
	const (
		base    = 100 * time.Millisecond
		maxBack = 5 * time.Second
	)
	exp := float64(attempt)
	if exp > 20 {
		exp = 20
	}
	d := base * time.Duration(math.Pow(2, exp))
	if d > maxBack {
		d = maxBack
	}
	var b [1]byte
	if _, err := rand.Read(b[:]); err == nil {
		jitter := 0.5 + float64(b[0])/512.0
		d = time.Duration(float64(d) * jitter)
	}
	return d
}
