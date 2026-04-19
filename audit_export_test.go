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

// This file exports unexported functions for black-box testing.
package audit

import (
	"bytes"
	"errors"
	"time"
)

// Keep "bytes" and "errors" imports non-stale for future helpers.
var (
	_ = bytes.NewBuffer
	_ = errors.New
)

// MaxPooledBufCapForTest exports the [maxPooledBufCap] constant for
// test assertions. See putJSONBuf in format_json.go (#497 W2).
const MaxPooledBufCapForTest = maxPooledBufCap

// PutJSONBufClearsContents fills a fresh buffer with non-zero bytes
// at the given capacity, calls putJSONBuf, and returns whether all
// bytes [0:cap] were zeroed by the defensive clear-on-Put. Used to
// verify the security-defence-in-depth zeroing without relying on
// sync.Pool reuse observation (which is fundamentally flaky).
//
// Returns true when the buffer contents were zeroed (accepted path);
// false when the buffer was rejected by the cap check (contents
// untouched, sentinel bytes survive).
func PutJSONBufClearsContents(capBytes int) bool {
	buf := new(bytes.Buffer)
	buf.Grow(capBytes)
	for i := 0; i < capBytes; i++ {
		buf.WriteByte(0xA5)
	}
	full := buf.Bytes()[:cap(buf.Bytes())]

	putJSONBuf(buf)

	for _, b := range full {
		if b != 0 {
			return false
		}
	}
	return true
}

// IsEnabledForTest checks whether the given event type is enabled in
// the auditor's current filter state. Lock-free, matching the
// production Audit() hot path.
func IsEnabledForTest(a *Auditor, eventType string) bool {
	if a.disabled || a.filter == nil || a.taxonomy == nil {
		return false
	}
	return a.filter.isEnabled(eventType, a.taxonomy)
}

// FormatCacheSizeForTest exposes the array capacity constant.
const FormatCacheSizeForTest = formatCacheSize

// FormatCacheForTest wraps formatCache with exported methods for
// black-box testing.
type FormatCacheForTest struct {
	C formatCache
}

// Get delegates to the unexported formatCache.get.
func (w *FormatCacheForTest) Get(f Formatter) ([]byte, bool) {
	return w.C.get(f)
}

// Put delegates to the unexported formatCache.put. The owned buffer
// is always nil for test puts: tests construct cache entries from raw
// []byte values, never from buffered-formatter leases.
func (w *FormatCacheForTest) Put(f Formatter, data []byte) {
	w.C.put(f, data, nil)
}

// DropLimiterForTest wraps dropLimiter for testing.
type DropLimiterForTest struct {
	D dropLimiter
}

// Record delegates to the unexported dropLimiter.record.
func (w *DropLimiterForTest) Record(interval time.Duration, warnFn func(dropped int64)) {
	w.D.record(interval, warnFn)
}

// PendingCount returns the number of drops accumulated since the
// last emitted warning. Used by conservation tests (#492) to prove
// total drops across all windows equals total records.
func (w *DropLimiterForTest) PendingCount() int64 {
	return w.D.count.Load()
}
