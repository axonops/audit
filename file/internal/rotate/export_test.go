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

package rotate

// SetTestOnFlush registers a test-only callback fired after every
// successful background bufio.Flush from tickFlush. Pass nil to
// clear the hook. Tests typically pair this with t.Cleanup to
// ensure the hook is cleared even if the test fails mid-flow.
//
// Replaces the polling test pattern (read-file-and-sleep) that
// flaked under CI runner load (#705 family). The canonical usage:
//
//	flushed := make(chan struct{}, 8)
//	w.SetTestOnFlush(func() {
//	    select {
//	    case flushed <- struct{}{}:
//	    default: // never block production
//	    }
//	})
//	t.Cleanup(func() { w.SetTestOnFlush(nil) })
//
// Concurrency: the hook is invoked from the flushLoop goroutine
// outside the writer mutex. Callbacks MUST return promptly and
// MUST NOT block on a full channel. Use a buffered channel and
// non-blocking send.
func (w *Writer) SetTestOnFlush(fn func()) {
	if fn == nil {
		w.testOnFlush.Store(nil)
		return
	}
	w.testOnFlush.Store(&fn)
}
