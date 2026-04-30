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

package file_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/axonops/audit/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileOutput_LastDeliveryNanos_AdvancesOnFlush verifies the
// LastDeliveryReporter implementation timestamps the most recent
// successful disk flush (#753 AC #4).
func TestFileOutput_LastDeliveryNanos_AdvancesOnFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"never-flushed output must report 0")

	require.NoError(t, out.Write([]byte(`{"event_type":"first"}`+"\n")))

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > 0
	}, 5*time.Second, 5*time.Millisecond,
		"successful flush must advance the timestamp")
	first := out.LastDeliveryNanos()

	time.Sleep(2 * time.Millisecond)
	require.NoError(t, out.Write([]byte(`{"event_type":"second"}`+"\n")))

	require.Eventually(t, func() bool {
		return out.LastDeliveryNanos() > first
	}, 5*time.Second, 5*time.Millisecond,
		"successive flushes must monotonically advance the timestamp")
}

// TestFileOutput_LastDeliveryNanos_NeverDelivered verifies that an
// output that never wrote anything reports the zero sentinel
// (#753 AC #1 — zero-as-no-data semantics for never-delivered).
func TestFileOutput_LastDeliveryNanos_NeverDelivered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	out, err := file.New(&file.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, int64(0), out.LastDeliveryNanos(),
		"output with no writes must report the zero sentinel")
}
