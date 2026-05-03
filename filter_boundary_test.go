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

package audit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/internal/testhelper"
)

// TestValidateEventRoute_SeverityBoundaries pins the strict comparisons
// in validateSeverityRange (filter.go:120 and filter.go:124) so that
// flipping `<` to `<=` or `>` to `>=` is caught.
//
// The validator accepts severities in [MinSeverity, MaxSeverity] —
// that's 0..10 inclusive on BOTH ends. Each at-boundary case (0, 10)
// must be accepted and each just-past-boundary case (-1, 11) must be
// rejected. Without the paired-boundary assertions, off-by-one
// mutations of the range checks slip through.
func TestValidateEventRoute_SeverityBoundaries(t *testing.T) {
	t.Parallel()
	tax := testhelper.TestTaxonomy()

	cases := []struct {
		min     *int
		max     *int
		name    string
		wantErr bool
	}{
		// MinSeverity at-boundary: 0 and 10 must be accepted.
		{intPtr(0), nil, "min_at_zero_accepted", false},
		{intPtr(10), nil, "min_at_max_accepted", false},
		// MinSeverity just-past-boundary: -1 and 11 rejected.
		{intPtr(-1), nil, "min_below_zero_rejected", true},
		{intPtr(11), nil, "min_above_max_rejected", true},
		// MaxSeverity at-boundary: 0 and 10 accepted (paired-zero with
		// MinSeverity to keep min ≤ max invariant).
		{intPtr(0), intPtr(0), "max_at_zero_accepted", false},
		{nil, intPtr(10), "max_at_max_accepted", false},
		// MaxSeverity just-past-boundary: -1 and 11 rejected.
		{nil, intPtr(-1), "max_below_zero_rejected", true},
		{nil, intPtr(11), "max_above_max_rejected", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			route := audit.EventRoute{MinSeverity: tc.min, MaxSeverity: tc.max}
			err := audit.ValidateEventRoute(&route, tax)
			if tc.wantErr {
				require.Error(t, err,
					"validateSeverityRange must reject this case (subtest name pins which)")
			} else {
				assert.NoError(t, err,
					"validateSeverityRange must accept this case (subtest name pins which)")
			}
		})
	}
}
