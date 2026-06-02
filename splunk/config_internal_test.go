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

package splunk

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateCloudStack exercises the unexported regex gate that
// guards splunkcloud://<stack> URL expansion against host smuggling.
// Lives in the splunk package (white-box) because validateCloudStack
// is unexported.
func TestValidateCloudStack(t *testing.T) {
	tests := []struct {
		name    string
		stack   string
		wantErr bool
	}{
		{"acme-prod", "acme-prod", false},
		{"single char", "a", false},
		{"63 chars", strings.Repeat("a", 63), false},
		{"empty rejected", "", true},
		{"64 chars rejected", strings.Repeat("a", 64), true},
		{"with dot rejected", "acme.evil.com", true},
		{"with at sign rejected", "acme@evil", true},
		{"with slash rejected", "acme/path", true},
		{"with colon rejected", "acme:1234", true},
		{"with space rejected", "acme prod", true},
		{"with hash rejected", "acme#1", true},
		{"with backslash rejected", "acme\\bad", true},
		{"with newline rejected", "acme\n", true},
		{"with cyrillic homograph rejected", "аcme-prod", true}, // Cyrillic 'а'
		{"starting with hyphen rejected", "-acme", true},
		{"uppercase rejected", "ACME", true},
		{"plus sign rejected", "acme+prod", true},
		{"all digits accepted", "123", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCloudStack(tc.stack)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrConfigInvalid)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
