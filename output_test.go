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
	"strings"
	"testing"

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOutputName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "valid simple", input: "console"},
		{name: "valid with underscore", input: "audit_file"},
		{name: "valid with hyphen", input: "security-feed"},
		{name: "valid mixed", input: "myOutput-2"},
		{name: "valid uppercase", input: "ComplianceArchive"},
		{name: "valid single char", input: "a"},
		{name: "valid 128 bytes", input: strings.Repeat("a", 128)},

		{name: "empty", input: "", wantErr: "must not be empty"},
		{name: "too long", input: strings.Repeat("a", 129), wantErr: "exceeds maximum length"},
		{name: "underscore prefix", input: "_internal", wantErr: "must not start with underscore"},
		{name: "digit prefix", input: "1bad", wantErr: "must start with a letter"},
		{name: "contains colon", input: "webhook:host", wantErr: "invalid character"},
		{name: "contains slash", input: "file/path", wantErr: "invalid character"},
		{name: "contains space", input: "my output", wantErr: "invalid character"},
		{name: "contains dot", input: "my.output", wantErr: "invalid character"},
		{name: "contains newline", input: "bad\nname", wantErr: "invalid character"},
		{name: "contains tab", input: "bad\tname", wantErr: "invalid character"},
		{name: "contains equals", input: "key=value", wantErr: "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := audit.ValidateOutputName(tt.input)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.ErrorIs(t, err, audit.ErrConfigInvalid)
			}
		})
	}
}
