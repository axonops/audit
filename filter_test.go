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

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTaxonomy returns a taxonomy for route testing with categories
// "write", "read", "security" and corresponding event types.
func testTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"write":    {"user_create", "user_delete"},
			"read":     {"user_get", "config_get"},
			"security": {"auth_failure", "permission_denied"},
		},
		Events: map[string]audit.EventDef{
			"user_create":       {Category: "write", Required: []string{"outcome"}},
			"user_delete":       {Category: "write", Required: []string{"outcome"}},
			"user_get":          {Category: "read", Required: []string{"outcome"}},
			"config_get":        {Category: "read", Required: []string{"outcome"}},
			"auth_failure":      {Category: "security", Required: []string{"outcome"}},
			"permission_denied": {Category: "security", Required: []string{"outcome"}},
		},
		DefaultEnabled: []string{"write", "read", "security"},
	}
}

func TestEventRoute_IsEmpty(t *testing.T) {
	assert.True(t, (&audit.EventRoute{}).IsEmpty())
	assert.False(t, (&audit.EventRoute{IncludeCategories: []string{"write"}}).IsEmpty())
	assert.False(t, (&audit.EventRoute{ExcludeEventTypes: []string{"auth_failure"}}).IsEmpty())
}

func TestValidateEventRoute(t *testing.T) {
	tax := testTaxonomy()

	tests := []struct {
		name    string
		wantErr string
		route   audit.EventRoute
	}{
		{
			name:  "empty route",
			route: audit.EventRoute{},
		},
		{
			name:  "valid include categories",
			route: audit.EventRoute{IncludeCategories: []string{"write", "security"}},
		},
		{
			name:  "valid include event types",
			route: audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
		},
		{
			name:  "valid exclude categories",
			route: audit.EventRoute{ExcludeCategories: []string{"read"}},
		},
		{
			name:  "valid exclude event types",
			route: audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
		},
		{
			name: "valid include categories and event types",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				IncludeEventTypes: []string{"auth_failure"},
			},
		},
		{
			name: "valid exclude categories and event types",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
		},
		{
			name: "mixed include and exclude categories",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				ExcludeCategories: []string{"read"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name: "mixed include categories and exclude event types",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				ExcludeEventTypes: []string{"auth_failure"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name: "mixed include event types and exclude categories",
			route: audit.EventRoute{
				IncludeEventTypes: []string{"user_create"},
				ExcludeCategories: []string{"read"},
			},
			wantErr: "either include or exclude, not both",
		},
		{
			name:    "unknown include category",
			route:   audit.EventRoute{IncludeCategories: []string{"nonexistent"}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown exclude category",
			route:   audit.EventRoute{ExcludeCategories: []string{"bogus"}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown include event type",
			route:   audit.EventRoute{IncludeEventTypes: []string{"fake_event"}},
			wantErr: "unknown taxonomy entries",
		},
		{
			name:    "unknown exclude event type",
			route:   audit.EventRoute{ExcludeEventTypes: []string{"fake_event"}},
			wantErr: "unknown taxonomy entries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := audit.ValidateEventRoute(&tt.route, &tax)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestMatchesRoute(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		category  string
		route     audit.EventRoute
		want      bool
	}{
		// Empty route — matches everything.
		{
			name:      "empty route matches all",
			route:     audit.EventRoute{},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		// Include mode — categories.
		{
			name:      "include category match",
			route:     audit.EventRoute{IncludeCategories: []string{"security"}},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name:      "include category no match",
			route:     audit.EventRoute{IncludeCategories: []string{"security"}},
			eventType: "user_create",
			category:  "write",
			want:      false,
		},
		// Include mode — event types.
		{
			name:      "include event type match",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name:      "include event type no match",
			route:     audit.EventRoute{IncludeEventTypes: []string{"auth_failure"}},
			eventType: "permission_denied",
			category:  "security",
			want:      false,
		},
		// Include mode — union of categories + event types.
		{
			name: "include union category match",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		{
			name: "include union event type match",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "auth_failure",
			category:  "security",
			want:      true,
		},
		{
			name: "include union no match",
			route: audit.EventRoute{
				IncludeCategories: []string{"write"},
				IncludeEventTypes: []string{"auth_failure"},
			},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		// Exclude mode — categories.
		{
			name:      "exclude category match skips",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			eventType: "user_get",
			category:  "read",
			want:      false,
		},
		{
			name:      "exclude category no match delivers",
			route:     audit.EventRoute{ExcludeCategories: []string{"read"}},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
		// Exclude mode — event types.
		{
			name:      "exclude event type match skips",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		{
			name:      "exclude event type no match delivers",
			route:     audit.EventRoute{ExcludeEventTypes: []string{"config_get"}},
			eventType: "user_get",
			category:  "read",
			want:      true,
		},
		// Exclude mode — union of categories + event types.
		{
			name: "exclude union category match skips",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "config_get",
			category:  "read",
			want:      false,
		},
		{
			name: "exclude union event type match skips",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "user_delete",
			category:  "write",
			want:      false,
		},
		{
			name: "exclude union no match delivers",
			route: audit.EventRoute{
				ExcludeCategories: []string{"read"},
				ExcludeEventTypes: []string{"user_delete"},
			},
			eventType: "user_create",
			category:  "write",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audit.MatchesRoute(&tt.route, tt.eventType, tt.category)
			assert.Equal(t, tt.want, got)
		})
	}
}
