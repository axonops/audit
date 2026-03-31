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

package testhelper

import "github.com/axonops/go-audit"

// ValidTaxonomy returns a taxonomy suitable for general testing with
// read, write, and security categories.
func ValidTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"read":     {Events: []string{"schema_read", "config_read"}},
			"write":    {Events: []string{"schema_register", "schema_delete"}},
			"security": {Events: []string{"auth_failure"}},
		},
		Events: map[string]*audit.EventDef{
			"schema_read":     {Required: []string{"outcome"}, Optional: []string{"subject"}},
			"config_read":     {Required: []string{"outcome"}},
			"schema_register": {Required: []string{"outcome", "actor_id", "subject"}, Optional: []string{"schema_type"}},
			"schema_delete":   {Required: []string{"outcome", "actor_id", "subject"}},
			"auth_failure":    {Required: []string{"outcome", "actor_id"}, Optional: []string{"reason"}},
		},
		DefaultEnabled: []string{"write", "security"},
	}
}

// TestTaxonomy returns a taxonomy with user_create, user_delete, and
// other common event types for routing and filter tests.
func TestTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"write":    {Events: []string{"user_create", "user_delete"}},
			"read":     {Events: []string{"user_get", "config_get"}},
			"security": {Events: []string{"auth_failure", "permission_denied"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create":       {Required: []string{"outcome"}},
			"user_delete":       {Required: []string{"outcome"}},
			"user_get":          {Required: []string{"outcome"}},
			"config_get":        {Required: []string{"outcome"}},
			"auth_failure":      {Required: []string{"outcome"}},
			"permission_denied": {Required: []string{"outcome"}},
		},
		DefaultEnabled: []string{"write", "read", "security"},
	}
}
