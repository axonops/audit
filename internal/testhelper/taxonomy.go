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
		Categories: map[string][]string{
			"read":     {"schema_read", "config_read"},
			"write":    {"schema_register", "schema_delete"},
			"security": {"auth_failure"},
		},
		Events: map[string]*audit.EventDef{
			"schema_read":     {Category: "read", Required: []string{"outcome"}, Optional: []string{"subject"}},
			"config_read":     {Category: "read", Required: []string{"outcome"}},
			"schema_register": {Category: "write", Required: []string{"outcome", "actor_id", "subject"}, Optional: []string{"schema_type"}},
			"schema_delete":   {Category: "write", Required: []string{"outcome", "actor_id", "subject"}},
			"auth_failure":    {Category: "security", Required: []string{"outcome", "actor_id"}, Optional: []string{"reason"}},
		},
		DefaultEnabled: []string{"write", "security"},
	}
}

// TestTaxonomy returns a taxonomy with user_create, user_delete, and
// other common event types for routing and filter tests.
func TestTaxonomy() audit.Taxonomy {
	return audit.Taxonomy{
		Version: 1,
		Categories: map[string][]string{
			"write":    {"user_create", "user_delete"},
			"read":     {"user_get", "config_get"},
			"security": {"auth_failure", "permission_denied"},
		},
		Events: map[string]*audit.EventDef{
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
