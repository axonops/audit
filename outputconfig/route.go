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

package outputconfig

import (
	"fmt"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
)

type yamlRoute struct {
	// MinSeverity (YAML: min_severity) — minimum severity threshold.
	// Events with severity below this value are not delivered. Nil = no filter.
	MinSeverity *int `yaml:"min_severity"`
	// MaxSeverity (YAML: max_severity) — maximum severity threshold.
	// Events with severity above this value are not delivered. Nil = no filter.
	MaxSeverity       *int     `yaml:"max_severity"`
	IncludeCategories []string `yaml:"include_categories"`
	IncludeEventTypes []string `yaml:"include_event_types"`
	ExcludeCategories []string `yaml:"exclude_categories"`
	ExcludeEventTypes []string `yaml:"exclude_event_types"`
}

// outputFields holds parsed fields from a single output value.

func buildRoute(name string, raw any, taxonomy *audit.Taxonomy) (*audit.EventRoute, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil route = receive all events
	}
	// safeMarshal (not yaml.Marshal) — see safe_marshal.go (#487).
	routeBytes, err := safeMarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("output %q route: %w", name, err)
	}
	var yr yamlRoute
	if uErr := yaml.UnmarshalWithOptions(routeBytes, &yr, yaml.DisallowUnknownField()); uErr != nil {
		return nil, fmt.Errorf("output %q route: %w", name, audit.WrapUnknownFieldError(uErr, yr))
	}
	route := &audit.EventRoute{
		IncludeCategories: yr.IncludeCategories,
		IncludeEventTypes: yr.IncludeEventTypes,
		ExcludeCategories: yr.ExcludeCategories,
		ExcludeEventTypes: yr.ExcludeEventTypes,
		MinSeverity:       yr.MinSeverity,
		MaxSeverity:       yr.MaxSeverity,
	}
	if err := audit.ValidateEventRoute(route, taxonomy); err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	return route, nil
}

func buildOutputFormatter(name string, raw any) (audit.Formatter, error) {
	if raw == nil {
		return nil, nil //nolint:nilnil // nil = use auditor default
	}
	f, err := buildFormatter(raw)
	if err != nil {
		return nil, fmt.Errorf("output %q: %w", name, err)
	}
	return f, nil
}

// yamlHMACConfig is the intermediate YAML representation of the
