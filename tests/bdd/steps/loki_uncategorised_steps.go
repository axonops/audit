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

package steps

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// registerLokiUncategorisedSteps registers BDD steps for verifying
// uncategorised event behaviour in Loki.
func registerLokiUncategorisedSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	registerLokiUncategorisedThenSteps(ctx, tc)
}

func registerLokiUncategorisedThenSteps(ctx *godog.ScenarioContext, tc *AuditTestContext) {
	// Note: "querying Loki by label ... should return an event with:"
	// is registered in loki_steps.go. Do not duplicate here.

	ctx.Step(`^the loki event payload for the marker should not contain field "([^"]*)"$`,
		func(field string) error {
			marker := tc.Markers["default"]
			return assertLokiMarkerEventFieldAbsent(tc, marker, field)
		})

	ctx.Step(`^the loki server should contain the named marker "([^"]*)" within (\d+) seconds$`,
		func(name string, timeout int) error {
			markerVal := tc.Markers[name]
			if markerVal == "" {
				return fmt.Errorf("no marker with name %q", name)
			}
			return pollLokiForNamedMarker(tc, markerVal, timeout)
		})

	ctx.Step(`^querying Loki by label "([^"]*)" = "([^"]*)" should not return named marker "([^"]*)" within (\d+) seconds$`,
		func(label, value, name string, timeout int) error {
			markerVal := tc.Markers[name]
			if markerVal == "" {
				return fmt.Errorf("no marker with name %q", name)
			}
			return assertLokiLabelQueryExcludesMarker(tc, label, value, markerVal, timeout)
		})

	ctx.Step(`^querying Loki excluding event_category labels "([^"]*)" should return the named marker "([^"]*)" within (\d+) seconds$`,
		func(categories, name string, timeout int) error {
			markerVal := tc.Markers[name]
			if markerVal == "" {
				return fmt.Errorf("no marker with name %q", name)
			}
			return assertLokiNegationQueryReturnsMarker(tc, categories, markerVal, timeout)
		})

	ctx.Step(`^querying Loki excluding event_category labels "([^"]*)" should not return the named marker "([^"]*)" within (\d+) seconds$`,
		func(categories, name string, timeout int) error {
			markerVal := tc.Markers[name]
			if markerVal == "" {
				return fmt.Errorf("no marker with name %q", name)
			}
			return assertLokiNegationQueryExcludesMarker(tc, categories, markerVal, timeout)
		})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// assertLokiMarkerEventFieldAbsent queries Loki for the marker event
// and verifies the named field is absent from the JSON payload.
func assertLokiMarkerEventFieldAbsent(tc *AuditTestContext, markerVal, field string) error {
	raw, err := queryLokiForMarkerEvent(tc, markerVal)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse loki event: %w", err)
	}
	if _, ok := m[field]; ok {
		return fmt.Errorf("loki event contains field %q but should not (value: %v)", field, m[field])
	}
	return nil
}

// pollLokiForNamedMarker polls Loki for a specific marker value.
func pollLokiForNamedMarker(tc *AuditTestContext, markerVal string, timeoutSec int) error {
	logql := fmt.Sprintf(`{test_suite="bdd"} |= %q`, markerVal)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, stream := range result.Data.Result {
			for _, v := range stream.Values {
				if len(v) >= 2 && strings.Contains(v[1], markerVal) {
					return nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("named marker %q not found in Loki within %ds", markerVal, timeoutSec)
}

// assertLokiLabelQueryExcludesMarker verifies that a label query does
// NOT return events containing the marker. Waits the full timeout to
// be sure (events may still be ingesting).
func assertLokiLabelQueryExcludesMarker(tc *AuditTestContext, label, value, markerVal string, timeoutSec int) error {
	logql := fmt.Sprintf(`{test_suite="bdd",%s=%q} |= %q`, label, value, markerVal)
	time.Sleep(time.Duration(timeoutSec) * time.Second)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, stream := range result.Data.Result {
		for _, v := range stream.Values {
			if len(v) >= 2 && strings.Contains(v[1], markerVal) {
				return fmt.Errorf("marker %q found in {%s=%q} query but should not be", markerVal, label, value)
			}
		}
	}
	return nil
}

// assertLokiNegationQueryReturnsMarker queries Loki with negated
// event_category labels and verifies the marker IS found.
func assertLokiNegationQueryReturnsMarker(tc *AuditTestContext, categories, markerVal string, timeoutSec int) error {
	logql := buildNegationQuery(categories, markerVal)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, stream := range result.Data.Result {
			for _, v := range stream.Values {
				if len(v) >= 2 && strings.Contains(v[1], markerVal) {
					return nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("marker %q not found in negation query within %ds", markerVal, timeoutSec)
}

// assertLokiNegationQueryExcludesMarker queries Loki with negated
// event_category labels and verifies the marker is NOT found.
func assertLokiNegationQueryExcludesMarker(tc *AuditTestContext, categories, markerVal string, timeoutSec int) error {
	logql := buildNegationQuery(categories, markerVal)
	time.Sleep(time.Duration(timeoutSec) * time.Second)
	result, err := queryLokiBDD(tc, logql, defaultLokiTenant)
	if err != nil {
		return err
	}
	for _, stream := range result.Data.Result {
		for _, v := range stream.Values {
			if len(v) >= 2 && strings.Contains(v[1], markerVal) {
				return fmt.Errorf("marker %q found in negation query but should not be", markerVal)
			}
		}
	}
	return nil
}

// buildNegationQuery constructs a LogQL query that excludes all
// named categories. E.g., for "write,security":
// {test_suite="bdd",event_category!="write",event_category!="security"} |= "marker".
func buildNegationQuery(categories, markerVal string) string {
	cats := strings.Split(categories, ",")
	var negations []string
	for _, cat := range cats {
		cat = strings.TrimSpace(cat)
		if cat != "" {
			negations = append(negations, fmt.Sprintf(`event_category!=%q`, cat))
		}
	}
	return fmt.Sprintf(`{test_suite="bdd",%s} |= %q`, strings.Join(negations, ","), markerVal)
}
