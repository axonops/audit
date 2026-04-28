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

package audit

import "slices"

// QueueLen returns the number of events currently queued in the async
// intake queue. Returns 0 for disabled or synchronous auditors. Safe
// for concurrent use.
func (a *Auditor) QueueLen() int {
	if a.ch == nil {
		return 0
	}
	return len(a.ch)
}

// QueueCap returns the configured async intake queue capacity. Returns
// 0 for disabled or synchronous auditors. Safe for concurrent use.
func (a *Auditor) QueueCap() int {
	if a.ch == nil {
		return 0
	}
	return cap(a.ch)
}

// OutputNames returns a sorted list of all configured output names.
// Safe for concurrent use. Returns nil for disabled auditors with no
// outputs.
func (a *Auditor) OutputNames() []string {
	if len(a.entries) == 0 {
		return nil
	}
	names := make([]string, len(a.entries))
	for i, oe := range a.entries {
		names[i] = oe.output.Name()
	}
	slices.Sort(names)
	return names
}

// IsCategoryEnabled reports whether events in the named category
// would be delivered. This accounts for both category-level state
// and per-event overrides. Returns false for disabled auditors or
// unknown categories.
func (a *Auditor) IsCategoryEnabled(category string) bool {
	if a.disabled || a.taxonomy == nil || a.filter == nil {
		return false
	}
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return false
	}
	// Check category state via the filter's atomic map.
	if enabled, ok := a.filter.enabledCategories.Load(category); ok {
		return enabled
	}
	return true // default-enabled
}

// IsEventEnabled reports whether the named event type would be
// delivered. This accounts for category state, per-event overrides,
// and the global filter. Returns false for disabled auditors or
// unknown event types.
func (a *Auditor) IsEventEnabled(eventType string) bool {
	if a.disabled || a.taxonomy == nil || a.filter == nil {
		return false
	}
	return a.filter.isEnabled(eventType, a.taxonomy)
}

// IsDisabled reports whether the auditor is a no-op (created with
// [WithDisabled]). Safe for concurrent use.
func (a *Auditor) IsDisabled() bool {
	return a.disabled
}

// IsSynchronous reports whether the auditor delivers events inline
// within [Auditor.AuditEvent] (created with [WithSynchronousDelivery]).
// Safe for concurrent use.
func (a *Auditor) IsSynchronous() bool {
	return a.synchronous
}
