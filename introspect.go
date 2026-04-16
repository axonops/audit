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
// intake queue. Returns 0 for disabled or synchronous loggers.
func (l *Logger) QueueLen() int {
	if l.ch == nil {
		return 0
	}
	return len(l.ch)
}

// QueueCap returns the configured async intake queue capacity. Returns
// 0 for disabled or synchronous loggers.
func (l *Logger) QueueCap() int {
	if l.ch == nil {
		return 0
	}
	return cap(l.ch)
}

// OutputNames returns a sorted list of all configured output names.
// Safe for concurrent use. Returns nil for disabled loggers with no
// outputs.
func (l *Logger) OutputNames() []string {
	if len(l.entries) == 0 {
		return nil
	}
	names := make([]string, len(l.entries))
	for i, oe := range l.entries {
		names[i] = oe.output.Name()
	}
	slices.Sort(names)
	return names
}

// IsCategoryEnabled reports whether events in the named category
// would be delivered. This accounts for both category-level state
// and per-event overrides. Returns false for disabled loggers or
// unknown categories.
func (l *Logger) IsCategoryEnabled(category string) bool {
	if l.disabled || l.taxonomy == nil || l.filter == nil {
		return false
	}
	if _, ok := l.taxonomy.Categories[category]; !ok {
		return false
	}
	// Check category state via the filter's atomic map.
	if enabled, ok := l.filter.enabledCategories.Load(category); ok {
		return enabled
	}
	return true // default-enabled
}

// IsEventEnabled reports whether the named event type would be
// delivered. This accounts for category state, per-event overrides,
// and the global filter. Returns false for disabled loggers or
// unknown event types.
func (l *Logger) IsEventEnabled(eventType string) bool {
	if l.disabled || l.taxonomy == nil || l.filter == nil {
		return false
	}
	return l.filter.isEnabled(eventType, l.taxonomy)
}

// IsDisabled reports whether the logger is a no-op (created with
// [WithDisabled]).
func (l *Logger) IsDisabled() bool {
	return l.disabled
}

// IsSynchronous reports whether the logger delivers events inline
// within [Logger.AuditEvent] (created with [WithSynchronousDelivery]).
func (l *Logger) IsSynchronous() bool {
	return l.synchronous
}
