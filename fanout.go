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

import "sync"

// Event flow through the fan-out engine:
//
//	Audit() → validate → global filter → enqueue
//	  → drainLoop → for each output:
//	    → per-output route filter (matchesRoute)
//	    → serialise once per unique formatter
//	    → deliver to output
//
// Events that pass the global category/event filter are delivered to
// each output whose EventRoute matches. Serialisation is cached per
// Formatter pointer: if three outputs share the same formatter, the
// event is serialised once and the same []byte is delivered to all
// three. Output failures are isolated — one output returning an error
// does not block delivery to others.

// outputEntry bundles an [Output] with its per-output [EventRoute] and
// optional [Formatter] override. The route may be changed at runtime
// via [Logger.SetOutputRoute]; the mutex protects concurrent access.
type outputEntry struct {
	output    Output
	formatter Formatter // nil = use logger's default formatter
	route     EventRoute
	mu        sync.RWMutex
}

// matchesEvent reports whether the event should be delivered to this
// output based on its current route.
func (oe *outputEntry) matchesEvent(eventType, category string) bool {
	oe.mu.RLock()
	route := oe.route
	oe.mu.RUnlock()
	return MatchesRoute(&route, eventType, category)
}

// effectiveFormatter returns the per-output formatter if set, or the
// provided default.
func (oe *outputEntry) effectiveFormatter(defaultFmt Formatter) Formatter {
	if oe.formatter != nil {
		return oe.formatter
	}
	return defaultFmt
}

// setRoute replaces the output's event route under a write lock.
func (oe *outputEntry) setRoute(route EventRoute) {
	oe.mu.Lock()
	oe.route = route
	oe.mu.Unlock()
}

// getRoute returns a copy of the output's current event route.
func (oe *outputEntry) getRoute() EventRoute {
	oe.mu.RLock()
	defer oe.mu.RUnlock()
	return oe.route
}
