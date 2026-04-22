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
	"time"

	"github.com/axonops/audit"
)

// ToIntForTest exposes toInt for black-box testing.
var ToIntForTest = toInt

// ToBoolForTest exposes toBool for black-box testing.
var ToBoolForTest = toBool

// ToStringForTest exposes toString for black-box testing.
var ToStringForTest = toString

// ToStringSliceForTest exposes toStringSlice for black-box testing.
var ToStringSliceForTest = toStringSlice

// DeepCopyValueForTest exposes deepCopyValue for black-box testing.
var DeepCopyValueForTest = deepCopyValue

// ExpandEnvStringForTest exposes expandEnvString for fuzzing via
// FuzzExpandEnvString (#481). Keeps the production surface clean
// while allowing the fuzz harness to run from the _test package.
var ExpandEnvStringForTest = expandEnvString

// NewResolverForTest exposes newResolver for tests that need to drive
// the resolver directly — used by [TestClearCaches_EmptiesBothMaps]
// to verify clearCaches() empties both maps (#479).
var NewResolverForTest = newResolver

// ResolverCacheSizesForTest returns the current (pathCache, refCache)
// lengths for a resolver built via [NewResolverForTest].
func ResolverCacheSizesForTest(r any) (pathLen, refLen int) {
	rr, ok := r.(*resolver)
	if !ok || rr == nil {
		return 0, 0
	}
	return len(rr.pathCache), len(rr.refCache)
}

// ResolverSeedCacheForTest seeds both caches with a single dummy
// entry so the clearCaches contract can be verified with non-empty
// starting state.
func ResolverSeedCacheForTest(r any) {
	rr, ok := r.(*resolver)
	if !ok || rr == nil {
		return
	}
	rr.pathCache["scheme://path"] = map[string]string{"key": "value"}
	rr.refCache["scheme://path#key"] = "value"
}

// ResolverClearCachesForTest exposes the unexported clearCaches
// method directly so tests exercise the contract in isolation from
// Load (#479).
func ResolverClearCachesForTest(r any) {
	rr, ok := r.(*resolver)
	if !ok {
		return
	}
	rr.clearCaches()
}

// LoadedConfigSnapshot is the test-only snapshot of the parsed
// `auditor:` YAML section values retained on [*Loaded]. Fields
// mirror the pre-#579 `audit.Config` shape so existing black-box
// tests need only a helper-call change to migrate.
type LoadedConfigSnapshot struct {
	ValidationMode  audit.ValidationMode
	ShutdownTimeout time.Duration
	QueueSize       int
	OmitEmpty       bool
	Disabled        bool
}

// LoadedConfigForTest exposes the parsed `auditor:` YAML values
// retained on [*Loaded] so black-box tests can verify parsing
// correctness without bloating the public API (#579 — the audit
// package no longer exposes a Config struct).
func LoadedConfigForTest(l *Loaded) LoadedConfigSnapshot {
	if l == nil {
		return LoadedConfigSnapshot{}
	}
	return LoadedConfigSnapshot{
		QueueSize:       l.auditorCfg.queueSize,
		ShutdownTimeout: l.auditorCfg.shutdownTimeout,
		ValidationMode:  l.auditorCfg.validationMode,
		OmitEmpty:       l.auditorCfg.omitEmpty,
		Disabled:        l.auditorCfg.disabled,
	}
}
