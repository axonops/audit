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

import "fmt"

const (
	// currentConfigVersion is the latest config schema version
	// supported by this library.
	currentConfigVersion = 1

	// minSupportedConfigVersion is the oldest config schema version
	// the library can migrate from.
	minSupportedConfigVersion = 1
)

// migrateConfig applies backwards-compatible migrations to older config
// versions. Called after [validateConfig] (which calls [Config.applyDefaults]),
// so version is always >= 1. The range check is scaffolding for when
// version 2 is introduced. For v0.x only version 1 exists.
func migrateConfig(c *Config) error {
	if c.version > currentConfigVersion {
		return fmt.Errorf("%w: config version %d is not supported by this library version (max: %d), upgrade the library",
			ErrConfigInvalid, c.version, currentConfigVersion)
	}
	// Version 1 → current: no migration needed.
	return nil
}

// MigrateTaxonomy applies backwards-compatible migrations to older
// taxonomy versions. It returns an error wrapping [ErrTaxonomyInvalid]
// if the version is unsupported.
//
// This function is called automatically by [WithTaxonomy]; it is
// exported so that [ParseTaxonomyYAML] and other callers can apply
// migration before calling [ValidateTaxonomy]. For v0.1.0 only
// version 1 exists, so this is scaffolding.
func MigrateTaxonomy(t *Taxonomy) error {
	if t.Version == 0 {
		return fmt.Errorf("%w: taxonomy version is required: set version to 1", ErrTaxonomyInvalid)
	}
	if t.Version > currentTaxonomyVersion {
		return fmt.Errorf("%w: taxonomy version %d is not supported by this library version (max: %d), upgrade the library",
			ErrTaxonomyInvalid, t.Version, currentTaxonomyVersion)
	}
	if t.Version < minSupportedTaxonomyVersion {
		return fmt.Errorf("%w: taxonomy version %d is no longer supported, minimum supported is %d",
			ErrTaxonomyInvalid, t.Version, minSupportedTaxonomyVersion)
	}
	// Version 1 → current: no migration needed.
	return nil
}
