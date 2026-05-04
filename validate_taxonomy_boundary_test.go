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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

// TestValidateTaxonomy_NonNameErrorDoesNotWrapErrInvalidTaxonomyName
// proves that ValidateTaxonomy wraps ErrInvalidTaxonomyName ONLY when
// the validation produced at least one name-shape error. A taxonomy
// with no name violations but with another error (e.g. unsupported
// version, missing required field) must wrap ErrTaxonomyInvalid only,
// NOT ErrInvalidTaxonomyName. Pins the strict boundary at
// validate_taxonomy.go:61 (`if len(nameErrs) > 0`) so that flipping
// `>` to `>=` (which would always wrap ErrInvalidTaxonomyName) is
// caught.
//
// Without this assertion, callers that discriminate between name and
// non-name violations via errors.Is(err, ErrInvalidTaxonomyName) would
// receive a false-positive name error on every malformed taxonomy.
func TestValidateTaxonomy_NonNameErrorDoesNotWrapErrInvalidTaxonomyName(t *testing.T) {
	t.Parallel()

	// Unsupported version is a non-name error: checkTaxonomyVersion
	// produces an `errs` entry but no `nameErrs`. The pair below
	// asserts both that the non-name path fires AND that the name
	// path does NOT fire.
	tax := audit.Taxonomy{
		Version: 999,
		Categories: map[string]*audit.CategoryDef{
			"write": {Events: []string{"user_create"}},
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Categories: []string{"write"},
				Required:   []string{"outcome"},
			},
		},
	}
	err := audit.ValidateTaxonomy(tax)
	require.Error(t, err, "version=999 must be rejected")
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid,
		"non-name error must wrap ErrTaxonomyInvalid")
	assert.False(t, errors.Is(err, audit.ErrInvalidTaxonomyName),
		"non-name error must NOT wrap ErrInvalidTaxonomyName; got %v", err)

	// Paired case: a taxonomy whose ONLY violation is a name-shape
	// problem MUST wrap both ErrTaxonomyInvalid AND ErrInvalidTaxonomyName.
	// Without this assertion a future refactor could silently drop the
	// name-error wrap from the happy path of validate_taxonomy.go:65.
	taxNameErr := audit.Taxonomy{
		Version: 1,
		Categories: map[string]*audit.CategoryDef{
			"WRITE": {Events: []string{"user_create"}}, // uppercase → name-shape error
		},
		Events: map[string]*audit.EventDef{
			"user_create": {
				Categories: []string{"WRITE"},
				Required:   []string{"outcome"},
			},
		},
	}
	err = audit.ValidateTaxonomy(taxNameErr)
	require.Error(t, err, "uppercase category name must be rejected")
	assert.ErrorIs(t, err, audit.ErrTaxonomyInvalid,
		"name-shape error must wrap ErrTaxonomyInvalid")
	assert.ErrorIs(t, err, audit.ErrInvalidTaxonomyName,
		"name-shape error must wrap ErrInvalidTaxonomyName")
}
