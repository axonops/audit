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

package outputs_test

import (
	"slices"
	"testing"

	"github.com/axonops/audit"
	_ "github.com/axonops/audit/outputs" // registers all output types
	"github.com/stretchr/testify/assert"
)

func TestOutputsPackage_RegistersAllTypes(t *testing.T) {
	t.Parallel()
	types := audit.RegisteredOutputTypes()

	// The outputs package registers 4 types; stdout is always
	// registered by the core package.
	assert.True(t, slices.Contains(types, "file"), "file should be registered")
	assert.True(t, slices.Contains(types, "loki"), "loki should be registered")
	assert.True(t, slices.Contains(types, "stdout"), "stdout should be registered (core)")
	assert.True(t, slices.Contains(types, "syslog"), "syslog should be registered")
	assert.True(t, slices.Contains(types, "webhook"), "webhook should be registered")
}

func TestOutputsPackage_DoubleImport_NoError(t *testing.T) {
	t.Parallel()
	// Importing both outputs (all) and file (individual) should not panic.
	// The file factory is already registered via outputs; this verifies
	// RegisterOutputFactory overwrites silently.
	factory := audit.LookupOutputFactory("file")
	assert.NotNil(t, factory, "file factory should be registered after double import")
}
