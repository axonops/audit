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

// Tests for the stdout OutputFactory exposed by audit.StdoutFactory().
//
// Prior to #578 the factory was auto-registered via an init() in the
// core package. That was dropped to eliminate hidden global mutation
// at import time. These tests exercise the factory directly via
// audit.StdoutFactory(); callers who want the YAML `type: stdout`
// form either blank-import github.com/axonops/audit/outputs (which
// registers it for them) or call audit.RegisterOutputFactory("stdout",
// audit.StdoutFactory()) explicitly.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
)

func TestStdoutFactory_NewReturnsWorkingOutput(t *testing.T) {
	t.Parallel()
	factory := audit.StdoutFactory()
	require.NotNil(t, factory, "audit.StdoutFactory() must return a non-nil factory")

	out, err := factory("my_stdout", nil, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	assert.Equal(t, "my_stdout", out.Name())
	assert.NoError(t, out.Write([]byte("test\n")))
}

func TestStdoutFactory_AcceptsNoConfig(t *testing.T) {
	t.Parallel()
	factory := audit.StdoutFactory()

	// nil config — accepted (the normal case)
	out, err := factory("no_config", nil, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// empty byte slice — also accepted
	out2, err := factory("empty_config", []byte{}, nil, nil, audit.FrameworkContext{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out2.Close() })
}

func TestStdoutFactory_RejectsConfig(t *testing.T) {
	t.Parallel()
	factory := audit.StdoutFactory()

	_, err := factory("bad_stdout", []byte("some_option: true\n"), nil, nil, audit.FrameworkContext{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not accept configuration")
	assert.Contains(t, err.Error(), "bad_stdout")
}

// TestOutputsConvenienceRegistersStdout documents that blank-importing
// github.com/axonops/audit/outputs registers the stdout factory (matching
// the pre-#578 behaviour of the core init()). This test lives in the
// outputs convenience package itself; referenced here for discoverability.
