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

	"github.com/axonops/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type flatStruct struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type structWithDash struct {
	Name    string `yaml:"name"`
	Ignored string `yaml:"-"`
	Port    int    `yaml:"port"`
}

type structWithOmitempty struct {
	Name string `yaml:"name,omitempty"`
	Port int    `yaml:"port"`
}

type structNoTags struct {
	Name string
	Port int
}

func TestWrapUnknownFieldError_AddsValidFields(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_SkipsDashTags(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, structWithDash{})
	assert.Contains(t, wrapped.Error(), "(valid: name, port)")
	assert.NotContains(t, wrapped.Error(), "Ignored")
}

func TestWrapUnknownFieldError_HandlesOmitempty(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, structWithOmitempty{})
	assert.Contains(t, wrapped.Error(), "(valid: name, port)")
}

func TestWrapUnknownFieldError_SortedAlphabetically(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	// address < name < port
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_AcceptsPointer(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, &flatStruct{})
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_NonUnknownFieldError_PassesThrough(t *testing.T) {
	err := errors.New("some other yaml error")
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Equal(t, err, wrapped)
}

func TestWrapUnknownFieldError_NilError_ReturnsNil(t *testing.T) {
	assert.Nil(t, audit.WrapUnknownFieldError(nil, flatStruct{}))
}

func TestWrapUnknownFieldError_NoTags_PassesThrough(t *testing.T) {
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, structNoTags{})
	// No yaml tags → no valid field list → error unchanged
	assert.Equal(t, err, wrapped)
}

func TestWrapUnknownFieldError_PreservesWrapping(t *testing.T) {
	inner := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(inner, flatStruct{})
	require.ErrorIs(t, wrapped, inner)
}
