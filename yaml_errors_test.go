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
	"bytes"
	"errors"
	"testing"

	"github.com/axonops/audit"
	"github.com/goccy/go-yaml"
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

// realUnknownFieldError triggers a genuine *yaml.UnknownFieldError from
// goccy/go-yaml's DisallowUnknownField option. Returning the same typed
// error a consumer would observe in production keeps these tests honest:
// they exercise WrapUnknownFieldError's typed-As discrimination, not a
// fabricated string-shaped substitute.
func realUnknownFieldError(t *testing.T) error {
	t.Helper()
	var dst flatStruct
	dec := yaml.NewDecoder(bytes.NewReader([]byte("typo: 1\n")), yaml.DisallowUnknownField())
	err := dec.Decode(&dst)
	require.Error(t, err)
	var unknownField *yaml.UnknownFieldError
	require.True(t, errors.As(err, &unknownField), "decoder did not produce *yaml.UnknownFieldError")
	return err
}

func TestWrapUnknownFieldError_AddsValidFields(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_SkipsDashTags(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, structWithDash{})
	assert.Contains(t, wrapped.Error(), "(valid: name, port)")
	assert.NotContains(t, wrapped.Error(), "Ignored")
}

func TestWrapUnknownFieldError_HandlesOmitempty(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, structWithOmitempty{})
	assert.Contains(t, wrapped.Error(), "(valid: name, port)")
}

func TestWrapUnknownFieldError_SortedAlphabetically(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_AcceptsPointer(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, &flatStruct{})
	assert.Contains(t, wrapped.Error(), "(valid: address, name, port)")
}

func TestWrapUnknownFieldError_NonUnknownFieldError_PassesThrough(t *testing.T) {
	t.Parallel()
	err := errors.New("some other yaml error")
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Equal(t, err, wrapped)
}

func TestWrapUnknownFieldError_NilError_ReturnsNil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, audit.WrapUnknownFieldError(nil, flatStruct{}))
}

func TestWrapUnknownFieldError_NoTags_PassesThrough(t *testing.T) {
	t.Parallel()
	err := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(err, structNoTags{})
	// No yaml tags → no valid field list → error unchanged
	assert.Equal(t, err, wrapped)
}

func TestWrapUnknownFieldError_PreservesWrapping(t *testing.T) {
	t.Parallel()
	inner := realUnknownFieldError(t)
	wrapped := audit.WrapUnknownFieldError(inner, flatStruct{})
	require.ErrorIs(t, wrapped, inner)
}

// TestWrapUnknownFieldError_TypedAsAfterWrap pins the public-API contract
// that goccy/go-yaml exposes *yaml.UnknownFieldError and that wrapping
// preserves typed-As discrimination through fmt.Errorf("%w ..."). If a
// future minor bump of goccy/go-yaml renames or unexports the type, this
// test fails immediately rather than silently regressing detection.
func TestWrapUnknownFieldError_TypedAsAfterWrap(t *testing.T) {
	t.Parallel()
	wrapped := audit.WrapUnknownFieldError(realUnknownFieldError(t), flatStruct{})
	var target *yaml.UnknownFieldError
	require.True(t, errors.As(wrapped, &target),
		"errors.As(wrapped, *yaml.UnknownFieldError) must succeed after WrapUnknownFieldError")
}

// TestWrapUnknownFieldError_StringMatchNotEnough verifies that an error
// whose message merely contains the substring "unknown field" but is NOT
// a *yaml.UnknownFieldError is left untouched. This pins the upgrade
// from string-matching (#541) — false positives that would have wrapped
// under the old implementation must now pass through.
func TestWrapUnknownFieldError_StringMatchNotEnough(t *testing.T) {
	t.Parallel()
	err := errors.New(`[1:1] unknown field "typo"`)
	wrapped := audit.WrapUnknownFieldError(err, flatStruct{})
	assert.Equal(t, err, wrapped, "string-matching false positive must not be wrapped after typed-As migration")
}
