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

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// WrapUnknownFieldError checks if err is (or wraps) a
// [yaml.UnknownFieldError] from goccy/go-yaml's DisallowUnknownField
// option and, if so, appends a "(valid: ...)" suffix listing the
// sorted YAML field names from target. Returns err unchanged when
// the error is not an unknown-field error.
//
// Discrimination uses [errors.As] against the public type re-exported
// by github.com/goccy/go-yaml (v1.18.0+) — not string matching against
// upstream wording — so an upstream message rephrasing cannot cause
// silent regression.
//
// target must be a struct or pointer to struct. The function extracts
// YAML tag names via reflection — no manual field lists needed.
func WrapUnknownFieldError(err error, target any) error {
	if err == nil {
		return nil
	}
	var unknownField *yaml.UnknownFieldError
	if !errors.As(err, &unknownField) {
		return err
	}
	names := yamlFieldNames(target)
	if len(names) == 0 {
		return err
	}
	return fmt.Errorf("%w (valid: %s)", err, strings.Join(names, ", "))
}

// yamlFieldNames returns sorted YAML tag names from a struct's fields.
// It handles both struct values and pointers to structs. Fields with
// tag "-" or no yaml tag are skipped. Tag options after a comma (e.g.
// "name,omitempty") are stripped — only the field name is returned.
func yamlFieldNames(v any) []string {
	t := reflect.TypeOf(v)
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		// Strip options like ",omitempty"
		if idx := strings.IndexByte(tag, ','); idx != -1 {
			tag = tag[:idx]
		}
		if tag == "" {
			continue
		}
		names = append(names, tag)
	}
	sort.Strings(names)
	return names
}
