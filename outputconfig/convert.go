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
	"fmt"
	"strconv"
)

func toBool(v any) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case string:
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			return false, fmt.Errorf("invalid boolean %q: %w", val, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("expected boolean, got %T", v)
	}
}

// toInt converts a YAML-decoded value to int. Handles int, uint64,
// float64 (YAML numbers), and string representations (from env var
// expansion).
func toInt(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case uint64:
		return int(val), nil //nolint:gosec // config values are small integers, no overflow risk
	case float64:
		iv := int(val)
		if float64(iv) != val {
			return 0, fmt.Errorf("expected integer, got fractional number %v", val)
		}
		return iv, nil
	case string:
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("invalid integer %q: %w", val, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", v)
	}
}

// toString converts a YAML-decoded value to string. Handles string
// values directly and converts numeric/bool types via fmt.Sprintf.
func toString(v any) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case nil:
		return "", nil
	default:
		return fmt.Sprintf("%v", val), nil
	}
}

// toStringSlice converts a YAML-decoded value to []string. Handles
// []any containing string elements.
func toStringSlice(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected sequence, got %T", v)
	}
	result := make([]string, 0, len(arr))
	for i, elem := range arr {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("element [%d]: expected string, got %T", i, elem)
		}
		result = append(result, s)
	}
	return result, nil
}
