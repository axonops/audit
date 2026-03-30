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
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// validVarName matches POSIX portable environment variable names.
var validVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// expandEnvInNode walks a parsed YAML tree and expands ${VAR} and
// ${VAR:-default} patterns in string scalar values.
//
// Security: expansion happens AFTER YAML parsing (not on raw bytes)
// to prevent YAML injection via env var values containing YAML syntax.
// Only string-typed leaf values are expanded — map keys are never
// modified. A visited set prevents double-expansion of YAML alias
// targets that are shared between multiple references.
//
// Unset variables without a default cause an error naming the variable
// (but NOT its expected value). No recursive expansion — a single pass.
func expandEnvInNode(node *yaml.Node, fieldPath string) error {
	return expandEnvInNodeVisited(node, fieldPath, make(map[*yaml.Node]bool))
}

func expandEnvInNodeVisited(node *yaml.Node, fieldPath string, visited map[*yaml.Node]bool) error { //nolint:gocognit,gocyclo,cyclop // tree walking is inherently complex
	if node == nil || visited[node] {
		return nil
	}
	visited[node] = true

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := expandEnvInNodeVisited(child, fieldPath, visited); err != nil {
				return err
			}
		}

	case yaml.MappingNode:
		// Content is [key, value, key, value, ...]
		// Expand only values (odd indices), never keys (even indices).
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			childPath := fieldPath
			if childPath != "" {
				childPath += "."
			}
			childPath += keyNode.Value
			if err := expandEnvInNodeVisited(valNode, childPath, visited); err != nil {
				return err
			}
		}

	case yaml.SequenceNode:
		for i, child := range node.Content {
			childPath := fmt.Sprintf("%s[%d]", fieldPath, i)
			if err := expandEnvInNodeVisited(child, childPath, visited); err != nil {
				return err
			}
		}

	case yaml.ScalarNode:
		if node.Tag == "!!str" || node.Tag == "" {
			expanded, err := expandEnvString(node.Value, fieldPath)
			if err != nil {
				return err
			}
			node.Value = expanded
		}

	case yaml.AliasNode:
		// Expand the alias target. The visited set prevents
		// double-expansion when multiple aliases reference the
		// same anchor.
		if err := expandEnvInNodeVisited(node.Alias, fieldPath, visited); err != nil {
			return err
		}
	}

	return nil
}

// expandEnvString expands ${VAR} and ${VAR:-default} in a single string.
// Returns an error if a variable is unset and has no default.
func expandEnvString(s, fieldPath string) (string, error) { //nolint:gocognit,gocyclo,cyclop // string parsing with escape handling
	if !strings.Contains(s, "${") {
		return s, nil
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		// Look for "${".
		idx := strings.Index(s[i:], "${")
		if idx < 0 {
			b.WriteString(s[i:])
			break
		}
		pos := i + idx

		// Check for escaped $${.
		if pos > 0 && s[pos-1] == '$' {
			b.WriteString(s[i : pos-1])
			b.WriteString("${")
			i = pos + 2
			continue
		}

		b.WriteString(s[i:pos])

		// Find closing '}'.
		end := strings.Index(s[pos+2:], "}")
		if end < 0 {
			return "", fmt.Errorf("field %q: unclosed variable reference at offset %d", fieldPath, pos)
		}
		end += pos + 2

		expr := s[pos+2 : end]
		varName, defaultVal, hasDefault := parseVarExpr(expr)

		if varName == "" {
			return "", fmt.Errorf("field %q: empty variable name at offset %d", fieldPath, pos)
		}
		if !validVarName.MatchString(varName) {
			return "", fmt.Errorf("field %q: invalid variable name %q at offset %d (must match [A-Za-z_][A-Za-z0-9_]*)", fieldPath, varName, pos)
		}

		val, exists := os.LookupEnv(varName)
		if !exists {
			if !hasDefault {
				return "", fmt.Errorf("environment variable %q is not set and has no default (field %q)", varName, fieldPath)
			}
			val = defaultVal
		}

		b.WriteString(val)
		i = end + 1
	}

	return b.String(), nil
}

// parseVarExpr parses "VAR" or "VAR:-default" from the content
// between ${ and }.
func parseVarExpr(expr string) (name, defaultVal string, hasDefault bool) {
	if idx := strings.Index(expr, ":-"); idx >= 0 {
		return expr[:idx], expr[idx+2:], true
	}
	return expr, "", false
}
