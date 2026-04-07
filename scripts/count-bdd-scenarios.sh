#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# count-bdd-scenarios.sh — Count BDD scenarios from feature files.
#
# Handles Scenario Outline expansion: a Scenario Outline with N data rows
# in its Examples table(s) counts as N scenarios, not 1.
#
# Usage:
#   ./scripts/count-bdd-scenarios.sh <feature-dir> [<feature-dir2> ...]
#
# Output: the total number of executable scenarios (one integer on stdout).
# Exit code 0 on success, 1 on error.

set -euo pipefail

if [ $# -eq 0 ]; then
    echo "Usage: $0 <feature-dir> [<feature-dir2> ...]" >&2
    exit 1
fi

total=0

for dir in "$@"; do
    if [ ! -d "$dir" ]; then
        echo "ERROR: directory not found: $dir" >&2
        exit 1
    fi

    for feature_file in "$dir"/*.feature; do
        [ -f "$feature_file" ] || continue

        # State machine to parse feature files.
        # States: NONE, IN_OUTLINE, IN_EXAMPLES_HEADER, IN_EXAMPLES_DATA
        state="NONE"
        outline_count=0

        while IFS= read -r line; do
            # Strip leading whitespace for matching.
            trimmed="${line#"${line%%[![:space:]]*}"}"

            # Skip empty lines and comments.
            [ -z "$trimmed" ] && continue
            [[ "$trimmed" == \#* ]] && continue

            # Tag lines start with @ — skip (they don't affect counting).
            [[ "$trimmed" == @* ]] && continue

            case "$state" in
                NONE)
                    if [[ "$trimmed" == "Scenario:"* ]]; then
                        total=$((total + 1))
                    elif [[ "$trimmed" == "Scenario Outline:"* ]]; then
                        state="IN_OUTLINE"
                        outline_count=0
                    fi
                    ;;
                IN_OUTLINE)
                    if [[ "$trimmed" == "Examples:"* ]]; then
                        state="IN_EXAMPLES_HEADER"
                    elif [[ "$trimmed" == "Scenario:"* ]]; then
                        # Outline with no Examples — should not happen but handle it.
                        total=$((total + outline_count))
                        total=$((total + 1))
                        state="NONE"
                        outline_count=0
                    elif [[ "$trimmed" == "Scenario Outline:"* ]]; then
                        # Previous outline ended, new one starts.
                        total=$((total + outline_count))
                        outline_count=0
                    fi
                    ;;
                IN_EXAMPLES_HEADER)
                    # The first table row after Examples: is the header row — skip it.
                    if [[ "$trimmed" == "|"* ]]; then
                        state="IN_EXAMPLES_DATA"
                    fi
                    ;;
                IN_EXAMPLES_DATA)
                    if [[ "$trimmed" == "|"* ]]; then
                        # Data row — counts as one scenario execution.
                        outline_count=$((outline_count + 1))
                    elif [[ "$trimmed" == "Examples:"* ]]; then
                        # Another Examples table for the same Outline.
                        state="IN_EXAMPLES_HEADER"
                    elif [[ "$trimmed" == "Scenario:"* ]]; then
                        total=$((total + outline_count))
                        total=$((total + 1))
                        state="NONE"
                        outline_count=0
                    elif [[ "$trimmed" == "Scenario Outline:"* ]]; then
                        total=$((total + outline_count))
                        state="IN_OUTLINE"
                        outline_count=0
                    else
                        # Non-table line — end of Examples data.
                        # Stay in IN_OUTLINE in case there are more Examples tables.
                        # But if this is a new keyword (Feature, Background, etc.), go to NONE.
                        if [[ "$trimmed" == "Feature:"* ]] || [[ "$trimmed" == "Background:"* ]] || [[ "$trimmed" == "Rule:"* ]]; then
                            total=$((total + outline_count))
                            state="NONE"
                            outline_count=0
                        else
                            state="IN_OUTLINE"
                        fi
                    fi
                    ;;
            esac
        done < "$feature_file"

        # End of file — flush any pending outline count.
        if [ "$state" = "IN_EXAMPLES_DATA" ] || [ "$state" = "IN_OUTLINE" ] || [ "$state" = "IN_EXAMPLES_HEADER" ]; then
            total=$((total + outline_count))
        fi
    done
done

echo "$total"
