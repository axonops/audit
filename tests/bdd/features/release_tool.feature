@release-tool
Feature: release-tool CLI behaviour
  As an operator running the release flow
  I want release-tool to enforce typed, idempotent semantics
  So that the v0.2.1-era bash cascade bugs (#900-#916) can not recur

  Background:
    Given the release-tool binary has been built

  # ----------------------------------------------------------------
  # Persistent flag surface
  # ----------------------------------------------------------------

  Scenario: --help prints the usage block to stderr and exits 0
    When I run release-tool with arguments "--help"
    Then the exit code is 0
    And the stderr contains "USAGE"
    And the stderr contains "commit-pinned-deps"
    And the stderr contains "create-tag"

  Scenario: --version writes the version to stdout
    When I run release-tool with arguments "--version"
    Then the exit code is 0
    And the stdout starts with "release-tool "

  Scenario: An unknown subcommand exits 2 with a useful diagnostic
    When I run release-tool with arguments "nonexistent-subcommand"
    Then the exit code is 2
    And the stderr contains "unknown subcommand"

  Scenario: No subcommand exits 2 with a useful diagnostic
    When I run release-tool with no arguments
    Then the exit code is 2
    And the stderr contains "no subcommand"

  # ----------------------------------------------------------------
  # create-tag subcommand
  # ----------------------------------------------------------------

  Scenario: create-tag with missing required flags exits 2
    When I run release-tool with arguments "create-tag --owner axonops --repo audit"
    Then the exit code is 2
    And the stderr contains "missing required flag"

  Scenario: create-tag refuses a non-40-hex SHA — #911 regression
    # The --sha argument here is the EXACT 404 JSON body that bash
    # versions accepted as a SHA. The docstring preserves every
    # character (double quotes, braces) verbatim — splitShellLike
    # only sees the literal token "{message:NotFound}" as the SHA,
    # which is still emphatically not 40 hex chars.
    When I run release-tool with these args:
      """
      create-tag
      --owner=axonops
      --repo=audit
      --tag=v0.2.2
      --message=Release
      --sha={"message":"Not Found"}
      """
    Then the exit code is 3
    And the stderr contains "40 lowercase hex"

  # ----------------------------------------------------------------
  # commit-pinned-deps subcommand
  # ----------------------------------------------------------------

  Scenario: commit-pinned-deps with missing required flags exits 2
    When I run release-tool with arguments "commit-pinned-deps --owner axonops"
    Then the exit code is 2
    And the stderr contains "missing required flag"

  # ----------------------------------------------------------------
  # Happy path — covered via --dry-run so the scenario never makes
  # a real network call (test-analyst N1). Dry-run only short-
  # circuits AFTER the existing-ref lookup, so we point --owner /
  # --repo at "dry-run/dry-run" — release-tool's no-network path
  # rejects the upfront flag-shape gate first (regex refuses the
  # leading hyphen / structurally invalid forms), then validates
  # the SHA shape, and only then would hit the API. With a valid-
  # SHA / valid-flag combination the tool still tries to reach
  # api.github.com — which is why this scenario asserts the
  # validation-only contract (exit 3 on a bad SHA), and not exit 0.
  Scenario: create-tag refuses a structurally invalid branch-like tag
    When I run release-tool with arguments "create-tag --owner axonops --repo audit --tag .. --sha abcdef0123456789abcdef0123456789abcdef01 --message Release"
    Then the exit code is 3
    And the stderr contains "structurally invalid"
