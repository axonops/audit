@release-tool
Feature: release-tool CLI behaviour
  As an operator running the release flow
  I want release-tool to enforce typed, idempotent semantics
  So that the v0.2.1-era bash cascade bugs (#900-#916) can not recur

  Background:
    Given the release-tool binary has been built

  # ----------------------------------------------------------------
  # Persistent flag surface — fast usage gates
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
  # commit-pinned-deps subcommand
  # ----------------------------------------------------------------

  Scenario: commit-pinned-deps with missing required flags exits 2
    When I run release-tool with arguments "commit-pinned-deps --owner axonops"
    Then the exit code is 2
    And the stderr contains "missing required flag"

  Scenario: commit-pinned-deps creates an App-signed commit
    Given a staged go.mod in a fresh git repo
    And the GH_API_URL points at a server that accepts the GraphQL mutation
    When I run release-tool commit-pinned-deps against that server
    Then the exit code is 0
    And the stdout is exactly the captured commit OID

  Scenario: commit-pinned-deps rejects a non-go.mod file in the staged tree
    Given a staged ".github/workflows/release.yml" in a fresh git repo
    And the GH_API_URL points at a server that fails on any request
    When I run release-tool commit-pinned-deps against that server
    Then the exit code is 3
    And the stderr contains "rejected by allowlist"

  Scenario: commit-pinned-deps rejects a symlinked go.mod
    Given a symlinked go.mod in a fresh git repo
    And the GH_API_URL points at a server that fails on any request
    When I run release-tool commit-pinned-deps against that server
    Then the exit code is 3
    And the stderr contains "symlink"

  Scenario: commit-pinned-deps with --dry-run prints the payload and does not call the API
    Given a staged go.mod in a fresh git repo
    And the GH_API_URL points at a server that succeeds on idempotency lookups but fails on any mutation
    When I run release-tool commit-pinned-deps with --dry-run against that server
    Then the exit code is 0
    And the stdout decodes as JSON containing "createCommitOnBranch"
    And the server received zero mutation requests

  Scenario: commit-pinned-deps with --auto-create-branch creates the branch from main
    Given a staged go.mod in a fresh git repo
    And the GH_API_URL points at a server where the release branch does not exist
    When I run release-tool commit-pinned-deps with --auto-create-branch against that server
    Then the exit code is 0
    And the server received a CreateRef call for the release branch

  # ----------------------------------------------------------------
  # create-tag subcommand
  # ----------------------------------------------------------------

  Scenario: create-tag with missing required flags exits 2
    When I run release-tool with arguments "create-tag --owner axonops --repo audit"
    Then the exit code is 2
    And the stderr contains "missing required flag"

  Scenario: create-tag refuses a non-40-hex SHA — #911 regression
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

  Scenario: create-tag refuses a structurally invalid branch-like tag
    When I run release-tool with arguments "create-tag --owner axonops --repo audit --tag .. --sha abcdef0123456789abcdef0123456789abcdef01 --message Release"
    Then the exit code is 3
    And the stderr contains "structurally invalid"

  Scenario: create-tag at a fresh tag creates the tag object + ref
    Given the GH_API_URL points at a server where the tag does not exist
    When I run release-tool create-tag against that server
    Then the exit code is 0
    And the stdout is exactly the captured tag-object SHA

  Scenario: create-tag re-run at the same SHA exits 4 idempotently
    Given the GH_API_URL points at a server where the tag exists at the same SHA
    When I run release-tool create-tag against that server
    Then the exit code is 4
    And the stderr contains "no-op"

  Scenario: create-tag re-run at a different SHA exits 1 with a contamination error
    Given the GH_API_URL points at a server where the tag exists at a different SHA
    When I run release-tool create-tag against that server
    Then the exit code is 1
    And the stderr contains "refusing to overwrite"

  Scenario: create-tag with --dry-run prints the payloads and does not call the API
    Given the GH_API_URL points at a server where the tag does not exist and any mutation fails the test
    When I run release-tool create-tag with --dry-run against that server
    Then the exit code is 0
    And the stdout decodes as JSON containing "tag_object"
    And the server received zero mutation requests
