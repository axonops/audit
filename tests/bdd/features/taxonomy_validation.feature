@core @taxonomy
Feature: Taxonomy Validation
  As a library consumer, I want the logger to validate my YAML taxonomy
  and reject malformed or inconsistent definitions so that only well-formed
  audit events can be emitted.

  The taxonomy is the contract between the library and the consumer. It
  defines event types, categories, required and optional fields, and
  default-enabled categories. Real YAML is used in these scenarios as
  living documentation of the taxonomy format.

  # --- YAML parsing ---

  Scenario: Valid full taxonomy YAML is parsed and applied
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
        security:
          - auth_failure
      events:
        user_create:
          category: write
          required: [outcome, actor_id]
          optional: [marker]
        auth_failure:
          category: security
          required: [outcome, actor_id]
          optional: [reason]
      default_enabled:
        - write
        - security
      """
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully

  Scenario: Minimal taxonomy with one category and one event
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          - health_check
      events:
        health_check:
          category: ops
          required: [outcome]
      default_enabled:
        - ops
      """
    And a logger with stdout output
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
    Then the event should be delivered successfully

  Scenario: Empty YAML input is rejected
    When I try to parse taxonomy from empty YAML
    Then the taxonomy parse should fail with an error containing "empty"

  Scenario: Oversized YAML input is rejected
    When I try to parse taxonomy from YAML exceeding 1 MiB
    Then the taxonomy parse should fail with an error containing "exceeds"

  Scenario: Invalid YAML syntax is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write: [
      """
    Then the taxonomy parse should fail with an error containing "yaml"

  Scenario: Multi-document YAML is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      ---
      version: 2
      """
    Then the taxonomy parse should fail with an error containing "multiple"

  Scenario: Unknown top-level keys are rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      unknown_key: true
      """
    Then the taxonomy parse should fail with an error containing "unknown_key"

  # --- Structural validation ---

  Scenario: Missing version is rejected
    When I try to parse taxonomy from YAML:
      """
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "version"

  Scenario: Version 0 is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 0
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "version"

  Scenario: Unsupported future version is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 999
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "version"

  Scenario: Event in multiple categories is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
        admin:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "multiple categories"

  Scenario: Category member not defined in events is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
          - nonexistent_event
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "nonexistent_event"

  Scenario: Field in both required and optional is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome, actor_id]
          optional: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy parse should fail with an error containing "both Required and Optional"

  Scenario: DefaultEnabled references unknown category is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
        - nonexistent_category
      """
    Then the taxonomy parse should fail with an error containing "nonexistent_category"

  # --- Lifecycle event injection ---

  Scenario: Lifecycle events are auto-injected into taxonomy
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          category: write
          required: [outcome]
      default_enabled:
        - write
      """
    Then the taxonomy should contain event type "startup"
    And the taxonomy should contain event type "shutdown"
    And the taxonomy should contain category "lifecycle"

  Scenario: User-defined lifecycle events are preserved
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
        lifecycle:
          - startup
          - shutdown
      events:
        user_create:
          category: write
          required: [outcome]
        startup:
          category: lifecycle
          required: [app_name, version]
        shutdown:
          category: lifecycle
          required: [app_name, uptime_ms]
      default_enabled:
        - write
        - lifecycle
      """
    Then the taxonomy should contain event type "startup"
    And the taxonomy event "startup" should require field "version"

  # --- Validation modes ---

  Scenario: Unknown fields rejected in strict mode
    Given a standard test taxonomy
    And a logger with stdout output and validation mode "strict"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the audit call should return an error containing "unknown"

  Scenario: Unknown fields accepted with warning in warn mode
    Given a standard test taxonomy
    And a logger with stdout output and validation mode "warn"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the event should be delivered successfully

  Scenario: Unknown fields silently accepted in permissive mode
    Given a standard test taxonomy
    And a logger with stdout output and validation mode "permissive"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the event should be delivered successfully
    And the output should contain field "extra_info" with value "bonus"

  Scenario Outline: Missing required field fails in all validation modes
    Given a standard test taxonomy
    And a logger with stdout output and validation mode "<mode>"
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error containing "missing required"
    And the error should mention "actor_id"

    Examples:
      | mode       |
      | strict     |
      | warn       |
      | permissive |
