@core @config
Feature: Auditor Configuration
  As a library consumer, I want the library to validate my configuration
  so that invalid settings fail fast with a clear error instead
  of producing undefined behaviour.

  Scenario: Default config succeeds
    Given a standard test taxonomy
    When I create an auditor
    Then the auditor should be created successfully

  Scenario: QueueSize defaults to 10000 when zero
    Given a standard test taxonomy
    When I create an auditor with buffer size 0
    Then the auditor should be created successfully

  Scenario: QueueSize exceeding maximum is rejected with exact error
    Given a standard test taxonomy
    When I try to create an auditor with buffer size 2000000
    Then the auditor construction should fail with an error matching:
      """
      audit: config validation failed: queue_size 2000000 exceeds maximum 1000000
      """

  Scenario: ShutdownTimeout defaults when zero
    Given a standard test taxonomy
    When I create an auditor with drain timeout 0
    Then the auditor should be created successfully

  Scenario: ShutdownTimeout exceeding maximum is rejected with exact error
    Given a standard test taxonomy
    When I try to create an auditor with drain timeout 120s
    Then the auditor construction should fail with an error matching:
      """
      audit: config validation failed: shutdown_timeout 2m0s exceeds maximum 1m0s
      """

  Scenario: Disabled config returns no-op auditor
    Given a standard test taxonomy
    When I create a disabled auditor
    Then the auditor should handle audit calls without error

  Scenario: ValidationMode defaults to strict when empty
    Given a standard test taxonomy
    And an auditor with stdout output
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the audit call should return an error matching:
      """
      audit: event "user_create" has unknown fields: [extra]
      """

  # --- Required AppName / Host (#593 B-41) ---

  Scenario: audit.New without WithAppName fails with ErrAppNameRequired
    Given a standard test taxonomy
    When I try to create an auditor without WithAppName
    Then the auditor construction should fail with ErrAppNameRequired

  Scenario: audit.New without WithHost fails with ErrHostRequired
    Given a standard test taxonomy
    When I try to create an auditor without WithHost
    Then the auditor construction should fail with ErrHostRequired

  Scenario: Disabled auditor bypasses AppName / Host requirement
    Given a standard test taxonomy
    When I try to create a disabled auditor without WithAppName or WithHost
    Then the auditor should be created successfully
