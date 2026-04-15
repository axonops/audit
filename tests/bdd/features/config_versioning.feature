@core @config
Feature: Logger Configuration
  As a library consumer, I want the library to validate my configuration
  so that invalid settings fail fast with a clear error instead
  of producing undefined behaviour.

  Scenario: Default config succeeds
    Given a standard test taxonomy
    When I create a logger
    Then the logger should be created successfully

  Scenario: BufferSize defaults to 10000 when zero
    Given a standard test taxonomy
    When I create a logger with buffer size 0
    Then the logger should be created successfully

  Scenario: QueueSize exceeding maximum is rejected with exact error
    Given a standard test taxonomy
    When I try to create a logger with buffer size 2000000
    Then the logger construction should fail with an error matching:
      """
      audit: config validation failed: queue_size 2000000 exceeds maximum 1000000
      """

  Scenario: DrainTimeout defaults when zero
    Given a standard test taxonomy
    When I create a logger with drain timeout 0
    Then the logger should be created successfully

  Scenario: DrainTimeout exceeding maximum is rejected with exact error
    Given a standard test taxonomy
    When I try to create a logger with drain timeout 120s
    Then the logger construction should fail with an error matching:
      """
      audit: config validation failed: drain_timeout 2m0s exceeds maximum 1m0s
      """

  Scenario: Disabled config returns no-op logger
    Given a standard test taxonomy
    When I create a disabled logger
    Then the logger should handle audit calls without error

  Scenario: ValidationMode defaults to strict when empty
    Given a standard test taxonomy
    And a logger with stdout output
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the audit call should return an error matching:
      """
      audit: event "user_create" has unknown fields: [extra]
      """
