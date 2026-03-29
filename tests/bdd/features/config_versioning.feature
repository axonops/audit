@core @config
Feature: Config Versioning
  As a library consumer, I want the library to validate my configuration
  version so that mismatched versions fail fast with a clear error instead
  of producing undefined behaviour.

  Scenario: Config version 0 is rejected
    Given a standard test taxonomy
    When I try to create a logger with config version 0
    Then the logger construction should fail with an error containing "version"

  Scenario: Config version 1 succeeds
    Given a standard test taxonomy
    When I create a logger with config version 1
    Then the logger should be created successfully

  Scenario: Unknown future config version is rejected
    Given a standard test taxonomy
    When I try to create a logger with config version 999
    Then the logger construction should fail with an error containing "version"

  Scenario: Negative config version is rejected
    Given a standard test taxonomy
    When I try to create a logger with config version -1
    Then the logger construction should fail with an error containing "version"

  Scenario: BufferSize defaults to 10000 when zero
    Given a standard test taxonomy
    When I create a logger with config version 1 and buffer size 0
    Then the logger should be created successfully

  Scenario: BufferSize exceeding maximum is rejected
    Given a standard test taxonomy
    When I try to create a logger with config version 1 and buffer size 2000000
    Then the logger construction should fail with an error

  Scenario: DrainTimeout defaults when zero
    Given a standard test taxonomy
    When I create a logger with config version 1 and drain timeout 0
    Then the logger should be created successfully

  Scenario: DrainTimeout exceeding maximum is rejected
    Given a standard test taxonomy
    When I try to create a logger with config version 1 and drain timeout 120s
    Then the logger construction should fail with an error

  Scenario: Disabled config returns no-op logger
    Given a standard test taxonomy
    When I create a disabled logger with config version 1
    Then the logger should handle audit calls without error

  Scenario: ValidationMode defaults to strict when empty
    Given a standard test taxonomy
    And a logger with stdout output
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the audit call should return an error containing "unknown"
