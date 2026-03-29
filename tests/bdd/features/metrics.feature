@core @metrics
Feature: Metrics Interface
  As a library consumer, I want the logger to record metrics for all
  pipeline events so that I can monitor audit health via my observability
  stack.

  The core audit.Metrics interface records: event delivery (success/error),
  validation errors, filter drops, serialisation errors, and buffer drops.
  Output-specific metrics (file rotation, syslog reconnect, webhook flush)
  are tested in their respective output features.

  Background:
    Given a standard test taxonomy
    And mock metrics are configured

  Scenario: Successful event delivery records success metric
    Given a logger with stdout output and metrics
    When I audit event "user_create" with required fields
    And I close the logger
    Then the metrics should have recorded event "success" for output "stdout"

  Scenario: Validation error records validation metric
    Given a logger with stdout output and metrics
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Missing required field records validation metric
    Given a logger with stdout output and metrics
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Filtered event records filter metric
    Given a filtering taxonomy with only "write" enabled
    And a logger with stdout output and metrics
    When I audit event "auth_failure" with required fields
    Then the metrics should have recorded a filtered event "auth_failure"

  Scenario: Nil metrics does not cause panic
    Given a logger with stdout output
    When I audit event "user_create" with required fields
    And I close the logger
    Then the event should be delivered successfully

  Scenario: Multiple outputs each record success metric
    Given a logger with file and stdout outputs and metrics
    When I audit event "user_create" with required fields
    And I close the logger
    Then the metrics should have recorded at least 2 success events

  Scenario: Unknown field in strict mode records validation error
    Given a logger with stdout output and metrics in strict mode
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the metrics should have recorded a validation error

  Scenario: Unknown field in warn mode does not record validation error
    Given a logger with stdout output and metrics in warn mode
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the metrics should not have recorded a validation error

  Scenario: Buffer drop metric recorded when buffer full
    Given a logger with stdout output and metrics and buffer size 1
    When I fill the logger buffer beyond capacity
    Then the metrics should have recorded at least 1 buffer drop

  Scenario: Per-output route filter records output filtered metric
    Given a routing taxonomy with write, read, and security categories
    And a logger with routed outputs and metrics where webhook excludes "write"
    When I audit a "user_create" event in category "write" with marker "m_filt"
    And I close the logger
    Then the metrics should have recorded an output filtered event

  Scenario: Nil metrics with validation error does not panic
    Given a logger with stdout output
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error containing "unknown"

  Scenario: Nil metrics with filtered event does not panic
    Given a filtering taxonomy with only "write" enabled
    And a logger with stdout output
    When I audit event "auth_failure" with required fields
    Then the audit call should return no error
